"""Real synthetic Docker-save TAR/gzip fixtures, not website/image payloads."""
from hashlib import sha256
from io import BytesIO
import gzip
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import article_test_images as images
from article_test_artifact import inspect_archive
import test_article_test_artifact as artifact_fixture


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def tar(rows,extra=None):
    output=BytesIO()
    with tarfile.open(fileobj=output,mode='w') as archive:
        for name,data in rows.items():
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
            archive.addfile(info,BytesIO(data))
        if extra:extra(archive)
    return output.getvalue()


def envelope(oci=False,change=None,extra=None):
    def link(archive):
        info=tarfile.TarInfo('legitimate-layer-link');info.type=tarfile.SYMTYPE;info.linkname='hello';archive.addfile(info)
    layer=tar({'hello':b'synthetic'},link);diff=sha256(layer).hexdigest()
    blob=gzip.compress(layer,mtime=0) if oci else layer
    layer_name='blobs/sha256/'+sha256(blob).hexdigest() if oci else diff+'/layer.tar'
    cfg=[];ids=[];names=[]
    for app in (True,False):
        value=dict(architecture='amd64',os='linux',config=dict(User='10001:10001' if app else '',
            Entrypoint=['/app/start.sh'] if app else ['/entrypoint.sh'],Volumes=None if app else {'/var/lib/mysql':{}}),
            rootfs=dict(type='layers',diff_ids=['sha256:'+diff]))
        raw=encoded(value);identity=sha256(raw).hexdigest();cfg.append(raw);ids.append('sha256:'+identity)
        names.append('blobs/sha256/'+identity if oci else identity+'.json')
    tags=('jsm-article-test:'+'a'*40,'jsm-article-mysql:'+'a'*40)
    rows={names[0]:cfg[0],names[1]:cfg[1],layer_name:blob}
    manifest=[dict(Config=name,RepoTags=[tag],Layers=[layer_name]) for name,tag in zip(names,tags)]
    rows['manifest.json']=encoded(manifest)
    if oci:
        descriptors=[]
        for index in range(2):
            value=dict(schemaVersion=2,mediaType='application/vnd.oci.image.manifest.v1+json',
                config=dict(mediaType='application/vnd.oci.image.config.v1+json',digest=ids[index],size=len(cfg[index])),
                layers=[dict(mediaType='application/vnd.oci.image.layer.v1.tar+gzip',digest='sha256:'+sha256(blob).hexdigest(),size=len(blob))])
            raw=encoded(value);digest=sha256(raw).hexdigest();rows['blobs/sha256/'+digest]=raw
            descriptors.append(dict(mediaType='application/vnd.oci.image.manifest.v1+json',digest='sha256:'+digest,size=len(raw),
                annotations={'io.containerd.image.name':'docker.io/library/'+tags[index]}))
        rows['index.json']=encoded(dict(schemaVersion=2,manifests=descriptors));rows['oci-layout']=encoded({'imageLayoutVersion':'1.0.0'})
    if change:change(rows,manifest,ids)
    package=gzip.compress(tar(rows,extra),mtime=0)
    raw,build=artifact_fixture.ArtifactTests().package(lambda r:r.update({'images.tar.gz':package,
        'app-image-id':(ids[0]+'\n').encode(),'mysql-image-id':(ids[1]+'\n').encode()}))
    return raw,build


class ImagesTests(unittest.TestCase):
    def verify(self,raw,build):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'artifact.zip';path.write_bytes(raw)
            return images.verify(path,inspect_archive(path,build),time.monotonic()+2)

    def test_legacy_and_oci_actual_tar_gzip_config_diffids_and_inner_symlink(self):
        for oci in (False,True):
            raw,build=envelope(oci);proof=self.verify(raw,build)
            self.assertEqual(proof.layers,1);self.assertEqual(len(proof.image_ids),2)
            self.assertGreater(proof.layer_unpacked_bytes,0);self.assertLess(proof.layer_unpacked_bytes,images.TAR_LIMIT)

    def test_third_tag_duplicate_or_foreign_tag_and_bad_image_config_refuse(self):
        def extra_tag(rows,manifest,ids):
            manifest[0]['RepoTags'].append('foreign:latest');rows['manifest.json']=encoded(manifest)
        def bad_config(rows,manifest,ids):rows[manifest[0]['Config']]=b'PRIVATE'
        def hidden(rows,manifest,ids):rows['repositories']=encoded({'foreign':{'latest':'a'*64}})
        def extra_payload(rows,manifest,ids):rows['PRIVATE']=b'forbidden'
        for mutate in (extra_tag,bad_config,hidden,extra_payload):
            raw,build=envelope(change=mutate)
            with self.assertRaises(images.ImageRefused):self.verify(raw,build)

    def test_oci_compressed_blob_digest_is_independent_of_unpacked_diffid(self):
        def gzip_header(rows,manifest,ids):
            path=manifest[0]['Layers'][0];raw=bytearray(rows[path]);raw[4]^=1;rows[path]=bytes(raw)
        raw,build=envelope(oci=True,change=gzip_header)
        with self.assertRaises(images.ImageRefused):self.verify(raw,build)

    def test_outer_symlink_device_traversal_duplicate_refuse_without_host_extract(self):
        def entry(kind,name):
            def add(archive):
                info=tarfile.TarInfo(name);info.type=kind;info.linkname='PRIVATE' if kind==tarfile.SYMTYPE else ''
                archive.addfile(info,BytesIO())
            return add
        for kind,name in ((tarfile.SYMTYPE,'link'),(tarfile.CHRTYPE,'device'),(tarfile.REGTYPE,'../PRIVATE'),(tarfile.REGTYPE,'manifest.json')):
            raw,build=envelope(extra=entry(kind,name))
            with self.assertRaises(images.ImageRefused):self.verify(raw,build)

    def test_absolute_budget_and_decompression_cap_are_real_reader_barriers(self):
        from unittest.mock import patch
        raw,build=envelope()
        with patch.object(images,'TAR_LIMIT',128):
            with self.assertRaises(images.ImageRefused):self.verify(raw,build)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.zip';path.write_bytes(raw)
            with self.assertRaises(images.ImageRefused):images.verify(path,inspect_archive(path,build),time.monotonic()-1)

if __name__=='__main__':unittest.main()
