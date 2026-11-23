"""Verify a Docker-save envelope without extracting image files on the host.

Layers remain opaque to the host filesystem. Their uncompressed hashes/sizes
are checked against config diff_ids to bound later Docker consumption.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import gzip
from io import BytesIO
import os
from pathlib import PurePosixPath
import re
import stat
import tarfile
import time
from zipfile import ZipFile

from apache_parity_bridge import strict_json
from article_test_artifact import Inspected, file_stamp, bounded_hash, ARCHIVE_LIMIT

TAR_LIMIT=6*1024**3
JSON_LIMIT=1024**2
ENTRY_LIMIT=4096
SHA=re.compile('[0-9a-f]{64}')


class ImageRefused(ValueError):pass


def require(value):
    if not value:raise ImageRefused('ARTICLE_IMAGE_ENVELOPE_REFUSED')


def check(deadline):
    if time.monotonic()>=deadline:raise ImageRefused('ARTICLE_IMAGE_DEADLINE')


class Limited:
    def __init__(self,stream,limit,deadline):self.stream,self.limit,self.deadline,self.total=stream,limit,deadline,0
    def read(self,size=-1):
        check(self.deadline)
        if size<0:size=self.limit+1-self.total
        raw=self.stream.read(min(size,self.limit+1-self.total));self.total+=len(raw)
        require(self.total<=self.limit);return raw


@contextmanager
def image_tar(path,inspected,deadline):
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as file:
            fd=None;first=os.fstat(file.fileno());require(stat.S_ISREG(first.st_mode) and first.st_nlink==1)
            digest,size=bounded_hash(file,ARCHIVE_LIMIT);require(digest==inspected.build.archive_sha256 and size==inspected.archive_bytes)
            file.seek(0)
            with ZipFile(file) as archive,archive.open('images.tar.gz') as member,gzip.GzipFile(fileobj=member,mode='rb') as uncompressed:
                limited=Limited(uncompressed,TAR_LIMIT,deadline)
                with tarfile.open(fileobj=limited,mode='r|') as tar:
                    yield tar,limited
                    require(not getattr(tar.fileobj,'buf',b'').strip(b'\0'))
                # No hidden concatenated TAR/payload after the first envelope.
                while True:
                    tail=limited.read(65536)
                    if not tail:break
                    require(not tail.strip(b'\0'))
            require(file_stamp(first)==file_stamp(os.fstat(file.fileno()))
                    and file_stamp(first)==file_stamp(os.stat(path,follow_symlinks=False)))
    except ImageRefused:raise
    except Exception:raise ImageRefused('ARTICLE_IMAGE_ENVELOPE_REFUSED') from None
    finally:
        if fd is not None:os.close(fd)


def safe_name(name):
    require(type(name) is str and 0<len(name)<=256 and name.isascii() and '\\' not in name and '\0' not in name)
    parts=name.rstrip('/').split('/')
    require(not name.startswith('/') and all(p not in ('.','..','') for p in parts)
            and all(re.fullmatch('[A-Za-z0-9_.-]+',p) for p in parts))
    return name.rstrip('/')


def small(tar,entry):
    require(entry.isfile() and 0<entry.size<=JSON_LIMIT)
    file=tar.extractfile(entry);raw=file.read(JSON_LIMIT+1)
    require(len(raw)==entry.size and len(raw)<=JSON_LIMIT)
    return raw


def config_path(name,image_id):
    digest=image_id[7:]
    return name in (digest+'.json','blobs/sha256/'+digest)


def descriptor(value):
    require(type(value) is dict and set(value)<= {'mediaType','digest','size','platform','annotations'}
            and type(value.get('digest')) is str
            and re.fullmatch('sha256:[0-9a-f]{64}',value['digest']) and type(value.get('size')) is int
            and 0<value['size']<=TAR_LIMIT)
    return 'blobs/sha256/'+value['digest'][7:]


def tag(value,expected):
    require(type(value) is str)
    if value.startswith('docker.io/library/'):value=value[len('docker.io/library/'):]
    require(value in expected);return value


@dataclass(frozen=True)
class ImageProof:
    docker_tar_bytes:int
    layer_unpacked_bytes:int
    image_ids:tuple
    tags:tuple
    layers:int


def verify(path,inspected,deadline):
    try:return _verify(path,inspected,deadline)
    except ImageRefused:raise
    except Exception:raise ImageRefused('ARTICLE_IMAGE_ENVELOPE_REFUSED') from None


def _verify(path,inspected,deadline):
    require(type(inspected) is Inspected)
    images=(inspected.app_image,inspected.mysql_image);expected_tags=inspected.build.tags
    inventory={};metadata={};configs={}
    with image_tar(path,inspected,deadline) as (tar,limited):
        for entry in tar:
            check(deadline);name=safe_name(entry.name)
            require(name not in inventory and len(inventory)<ENTRY_LIMIT and (entry.isfile() or entry.isdir())
                    and not entry.linkname and not entry.pax_headers and 0<=entry.size<=TAR_LIMIT)
            inventory[name]=(entry.size,entry.isdir())
            if name in ('manifest.json','repositories','index.json','oci-layout'):
                metadata[name]=strict_json(small(tar,entry).decode('utf-8'))
            for image_id in images:
                if config_path(name,image_id):
                    raw=small(tar,entry);require(sha256(raw).hexdigest()==image_id[7:] and image_id not in configs)
                    configs[image_id]=(name,strict_json(raw.decode('utf-8')))
    tar_bytes=limited.total
    require(set(configs)==set(images) and type(metadata.get('manifest.json')) is list and len(metadata['manifest.json'])==2)
    manifests=metadata['manifest.json'];references={};seen_tags=set();allowed=set(metadata)
    by_tag={}
    for image_id,expected_tag in zip(images,expected_tags):
        name,cfg=configs[image_id];allowed.add(name)
        require(type(cfg) is dict and cfg.get('architecture')=='amd64' and cfg.get('os')=='linux')
        runtime=cfg.get('config');require(type(runtime) is dict)
        if image_id==images[0]:
            require(runtime.get('User')=='10001:10001' and runtime.get('Entrypoint')==['/app/start.sh']
                    and runtime.get('Volumes') in (None,{}))
        else:require(runtime.get('Volumes') in (None,{}, {'/var/lib/mysql':{}}))
        found=[row for row in manifests if type(row) is dict and row.get('Config')==name]
        require(len(found)==1);row=found[0]
        require(set(row)=={'Config','RepoTags','Layers'} and type(row['RepoTags']) is list and len(row['RepoTags'])==1
                and tag(row['RepoTags'][0],expected_tags)==expected_tag and expected_tag not in seen_tags)
        seen_tags.add(expected_tag)
        layers=row['Layers'];rootfs=cfg.get('rootfs')
        require(type(layers) is list and len(layers)<=256 and type(rootfs) is dict and rootfs.get('type')=='layers'
                and type(rootfs.get('diff_ids')) is list and len(layers)==len(rootfs['diff_ids']))
        for layer,diff in zip(layers,rootfs['diff_ids']):
            require(type(layer) is str and layer in inventory and not inventory[layer][1]
                    and type(diff) is str and re.fullmatch('sha256:[0-9a-f]{64}',diff))
            safe_name(layer);require(layer not in references or references[layer]==diff)
            references[layer]=diff;allowed.add(layer)
        by_tag[expected_tag]=(name,tuple(layers))
    if 'repositories' in metadata:
        repositories=metadata['repositories'];require(type(repositories) is dict and set(repositories)=={'jsm-article-test','jsm-article-mysql'})
        for name,rows in repositories.items():
            require(type(rows) is dict and set(rows)=={inspected.build.sha} and type(rows[inspected.build.sha]) is str
                    and SHA.fullmatch(rows[inspected.build.sha]))
    if 'index.json' in metadata or 'oci-layout' in metadata:
        require(metadata.get('oci-layout')=={'imageLayoutVersion':'1.0.0'})
        index=metadata.get('index.json');require(type(index) is dict and index.get('schemaVersion')==2
                and type(index.get('manifests')) is list and len(index['manifests'])==2)
        wanted={};oci_tags=set()
        for row in index['manifests']:
            blob=descriptor(row);annotations=row.get('annotations')
            require(type(annotations) is dict and set(annotations)<= {'io.containerd.image.name','org.opencontainers.image.ref.name'})
            names=[tag(value,expected_tags) for value in annotations.values()]
            require(names and len(set(names))==1 and names[0] not in oci_tags)
            oci_tags.add(names[0]);wanted[blob]=(row,names[0]);allowed.add(blob)
        require(oci_tags==set(expected_tags))
        with image_tar(path,inspected,deadline) as (tar,_):
            for entry in tar:
                if entry.name not in wanted:continue
                desc,reference=wanted.pop(entry.name);raw=small(tar,entry)
                require(sha256(raw).hexdigest()==desc['digest'][7:] and len(raw)==desc['size'])
                manifest=strict_json(raw.decode('utf-8'))
                require(type(manifest) is dict and set(manifest)<= {'schemaVersion','mediaType','config','layers','annotations'}
                        and manifest.get('schemaVersion')==2 and type(manifest.get('layers')) is list
                        and manifest.get('annotations') in (None,{}))
                config,layers=by_tag[reference]
                require(descriptor(manifest['config'])==config and manifest['config']['size']==inventory[config][0]
                        and tuple(descriptor(layer) for layer in manifest['layers'])==layers
                        and all(layer['size']==inventory[path][0] for layer,path in zip(manifest['layers'],layers)))
        require(not wanted)
    # Legacy per-layer metadata is safe only inside a referenced layer directory.
    for layer in references:
        if layer.endswith('/layer.tar'):
            parent=layer.rsplit('/',1)[0]
            allowed.update(name for name in (parent+'/json',parent+'/VERSION') if name in inventory)
    require(all(directory or name in allowed for name,(_,directory) in inventory.items()))
    sizes={}
    with image_tar(path,inspected,deadline) as (tar,_):
        for entry in tar:
            if entry.name not in references:continue
            file=tar.extractfile(entry);start=file.read(2)
            class Prefix:
                def __init__(self):self.prefix=start
                def read(self,n=-1):
                    part=self.prefix[:n] if n>=0 else self.prefix;self.prefix=self.prefix[len(part):]
                    return part+file.read(n-len(part) if n>=0 else n)
            stream=Prefix();wrapped=gzip.GzipFile(fileobj=stream,mode='rb') if start==b'\x1f\x8b' else stream
            digest=sha256();total=0
            while True:
                check(deadline);raw=wrapped.read(min(65536,TAR_LIMIT+1-total))
                if not raw:break
                total+=len(raw);require(total<=TAR_LIMIT);digest.update(raw)
            require('sha256:'+digest.hexdigest()==references[entry.name]);sizes[entry.name]=total
    require(set(sizes)==set(references))
    unpacked=sum(sizes[path] for _,layers in by_tag.values() for path in layers)
    require(unpacked<=TAR_LIMIT)
    # Include the full bounded gzip/TAR stream rather than only image payloads.
    return ImageProof(tar_bytes,unpacked,images,expected_tags,len(references))
