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
def image_stream(path,inspected,deadline):
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as file:
            fd=None;first=os.fstat(file.fileno());require(stat.S_ISREG(first.st_mode) and first.st_nlink==1)
            digest,size=bounded_hash(file,ARCHIVE_LIMIT);require(digest==inspected.build.archive_sha256 and size==inspected.archive_bytes)
            file.seek(0)
            with ZipFile(file) as archive,archive.open('images.tar.gz') as member,gzip.GzipFile(fileobj=member,mode='rb') as uncompressed:
                limited=Limited(uncompressed,TAR_LIMIT,deadline)
                yield limited
                require(limited.read(1)==b'')
            require(file_stamp(first)==file_stamp(os.fstat(file.fileno()))
                    and file_stamp(first)==file_stamp(os.stat(path,follow_symlinks=False)))
    except ImageRefused:raise
    except Exception:raise ImageRefused('ARTICLE_IMAGE_ENVELOPE_REFUSED') from None
    finally:
        if fd is not None:os.close(fd)


@contextmanager
def image_tar(path,inspected,deadline):
    with image_stream(path,inspected,deadline) as limited:
        with tarfile.open(fileobj=limited,mode='r|') as tar:
            yield tar,limited
            require(not getattr(tar.fileobj,'buf',b'').strip(b'\0'))
        while True:
            tail=limited.read(65536)
            if not tail:break
            require(not tail.strip(b'\0'))


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
    config_ids:tuple
    manifest_ids:tuple

    @property
    def aliases(self):
        return tuple(tuple(dict.fromkeys(x for x in (native,config,manifest) if x is not None))
            for native,config,manifest in zip(self.image_ids,self.config_ids,self.manifest_ids))


def verify_legacy_containerd(path, inspected, deadline, paths, selected, configs):
    """Containerd exports bounded Docker compatibility records alongside OCI blobs."""
    records = {}
    with image_tar(path, inspected, deadline) as (tar, _):
        for entry in tar:
            if entry.name not in paths:
                continue
            require(re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', entry.name) and 1 <= entry.size <= 8192)
            raw = small(tar, entry)
            require(config_path(entry.name, 'sha256:' + sha256(raw).hexdigest()))
            value = strict_json(raw.decode('utf-8'))
            fields = {'id', 'os', 'created', 'container_config'}
            require(type(value) is dict and fields <= set(value) <= fields | {'parent', 'config', 'architecture'}
                    and value['os'] == 'linux' and type(value['id']) is str and SHA.fullmatch(value['id'])
                    and type(value['container_config']) is dict and type(value['created']) is str
                    and ('parent' not in value or type(value['parent']) is str and SHA.fullmatch(value['parent']))
                    and value['id'] not in records)
            if 'config' in value:
                require(type(value['config']) is dict and value.get('architecture') == 'amd64')
            else:
                require('architecture' not in value)
            records[value['id']] = value
    require(len(records) == len(paths))
    terminal = [value for value in records.values() if 'config' in value]
    require(len(terminal) == len(selected))
    visited = set()
    for row in selected.values():
        runtime = configs[row['Config']][0]['config']
        matching = [value for value in terminal if all(
            (value['config'].get(field) or None) == (runtime.get(field) or None)
            for field in ('User', 'Entrypoint', 'Volumes', 'Labels'))]
        require(len(matching) == 1)
        current = matching[0]['id']
        depth = 0
        while current is not None:
            require(current in records and current not in visited)
            visited.add(current)
            depth += 1
            current = records[current].get('parent')
        require(depth == len(row['Layers']))
    require(visited == set(records))


def verify(path,inspected,deadline,*,containerd_layer_sources=False):
    try:return _verify(path,inspected,deadline,containerd_layer_sources)
    except ImageRefused:raise
    except Exception:raise ImageRefused('ARTICLE_IMAGE_ENVELOPE_REFUSED') from None


def _verify(path,inspected,deadline,containerd_layer_sources=False):
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
    tar_bytes=limited.total
    manifests=metadata.get('manifest.json');require(type(manifests) is list and len(manifests)==2)
    selected={};config_paths=set();allowed=set(metadata);by_tag={}
    for row in manifests:
        fields={'Config','RepoTags','Layers'}
        if containerd_layer_sources and type(row) is dict and 'LayerSources' in row:fields.add('LayerSources')
        require(type(row) is dict and set(row)==fields
                and type(row['RepoTags']) is list and len(row['RepoTags'])==1)
        reference=tag(row['RepoTags'][0],expected_tags);require(reference not in selected)
        name=row['Config'];require(type(name) is str and name in inventory and not inventory[name][1])
        safe_name(name);require(re.fullmatch(r'(?:blobs/sha256/[0-9a-f]{64}|[0-9a-f]{64}\.json)',name))
        require(name not in config_paths);config_paths.add(name);selected[reference]=row
    require(set(selected)==set(expected_tags))
    oci={};manifest_blobs={}
    if 'index.json' in metadata or 'oci-layout' in metadata:
        require(metadata.get('oci-layout')=={'imageLayoutVersion':'1.0.0'})
        index=metadata.get('index.json');require(type(index) is dict and set(index)<= {'schemaVersion','mediaType','manifests'}
                and index.get('schemaVersion')==2 and type(index.get('manifests')) is list and len(index['manifests'])==2)
        for row in index['manifests']:
            blob=descriptor(row);require(row.get('mediaType')=='application/vnd.oci.image.manifest.v1+json')
            annotation=row.get('annotations')
            require(type(annotation) is dict and set(annotation)<= {'io.containerd.image.name','org.opencontainers.image.ref.name',
                    'org.opencontainers.image.created','containerd.io/distribution.source.docker.io'})
            reference=tag(annotation.get('io.containerd.image.name'),expected_tags)
            require(reference not in oci and annotation.get('org.opencontainers.image.ref.name',inspected.build.sha)==inspected.build.sha)
            if 'org.opencontainers.image.created' in annotation:
                require(type(annotation['org.opencontainers.image.created']) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',annotation['org.opencontainers.image.created']))
            if 'containerd.io/distribution.source.docker.io' in annotation:
                require(reference==expected_tags[1] and annotation['containerd.io/distribution.source.docker.io']=='library/mysql')
            require(blob in inventory and not inventory[blob][1] and inventory[blob][0]==row['size'])
            oci[reference]=(blob,row);allowed.add(blob)
        require(set(oci)==set(expected_tags))
    wanted=config_paths|{blob for blob,_ in oci.values()}
    with image_tar(path,inspected,deadline) as (tar,_):
        for entry in tar:
            if entry.name not in wanted:continue
            raw=small(tar,entry);digest=sha256(raw).hexdigest()
            require(config_path(entry.name,'sha256:'+digest));value=strict_json(raw.decode('utf-8'))
            if entry.name in config_paths:configs[entry.name]=(value,'sha256:'+digest)
            else:manifest_blobs[entry.name]=value
    require(set(configs)==config_paths and set(manifest_blobs)=={blob for blob,_ in oci.values()})
    references={};compressions={};config_ids=[];manifest_ids=[]
    for image_id,reference in zip(images,expected_tags):
        row=selected[reference];name=row['Config'];cfg,config_id=configs[name];allowed.add(name);config_ids.append(config_id)
        require(type(cfg) is dict and cfg.get('architecture')=='amd64' and cfg.get('os')=='linux')
        runtime=cfg.get('config');require(type(runtime) is dict)
        if reference==expected_tags[0]:
            require(runtime.get('User')=='10001:10001' and runtime.get('Entrypoint')==['/app/start.sh'] and runtime.get('Volumes') in (None,{}))
        else:require(runtime.get('Volumes') in (None,{}, {'/var/lib/mysql':{}}))
        layers=row['Layers'];rootfs=cfg.get('rootfs')
        require(type(layers) is list and len(layers)<=256 and type(rootfs) is dict and rootfs.get('type')=='layers'
                and type(rootfs.get('diff_ids')) is list and len(layers)==len(rootfs['diff_ids']))
        for layer,diff in zip(layers,rootfs['diff_ids']):
            require(type(layer) is str and layer in inventory and not inventory[layer][1]
                    and type(diff) is str and re.fullmatch('sha256:[0-9a-f]{64}',diff))
            safe_name(layer);require(layer not in references or references[layer]==diff)
            references[layer]=diff;allowed.add(layer)
        manifest_id=None
        if oci:
            blob,desc=oci[reference];manifest_id=desc['digest'];manifest=manifest_blobs[blob]
            require(type(manifest) is dict and set(manifest)<= {'schemaVersion','mediaType','config','layers','annotations'}
                    and manifest.get('schemaVersion')==2 and manifest.get('mediaType')=='application/vnd.oci.image.manifest.v1+json'
                    and type(manifest.get('layers')) is list)
            # These bounded upstream annotations are data, never identity or execution inputs.
            annotations=manifest.get('annotations',{})
            known={'com.docker.official-images.bashbrew.arch','org.opencontainers.image.base.digest','org.opencontainers.image.base.name',
                   'org.opencontainers.image.created','org.opencontainers.image.revision','org.opencontainers.image.source',
                   'org.opencontainers.image.url','org.opencontainers.image.version'}
            require(type(annotations) is dict and set(annotations)<=known and all(type(x) is str and len(x)<=2048 for x in annotations.values()))
            require(descriptor(manifest['config'])==name and manifest['config'].get('mediaType')=='application/vnd.oci.image.config.v1+json'
                    and manifest['config']['digest']==config_id and manifest['config']['size']==inventory[name][0]
                    and tuple(descriptor(layer) for layer in manifest['layers'])==tuple(layers)
                    and all(layer['size']==inventory[path][0] for layer,path in zip(manifest['layers'],layers)))
            if 'LayerSources' in row:
                sources=row['LayerSources']
                require(type(sources) is dict and set(sources)==set(rootfs['diff_ids'])
                    and all(sources[diff]==item for diff,item in zip(rootfs['diff_ids'],manifest['layers'])))
            for layer in manifest['layers']:
                kind=layer.get('mediaType');require(kind in ('application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.oci.image.layer.v1.tar'))
                layer_path=descriptor(layer);require(layer_path not in compressions or compressions[layer_path]==kind);compressions[layer_path]=kind
        require('LayerSources' not in row or bool(oci))
        require(image_id in (config_id,manifest_id));manifest_ids.append(manifest_id)
        by_tag[reference]=(name,tuple(layers))
    if 'repositories' in metadata:
        names={value.rsplit(':',1)[0] for value in expected_tags} if containerd_layer_sources else {'jsm-article-test','jsm-article-mysql'}
        repositories=metadata['repositories'];require(type(repositories) is dict and set(repositories)==names)
        for name,rows in repositories.items():
            require(type(rows) is dict and set(rows)=={inspected.build.sha} and type(rows[inspected.build.sha]) is str and SHA.fullmatch(rows[inspected.build.sha]))
    # Legacy per-layer metadata is safe only inside a referenced layer directory.
    for layer in references:
        if layer.endswith('/layer.tar'):
            parent=layer.rsplit('/',1)[0]
            allowed.update(name for name in (parent+'/json',parent+'/VERSION') if name in inventory)
    extras={name for name,(_,directory) in inventory.items() if not directory and name not in allowed}
    if extras and containerd_layer_sources:
        require(bool(oci) and all('LayerSources' in row for row in selected.values()))
        verify_legacy_containerd(path,inspected,deadline,extras,selected,configs)
    else:
        require(not extras)
    sizes={}
    with image_tar(path,inspected,deadline) as (tar,_):
        for entry in tar:
            if entry.name not in references:continue
            file=tar.extractfile(entry);start=file.read(2);stored=sha256(start);stored_bytes=len(start)
            class Prefix:
                def __init__(self):self.prefix=start
                def read(self,n=-1):
                    nonlocal stored_bytes
                    part=self.prefix[:n] if n>=0 else self.prefix;self.prefix=self.prefix[len(part):]
                    tail=file.read(n-len(part) if n>=0 else n);stored.update(tail);stored_bytes+=len(tail)
                    return part+tail
            if entry.name in compressions:
                require((start==b'\x1f\x8b')==(compressions[entry.name]=='application/vnd.oci.image.layer.v1.tar+gzip'))
            stream=Prefix();wrapped=gzip.GzipFile(fileobj=stream,mode='rb') if start==b'\x1f\x8b' else stream
            digest=sha256();total=0
            while True:
                check(deadline);raw=wrapped.read(min(65536,TAR_LIMIT+1-total))
                if not raw:break
                total+=len(raw);require(total<=TAR_LIMIT);digest.update(raw)
            require(stored_bytes==entry.size)
            if entry.name.startswith('blobs/sha256/'):require(stored.hexdigest()==entry.name.rsplit('/',1)[1])
            require('sha256:'+digest.hexdigest()==references[entry.name]);sizes[entry.name]=total
    require(set(sizes)==set(references))
    unpacked=sum(sizes[path] for _,layers in by_tag.values() for path in layers)
    require(unpacked<=TAR_LIMIT)
    # Include the full bounded gzip/TAR stream rather than only image payloads.
    return ImageProof(tar_bytes,unpacked,images,expected_tags,len(references),tuple(config_ids),tuple(manifest_ids))
