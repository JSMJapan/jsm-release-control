"""Strict private Actions artifact reader; never publishes payloads or errors.

An independently authenticated GitHub run/artifact digest is the trust anchor.
The internal checksums are integrity checks, not source authorization.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from zipfile import ZipFile, BadZipFile, ZIP_STORED, ZIP_DEFLATED

from apache_parity_bridge import strict_json

SOURCE = '0184fcbc7bdbb0ca18da842532297bd12f3b557b'
TREE = 'b43fea383b8acfbda07562ee7a32fbc2fe98f05e'
MEMBERS = ('acceptance.json','app-image-id','build-commit','images.tar.gz','mysql-image-id',
           'schema.sql','seed.sql','source.json','SHA256SUMS')
IMAGE_LIMIT = 2*1024**3
ARCHIVE_LIMIT = IMAGE_LIMIT+1024**2
METADATA_LIMIT = 32768
PROOF = dict(status='CI_NATIVE_PASS',network='LOOPBACK_ONLY',database='FIVE_SYNTHETIC_ROWS',
             grants='SELECT_TWO_TABLES',cleanup='VERIFIED',api=5,ssr=10,negative=8)


class ArtifactRefused(ValueError):
    pass


def refuse():
    raise ArtifactRefused('ARTICLE_ARTIFACT_REFUSED')


def hex_value(value,length):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None


@dataclass(frozen=True)
class Build:
    sha: str
    run_id: str
    artifact_id: str
    archive_sha256: str

    def __post_init__(self):
        if (not hex_value(self.sha,40) or not hex_value(self.archive_sha256,64)
                or any(type(value) is not str or re.fullmatch('[1-9][0-9]{0,14}',value) is None
                       for value in (self.run_id,self.artifact_id))):refuse()

    @property
    def artifact_name(self):return 'article-test-2760-'+self.sha

    @property
    def tags(self):return ('jsm-article-test:'+self.sha,'jsm-article-mysql:'+self.sha)


@dataclass(frozen=True)
class Inspected:
    build: Build
    members: dict
    source_sha: str
    source_tree: str
    app_image: str
    mysql_image: str
    archive_bytes: int
    image_archive_bytes: int
    schema_sha256: str
    seed_sha256: str


def bounded_hash(stream,maximum):
    digest=sha256();total=0
    while True:
        raw=stream.read(min(65536,maximum+1-total))
        if not raw:return digest.hexdigest(),total
        total+=len(raw)
        if total>maximum:refuse()
        digest.update(raw)


def file_stamp(info):
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns


def _inspect(file,build):
    archive_hash,archive_size=bounded_hash(file,ARCHIVE_LIMIT)
    if archive_hash!=build.archive_sha256:refuse()
    file.seek(0)
    with ZipFile(file) as archive:
        rows=archive.infolist()
        if len(rows)!=len(MEMBERS) or {row.filename for row in rows}!=set(MEMBERS):refuse()
        for row in rows:
            limit=IMAGE_LIMIT if row.filename=='images.tar.gz' else METADATA_LIMIT
            kind=stat.S_IFMT(row.external_attr>>16)
            if (not 0<row.file_size<=limit or row.compress_size>ARCHIVE_LIMIT
                    or row.compress_type not in (ZIP_STORED,ZIP_DEFLATED) or row.flag_bits&1
                    or kind not in (0,stat.S_IFREG) or row.extra or row.comment):refuse()
        listed={}
        for line in archive.read('SHA256SUMS').decode('ascii').splitlines():
            digest,separator,name=line.partition('  ')
            if not separator or not hex_value(digest,64) or name not in MEMBERS[:-1] or name in listed:refuse()
            listed[name]=digest
        if set(listed)!=set(MEMBERS)-{'SHA256SUMS'}:refuse()
        measured={}
        for name,expected in listed.items():
            with archive.open(name) as member:
                actual,size=bounded_hash(member,IMAGE_LIMIT if name=='images.tar.gz' else METADATA_LIMIT)
            if actual!=expected:refuse()
            measured[name]=dict(sha256=actual,bytes=size)
        checksums=archive.read('SHA256SUMS')
        measured['SHA256SUMS']=dict(sha256=sha256(checksums).hexdigest(),bytes=len(checksums))
        if archive.read('build-commit')!=(build.sha+'\n').encode('ascii'):refuse()
        source=strict_json(archive.read('source.json').decode('utf-8'))
        if (type(source) is not dict or source.get('status')!='SOURCE_INPUTS_VERIFIED'
                or source.get('environment')!='TEST' or source.get('source_commit')!=SOURCE or source.get('source_tree')!=TREE):refuse()
        expected=dict(PROOF,schema_sha256=listed['schema.sql'],seed_sha256=listed['seed.sql'])
        proof=strict_json(archive.read('acceptance.json').decode('utf-8'))
        # Equality alone conflates true/1; all native counters must be exact ints.
        if type(proof) is not dict or proof!=expected or any(type(proof[k]) is not int for k in ('api','ssr','negative')):refuse()
        ids=[]
        for name in ('app-image-id','mysql-image-id'):
            text=archive.read(name).decode('ascii')
            if re.fullmatch(r'sha256:[0-9a-f]{64}\n',text) is None:refuse()
            ids.append(text[:-1])
        if ids[0]==ids[1]:refuse()
        return Inspected(build,measured,SOURCE,TREE,*ids,archive_size,measured['images.tar.gz']['bytes'],
                         listed['schema.sql'],listed['seed.sql'])


def inspect_archive(path,build):
    if type(build) is not Build:refuse()
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as file:
            before=os.fstat(file.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>ARCHIVE_LIMIT:refuse()
            result=_inspect(file,build)
            after=os.fstat(file.fileno());named=os.stat(path,follow_symlinks=False)
            if file_stamp(before)!=file_stamp(after) or file_stamp(before)!=file_stamp(named):refuse()
            return result
    except (OSError,ValueError,TypeError,UnicodeError,BadZipFile,RuntimeError):
        raise ArtifactRefused('ARTICLE_ARTIFACT_REFUSED') from None


def extract_metadata(path,output,inspected):
    """Only seven small reviewed names; never extract the Docker TAR on host."""
    names=set(MEMBERS)-{'images.tar.gz','SHA256SUMS'}
    if type(inspected) is not Inspected:refuse()
    directory=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        with ZipFile(path) as archive:
            for name in sorted(names):
                raw=archive.read(name)
                if len(raw)>METADATA_LIMIT or sha256(raw).hexdigest()!=inspected.members[name]['sha256']:refuse()
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
                with os.fdopen(fd,'wb') as target:target.write(raw)
    except (OSError,ValueError,BadZipFile):raise ArtifactRefused('ARTICLE_ARTIFACT_REFUSED') from None
    finally:os.close(directory)
