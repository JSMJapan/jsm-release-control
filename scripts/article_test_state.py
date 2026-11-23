"""Owned finite-install state. No application, credential or artifact payload in JSON."""
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import time
from apache_parity_bridge import strict_json

BASE='/var/lib/jsm-article-test-2760'
ROOT_UID=0
VERSION='jsm-clean-article-2760-v1'
TTL=7200
FILES={'state.json','bundle.pyz','artifact.zip','root.password','root.cnf','reader.password','schema.sql','seed.sql',
       'source.json','acceptance.json','app-image-id','mysql-image-id','build-commit','lock'}


class StateRefused(ValueError):pass


def require(ok,code='ARTICLE_STATE_REFUSED'):
    if not ok:raise StateRefused(code)


def trusted(info,kind):return info.st_uid==ROOT_UID and not info.st_mode&0o022 and stat.S_IFMT(info.st_mode)==kind


def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def valid_run(run):return type(run) is str and re.fullmatch('[0-9a-f]{12}',run) is not None


def record_valid(value,run):
    keys={'version','run','control_sha','build_sha','artifact_sha256','bundle_sha256','schema_sha256','seed_sha256',
          'images','tags','containers','create_attempted','created','expires','timer','timer_armed','import_started','import_complete'}
    if type(value) is not dict or set(value)!=keys or value.get('version')!=VERSION or value.get('run')!=run or not valid_run(run):return False
    for key in ('control_sha','build_sha'):
        if type(value.get(key)) is not str or re.fullmatch('[0-9a-f]{40}',value[key]) is None:return False
    for key in ('artifact_sha256','bundle_sha256','schema_sha256','seed_sha256'):
        if type(value.get(key)) is not str or re.fullmatch('[0-9a-f]{64}',value[key]) is None:return False
    if type(value.get('images')) is not list or len(value['images'])!=2 or any(type(x) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',x) for x in value['images']):return False
    if value.get('tags')!=['jsm-article-test:'+value['build_sha'],'jsm-article-mysql:'+value['build_sha']]:return False
    if type(value.get('containers')) is not dict or set(value['containers'])!={'db','app'}:return False
    if any(x is not None and (type(x) is not str or re.fullmatch('[0-9a-f]{64}',x) is None) for x in value['containers'].values()):return False
    if type(value.get('create_attempted')) is not dict or set(value['create_attempted'])!={'db','app'} or any(type(x) is not bool for x in value['create_attempted'].values()):return False
    if any(value['containers'][role] is not None and not value['create_attempted'][role] for role in ('db','app')):return False
    return (type(value.get('created')) is int and type(value.get('expires')) is int
            and value['expires']==value['created']+TTL and value.get('timer')=='jsm-article-2760-expire-'+run
            and type(value.get('timer_armed')) is bool and type(value.get('import_started')) is bool
            and type(value.get('import_complete')) is bool)


class Store:
    def __init__(self,run,base=BASE,create=False):
        require(valid_run(run));self.run=run;self.base=Path(base);self.path=self.base/run;self.fd=None;self.lock=None
        if create:
            try:os.mkdir(self.base,0o700)
            except FileExistsError:pass
        parent=os.open(self.base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            require(trusted(os.fstat(parent),stat.S_IFDIR))
            if create:os.mkdir(run,0o700,dir_fd=parent)
            self.fd=os.open(run,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            require(trusted(os.fstat(self.fd),stat.S_IFDIR) and stat.S_IMODE(os.fstat(self.fd).st_mode)==0o700)
        except BaseException:
            self.close();raise
        finally:os.close(parent)
        flags=os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_CREAT|os.O_EXCL if create else 0)
        try:
            self.lock=os.open('lock',flags,0o600,dir_fd=self.fd)
            require(trusted(os.fstat(self.lock),stat.S_IFREG) and os.fstat(self.lock).st_nlink==1)
            try:fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:raise StateRefused('ARTICLE_RUN_BUSY') from None
        except BaseException:
            self.close();raise

    def close(self):
        for name in ('lock','fd'):
            fd=getattr(self,name)
            if fd is not None:os.close(fd);setattr(self,name,None)

    def write(self,name,raw,mode=0o600):
        require(name in FILES);require(type(raw) is bytes and len(raw)<=512*1024)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode,dir_fd=self.fd)
        try:
            offset=0
            while offset<len(raw):
                written=os.write(fd,raw[offset:]);require(written>0);offset+=written
            os.fchmod(fd,mode);os.fsync(fd)
            info=os.fstat(fd);require(info.st_uid==ROOT_UID and info.st_nlink==1 and stat.S_ISREG(info.st_mode))
            return (info.st_dev,info.st_ino,len(raw),sha256(raw).hexdigest())
        finally:os.close(fd)

    def save(self,value):
        require(record_valid(value,self.run));raw=canonical(value);require(len(raw)<=16384)
        fd=os.open('state.tmp',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            require(os.write(fd,raw)==len(raw));os.fsync(fd)
        finally:os.close(fd)
        os.replace('state.tmp','state.json',src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd)

    def read(self):
        fd=os.open('state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
        try:
            info=os.fstat(fd);require(trusted(info,stat.S_IFREG) and info.st_nlink==1 and info.st_size<=16384)
            raw=os.read(fd,16385);require(len(raw)<=16384)
            value=strict_json(raw.decode('ascii'));require(canonical(value)==raw and record_valid(value,self.run));return value
        finally:os.close(fd)
