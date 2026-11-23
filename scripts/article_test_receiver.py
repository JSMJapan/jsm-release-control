"""Root-only bounded receiver for a reviewed public bundle and a fixed private artifact."""
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import time

from apache_parity_bridge import strict_json
from article_test_artifact import Build, ARCHIVE_LIMIT, SOURCE as SOURCE_SHA, TREE as SOURCE_TREE
from article_test_state import Store, BASE, valid_run, canonical, trusted
from article_test_docker import Docker
from article_test_host import HostRefused, require, prepare, stage, cleanup

MAGIC=b'JSM_ARTICLE_TEST_2760_V1\n'
VERSION='jsm-article-test-receiver-v1'
STAGE_SECONDS=600
CLEANUP_SECONDS=90


def pins(path=None):
    if path is None:
        import pkgutil
        raw=pkgutil.get_data(__name__,'article_test_pins.json')
        require(type(raw) is bytes,'ARTIFACT_NOT_PINNED')
    else:raw=Path(path).read_bytes()
    require(len(raw)<=4096,'ARTIFACT_NOT_PINNED')
    value=strict_json(raw.decode('ascii'))
    require(type(value) is dict and set(value)=={'status','source_sha','source_tree','build_sha','run_id','artifact_id','archive_sha256'}
        and value['status']=='PINNED' and value['source_sha']==SOURCE_SHA and value['source_tree']==SOURCE_TREE,'ARTIFACT_NOT_PINNED')
    return Build(value['build_sha'],value['run_id'],value['artifact_id'],value['archive_sha256'])


def read_exact(fd,size,deadline):
    require(type(size) is int and 0<=size<=65536,'ARTICLE_STREAM_REFUSED');out=bytearray()
    while len(out)<size:
        left=deadline-time.monotonic();require(left>0,'ARTICLE_STREAM_DEADLINE')
        require(bool(select.select([fd],[],[],left)[0]),'ARTICLE_STREAM_DEADLINE')
        raw=os.read(fd,size-len(out));require(bool(raw),'ARTICLE_STREAM_REFUSED');out.extend(raw)
    return bytes(out)


def header(fd,deadline):
    require(read_exact(fd,len(MAGIC),deadline)==MAGIC,'ARTICLE_STREAM_REFUSED')
    length=int.from_bytes(read_exact(fd,4,deadline),'big');require(0<length<=4096,'ARTICLE_STREAM_REFUSED')
    raw=read_exact(fd,length,deadline);value=strict_json(raw.decode('ascii'))
    require(canonical(value)==raw and type(value) is dict
        and set(value)=={'version','nonce','operation','run','control_sha','build','archive_size'},'ARTICLE_STREAM_REFUSED')
    require(value['version']==VERSION and type(value['nonce']) is str and re.fullmatch('[0-9a-f]{32}',value['nonce'])
        and type(value['control_sha']) is str and re.fullmatch('[0-9a-f]{40}',value['control_sha'])
        and valid_run(value['run']) and value['operation'] in ('STAGE','CLEANUP'),'ARTICLE_STREAM_REFUSED')
    if value['operation']=='STAGE':
        build=pins();require(value['build']==asdict(build) and type(value['archive_size']) is int
            and 0<value['archive_size']<=ARCHIVE_LIMIT,'ARTICLE_STREAM_REFUSED')
    else:require(value['build'] is None and value['archive_size']==0 and type(value['archive_size']) is int,'ARTICLE_STREAM_REFUSED')
    return value


def receive(fd,store,value,deadline):
    statv=os.statvfs(store.path)
    require(statv.f_bavail*statv.f_frsize>=value['archive_size']+4*1024**3,'ARTICLE_RESOURCE_REFUSED')
    target=os.open('artifact.zip',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=store.fd)
    digest=sha256();total=0
    try:
        while total<value['archive_size']:
            raw=read_exact(fd,min(65536,value['archive_size']-total),deadline);digest.update(raw);total+=len(raw)
            offset=0
            while offset<len(raw):
                size=os.write(target,raw[offset:]);require(size>0,'ARTICLE_STREAM_REFUSED');offset+=size
        os.fsync(target)
        require(digest.hexdigest()==value['build']['archive_sha256'],'ARTICLE_STREAM_REFUSED')
        end_input(fd,deadline)
    finally:os.close(target)


def end_input(fd,deadline):
    left=min(1,deadline-time.monotonic());require(left>0,'ARTICLE_STREAM_DEADLINE')
    require(bool(select.select([fd],[],[],left)[0]) and os.read(fd,1)==b'','ARTICLE_STREAM_REFUSED')


def expire(bundle,run):
    require(os.geteuid()==0 and valid_run(run),'ARTICLE_EXPIRE_REFUSED')
    with_store=None
    try:
        with_store=Store(run);state=with_store.read()
        require(sha256(bundle).hexdigest()==state['bundle_sha256'] and int(time.time())>=state['expires'],'ARTICLE_EXPIRE_REFUSED')
        deadline=time.monotonic()+CLEANUP_SECONDS
        runner=Docker(with_store.path,deadline) if state['import_started'] or any(state['create_attempted'].values()) else None
        return cleanup(with_store,state,runner,deadline)
    finally:
        if with_store is not None:with_store.close()


def perform(bundle,fd=0):
    require(os.geteuid()==0,'ARTICLE_ROOT_REQUIRED')
    started=time.monotonic();overall=started+STAGE_SECONDS+CLEANUP_SECONDS
    value=header(fd,min(started+10,overall));store=None
    try:
        store=Store(value['run'],create=value['operation']=='STAGE')
        if value['operation']=='STAGE':
            prepare(store,pins(),value['control_sha'],bundle,min(started+10,overall))
            receive(fd,store,value,min(started+300,overall))
            result=stage(store,pins(),value['control_sha'],bundle,min(started+STAGE_SECONDS,overall))
        else:
            end_input(fd,min(started+10,overall))
            state=store.read()
            runner=Docker(store.path,overall) if state['import_started'] or any(state['create_attempted'].values()) else None
            result=cleanup(store,state,runner,overall)
        return dict(version=VERSION,nonce=value['nonce'],euid=0,**result)
    except BaseException:
        # A failure before host stage has a state file only after its own creation intent was saved.
        if store is not None and store.path.exists():
            try:
                if 'state.json' in os.listdir(store.fd):
                    state=store.read()
                    runner=Docker(store.path,overall) if state['import_started'] or any(state['create_attempted'].values()) else None
                    cleanup(store,state,runner,overall)
                else:
                    for name in os.listdir(store.fd):
                        require(name in ('artifact.zip','lock','state.tmp'),'ARTICLE_CLEANUP_UNCONFIRMED')
                        info=os.stat(name,dir_fd=store.fd,follow_symlinks=False)
                        require(trusted(info,stat.S_IFREG) and info.st_nlink==1,'ARTICLE_CLEANUP_UNCONFIRMED')
                        os.unlink(name,dir_fd=store.fd)
                    os.rmdir(store.path)
            except Exception:raise HostRefused('ARTICLE_CLEANUP_UNCONFIRMED') from None
        raise
    finally:
        if store is not None:store.close()


SAFE=frozenset(('ARTIFACT_NOT_PINNED','ARTICLE_ROOT_REQUIRED','ARTICLE_STREAM_REFUSED','ARTICLE_STREAM_DEADLINE',
    'ARTICLE_RESOURCE_REFUSED','ARTICLE_CLEANUP_UNCONFIRMED','ARTICLE_STAGE_DEADLINE','ARTICLE_HOST_REFUSED',
    'ARTICLE_TIMER_REFUSED','ARTICLE_ISOLATION_REFUSED','ARTICLE_NAMESPACE_REFUSED','ARTICLE_MOUNT_REFUSED',
    'ARTICLE_NAME_COLLISION','ARTICLE_IMAGE_ID_REFUSED','ARTICLE_READINESS_REFUSED','ARTICLE_HTTP_REFUSED',
    'ARTICLE_GRANTS_REFUSED','ARTICLE_SEED_REFUSED','ARTICLE_DOCKER_REFUSED','ARTICLE_STATE_REFUSED','ARTICLE_RUN_BUSY',
    'ARTICLE_DB_READINESS_REFUSED','ARTICLE_ARTIFACT_REFUSED','ARTICLE_IMAGE_ENVELOPE_REFUSED','ARTICLE_PLATFORM_REFUSED','ARTICLE_EXISTING_IMAGE_REFUSED','ARTICLE_IMAGE_PRESENCE_UNCONFIRMED'))


def main(bundle):
    def timeout(*_):raise HostRefused('ARTICLE_STAGE_DEADLINE')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(STAGE_SECONDS+CLEANUP_SECONDS)
    try:
        if len(sys.argv)==3 and sys.argv[1]=='expire':result=expire(bundle,sys.argv[2])
        else:result=perform(bundle)
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
    except BaseException as error:
        reason=error.args[0] if len(error.args)==1 and type(error.args[0]) is str and error.args[0] in SAFE else 'ARTICLE_HOST_REFUSED'
        print(json.dumps({'version':VERSION,'status':'BLOCKED','reason':reason,'euid':os.geteuid()},sort_keys=True,separators=(',',':')))
        raise SystemExit(1)
    finally:signal.alarm(0)
