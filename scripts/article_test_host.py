"""Finite new-object-only STAGE/CLEANUP. No shared publisher, FPM, Apache or DB paths."""
from hashlib import sha256
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import time

from article_test_artifact import Build, inspect_archive, extract_metadata
from article_test_images import image_stream, verify as verify_images
from article_test_docker import Docker, LABEL, ID, IMAGE, DockerRefused
from article_test_state import Store, TTL, VERSION, FILES, trusted, valid_run

MEMORY=768*1024**2
RESERVE=4*1024**3
LIMITS=('--memory','768m','--memory-swap','768m','--cpus','0.5','--pids-limit','128',
        '--log-driver','json-file','--log-opt','max-size=2m','--log-opt','max-file=1','--restart','no')
SLUGS=('anime-figure-guide','parcel-packing','japanese-toothpaste',
       'how-to-save-on-shipping-goods-from-japan','uniqlo-airism-clothing-that-cools-you-down')


class HostRefused(ValueError):pass


def require(ok,reason='ARTICLE_HOST_REFUSED'):
    if not ok:raise HostRefused(reason)


def until(deadline):require(time.monotonic()<deadline,'ARTICLE_STAGE_DEADLINE')


def owned_file(info):
    return stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022


def owned_directory(info,ingress):
    return stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==(10001 if ingress else 0)


def mount(source,target,readonly=True):
    return 'type=bind,source='+str(source)+',target='+target+(',readonly' if readonly else '')


def command(args,deadline,limit=4096):
    """Only code-owned transient timer/systemctl commands reach this boundary."""
    until(deadline)
    try:
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env={'PATH':'/usr/bin:/bin','LANG':'C'},timeout=min(5,deadline-time.monotonic()),check=False)
        require(result.returncode==0 and len(result.stdout)<=limit);return result.stdout
    except HostRefused:raise
    except Exception:raise HostRefused('ARTICLE_TIMER_REFUSED') from None


def timer(store,state,deadline):
    name=state['timer']
    raw=command(('/usr/bin/systemctl','show',name+'.timer','--property=LoadState','--value'),deadline)
    require(raw.strip()==b'not-found','ARTICLE_NAME_COLLISION')
    bundle=store.path/'bundle.pyz'
    left=state['expires']-int(time.time());require(0<left<=TTL)
    command(('/usr/bin/systemd-run','--quiet','--collect','--unit='+name,'--on-active='+str(left)+'s',
        '--timer-property=AccuracySec=1s','--property=Type=oneshot','--property=TimeoutStartSec=120',
        '--property=UMask=0077','/usr/bin/python3','-I','-B',str(bundle),'expire',store.run),deadline)
    state['timer_armed']=True;store.save(state)


def resource_admission(store,archive_size,proof,docker):
    require(os.uname().sysname=='Linux' and os.uname().machine=='x86_64','ARTICLE_PLATFORM_REFUSED')
    # DockerRootDir is consumed privately; no host path is emitted or persisted.
    root=docker.run(('info','--format','{{.DockerRootDir}}'),limit=4096).decode('ascii').strip()
    require(root.startswith('/') and '\n' not in root and '\0' not in root)
    root_info=os.stat(root,follow_symlinks=False)
    require(trusted(root_info,stat.S_IFDIR),'ARTICLE_RESOURCE_REFUSED')
    staging=os.statvfs(store.path);engine=os.statvfs(root)
    required=2*proof.docker_tar_bytes+2*proof.layer_unpacked_bytes+RESERVE
    if os.stat(store.path).st_dev==root_info.st_dev:
        require(staging.f_bavail*staging.f_frsize>=required,'ARTICLE_RESOURCE_REFUSED')
    else:
        require(staging.f_bavail*staging.f_frsize>=RESERVE and engine.f_bavail*engine.f_frsize>=required,'ARTICLE_RESOURCE_REFUSED')
    # The ZIP already occupies archive_size bytes at this point; it is not counted as free.
    require(type(archive_size) is int and archive_size>0)
    with open('/proc/meminfo','rb') as source:raw=source.read(65537)
    require(len(raw)<=65536)
    matches=re.findall(rb'^MemAvailable: +([0-9]{1,12}) kB$',raw,re.M)
    require(len(matches)==1 and int(matches[0])*1024>=5*512*1024**2 and (os.cpu_count() or 0)>=2,'ARTICLE_RESOURCE_REFUSED')


def namespace(pid):
    require(type(pid) is int and 0<pid<=4194304,'ARTICLE_NAMESPACE_REFUSED')
    value=os.readlink('/proc/'+str(pid)+'/ns/net')
    require(re.fullmatch(r'net:\[[1-9][0-9]{0,19}\]',value),'ARTICLE_NAMESPACE_REFUSED');return value


def verify_container(docker,store,state,role,running=True):
    identity=state['containers'][role];require(type(identity) is str and ID.fullmatch(identity))
    image=state['images'][0 if role=='app' else 1]
    row=docker.observe(identity,store.run,image)
    network='none' if role=='db' else 'container:'+state['containers']['db']
    require(row['network']==network and row['memory']==MEMORY and type(row['memory']) is int
        and row['swap']==MEMORY and type(row['swap']) is int and row['cpu']==500000000 and type(row['cpu']) is int
        and row['pids']==128 and type(row['pids']) is int and row['privileged'] is False
        and row['ports'] in ({},None) and row['hosts'] in ([],None) and row['pidmode']==''
        and row['restart']=='no' and row['ipcmode']=='private'
        and row['log']=={'Type':'json-file','Config':{'max-size':'2m','max-file':'1'}},'ARTICLE_ISOLATION_REFUSED')
    caps=row['capdrop'];require(type(caps) is list and all(type(x) is str for x in caps))
    require([x.removeprefix('CAP_') for x in caps]==(['ALL'] if role=='app' else ['NET_RAW']))
    require(row['readonly'] is (role=='app'))
    if role=='app':require(row['security'] in (['no-new-privileges'],['no-new-privileges=true']))
    else:require(row['security'] in ([],None))
    binds={'/run/db-root':(str(store.path/'root.password'),False),'/run/root.cnf':(str(store.path/'root.cnf'),False)} if role=='db' else {
        '/run/article-secrets/reader':(str(store.path/'reader.password'),False),'/run/article-ingress':(str(store.path/'ingress'),True)}
    expected_options={'/var/lib/mysql':'rw,noexec,nosuid,nodev,size=512m'} if role=='db' else {'/tmp':'rw,noexec,nosuid,nodev,size=64m,mode=1777'}
    require(row['tmpfs']==expected_options,'ARTICLE_MOUNT_REFUSED')
    expected_tmp=set(expected_options)
    require(type(row['mounts']) is list and len(row['mounts'])==len(binds)+len(expected_tmp),'ARTICLE_MOUNT_REFUSED')
    seen=set()
    for item in row['mounts']:
        require(type(item) is dict and type(item.get('Destination')) is str)
        dest=item['Destination'];require(dest not in seen);seen.add(dest)
        if dest in binds:
            require(item.get('Type')=='bind' and (item.get('Source'),item.get('RW'))==binds[dest]
                and item.get('Propagation')=='rprivate','ARTICLE_MOUNT_REFUSED')
        else:require(dest in expected_tmp and item.get('Type')=='tmpfs' and item.get('RW') is True,'ARTICLE_MOUNT_REFUSED')
    if running:
        require(type(row['pid']) is int and row['pid']>0,'ARTICLE_NAMESPACE_REFUSED')
        net=namespace(row['pid']);require(net!=namespace(os.getpid()),'ARTICLE_NAMESPACE_REFUSED')
        if role=='app':
            db=docker.observe(state['containers']['db'],store.run,state['images'][1])
            require(net==namespace(db['pid']),'ARTICLE_NAMESPACE_REFUSED')
        raw=docker.run(('exec',identity,'cat','/proc/net/dev'),limit=4096)
        require(re.findall(rb'^\s*([a-zA-Z0-9_@.-]+):',raw,re.M)==[b'lo'],'ARTICLE_NAMESPACE_REFUSED')
        routes=docker.run(('exec',identity,'cat','/proc/net/route'),limit=4096).splitlines()
        require(bool(routes) and all(line.split()[0]==b'lo' for line in routes[1:] if line.split()),'ARTICLE_NAMESPACE_REFUSED')
    return row


def new_sql(docker,store,state,raw):
    verify_container(docker,store,state,'db')
    return docker.sql(state['containers']['db'],raw)


def initialize(docker,store,state,password):
    deadline=min(docker.deadline,time.monotonic()+90)
    while True:
        try:
            require(new_sql(docker,store,state,b'SELECT 1;').strip()==b'1','ARTICLE_DB_READINESS_REFUSED');break
        except DockerRefused:
            require(time.monotonic()+1<deadline,'ARTICLE_DB_READINESS_REFUSED');time.sleep(1)
    schema='article_'+store.run;reader='reader_'+store.run
    for name in ('schema','seed'):
        raw=(store.path/(name+'.sql')).read_bytes()
        require(len(raw)<=32768 and sha256(raw).hexdigest()==state[name+'_sha256'])
        prefix=(f'CREATE DATABASE `{schema}` CHARACTER SET utf8mb4;\n' if name=='schema' else '')+f'USE `{schema}`;\n'
        new_sql(docker,store,state,prefix.encode()+raw)
    statements=(f"CREATE USER '{reader}'@'127.0.0.1' IDENTIFIED BY '{password}';"
        f"GRANT SELECT ON `{schema}`.`tnk_blogs` TO '{reader}'@'127.0.0.1';"
        f"GRANT SELECT ON `{schema}`.`tnk_blogs_products` TO '{reader}'@'127.0.0.1';"
        f"SHOW GRANTS FOR '{reader}'@'127.0.0.1';")
    actual=new_sql(docker,store,state,statements.encode()).decode('ascii').splitlines()
    expected={f'GRANT USAGE ON *.* TO `{reader}`@`127.0.0.1`',
        f'GRANT SELECT ON `{schema}`.`tnk_blogs` TO `{reader}`@`127.0.0.1`',
        f'GRANT SELECT ON `{schema}`.`tnk_blogs_products` TO `{reader}`@`127.0.0.1`'}
    require(len(actual)==3 and set(actual)==expected,'ARTICLE_GRANTS_REFUSED')
    require(new_sql(docker,store,state,f'SELECT slug FROM `{schema}`.tnk_blogs ORDER BY slug;'.encode()).decode('ascii').splitlines()==sorted(SLUGS),'ARTICLE_SEED_REFUSED')
    # No host/customer DB is opened; aggregate only over the just-created schema.
    require(new_sql(docker,store,state,f'SELECT COUNT(*) FROM `{schema}`.tnk_blogs;'.encode()).strip()==b'5','ARTICLE_SEED_REFUSED')
    require(new_sql(docker,store,state,f'SELECT COUNT(*) FROM `{schema}`.tnk_blogs_products;'.encode()).strip()==b'0','ARTICLE_SEED_REFUSED')


def create_role(docker,store,state,role):
    # Persistent intent precedes Docker create. Recovery resolves only this exact name+label+image.
    state['create_attempted'][role]=True;store.save(state)
    name='jsm-article-2760-'+role+'-'+store.run
    args=('--name',name,'--label',LABEL+'='+store.run,'--pull','never','--ipc','private',*LIMITS)
    if role=='db':
        args+=('--network','none','--cap-drop','NET_RAW','--tmpfs','/var/lib/mysql:rw,noexec,nosuid,nodev,size=512m',
            '--mount',mount(store.path/'root.password','/run/db-root'),'--mount',mount(store.path/'root.cnf','/run/root.cnf'),
            '-e','MYSQL_ROOT_PASSWORD_FILE=/run/db-root',state['images'][1],
            '--bind-address=127.0.0.1','--skip-name-resolve','--mysqlx=0')
    else:
        args+=('--network','container:'+state['containers']['db'],'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
            '--mount',mount(store.path/'reader.password','/run/article-secrets/reader'),
            '--mount',mount(store.path/'ingress','/run/article-ingress',False),'-e','JSM_ARTICLE_RUN='+store.run,state['images'][0])
    identity=docker.create(args);state['containers'][role]=identity;store.save(state)
    verify_container(docker,store,state,role,False);docker.start(identity)
    verify_container(docker,store,state,role)


def cleanup(store,state,docker,deadline):
    """Never prune or delete by a global label filter. Recover only pre-recorded exact names."""
    require(docker is not None or not state['import_started'] and not any(state['create_attempted'].values()) and all(x is None for x in state['containers'].values()),'ARTICLE_CLEANUP_UNCONFIRMED')
    deadline=min(deadline,time.monotonic()+90)
    if docker is not None:docker.deadline=deadline
    failures=[]
    for role in ('app','db'):
        try:
            identity=state['containers'][role]
            if identity is None and state['create_attempted'][role]:
                name='jsm-article-2760-'+role+'-'+store.run
                rows=docker.run(('container','ls','--all','--quiet','--no-trunc','--filter','name=^'+name+'$'),limit=256).decode('ascii').splitlines()
                require(len(rows)<=1 and all(ID.fullmatch(row) for row in rows))
                identity=rows[0] if rows else None
            if identity is not None:
                present=docker.run(('container','ls','--all','--quiet','--no-trunc','--filter','id='+identity),limit=256).decode('ascii').splitlines()
                require(present in ([],[identity]),'ARTICLE_CLEANUP_UNCONFIRMED')
                if not present:
                    state['containers'][role]=None;store.save(state);continue
                docker.observe(identity,store.run,state['images'][0 if role=='app' else 1])
                docker.run(('rm','--force',identity),seconds=20,limit=256)
                # ID-only readback; failure is not treated as absence.
                rows=docker.run(('container','ls','--all','--quiet','--no-trunc','--filter','id='+identity),limit=256)
                require(not rows.strip(),'ARTICLE_CLEANUP_UNCONFIRMED')
                state['containers'][role]=None;store.save(state)
        except Exception:failures.append(role)
    if not failures and state['import_started']:
        for tag,image in zip(state['tags'],state['images']):
            try:
                current=docker.image_id(tag)
                if current is not None:
                    require(current==image,'ARTICLE_CLEANUP_UNCONFIRMED')
                    docker.run(('image','rm',tag),seconds=20,limit=4096)
                    require(docker.image_id(tag) is None,'ARTICLE_CLEANUP_UNCONFIRMED')
            except Exception:failures.append('image')
    if failures or state['import_started'] and not state['import_complete']:
        raise HostRefused('ARTICLE_CLEANUP_UNCONFIRMED')
    # Validate the complete deletion set before stopping expiry or deleting recovery controls.
    names=os.listdir(store.fd)
    for name in names:
        require(name in FILES or name in ('ingress','docker-config'),'ARTICLE_CLEANUP_UNCONFIRMED')
        if name in ('ingress','docker-config'):
            directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=store.fd)
            try:
                info=os.fstat(directory)
                require(owned_directory(info,name=='ingress'))
                entries=os.listdir(directory)
                if name=='ingress':
                    require(set(entries)<= {'http.sock'})
                    if entries:
                        info=os.stat('http.sock',dir_fd=directory,follow_symlinks=False)
                        require(stat.S_ISSOCK(info.st_mode) and info.st_uid==10001)
                else:require(entries==[])
            finally:os.close(directory)
        else:
            info=os.stat(name,dir_fd=store.fd,follow_symlinks=False)
            require(owned_file(info))
    # Keep state+bundle+lock and active TTL if any data deletion or timer stop fails.
    for name in names:
        if name in ('state.json','bundle.pyz','lock'):continue
        if name in ('ingress','docker-config'):
            directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=store.fd)
            try:
                if name=='ingress' and 'http.sock' in os.listdir(directory):os.unlink('http.sock',dir_fd=directory)
            finally:os.close(directory)
            os.rmdir(name,dir_fd=store.fd)
        else:os.unlink(name,dir_fd=store.fd)
    if state['timer_armed']:
        command(('/usr/bin/systemctl','stop',state['timer']+'.timer'),deadline)
    for name in ('state.json','bundle.pyz','lock'):
        if name in names:os.unlink(name,dir_fd=store.fd)
    os.rmdir(store.path)
    return {'status':'CLEANED','run':store.run,'containers_removed':True,'owned_tags_removed':True}


def prepare(store,build,control_sha,bundle,deadline):
    """Arm the same owned expiry before accepting any private archive byte."""
    require(type(build) is Build and type(control_sha) is str and re.fullmatch('[0-9a-f]{40}',control_sha))
    now=int(time.time())
    state=dict(version=VERSION,run=store.run,control_sha=control_sha,build_sha=build.sha,
        artifact_sha256=build.archive_sha256,bundle_sha256=sha256(bundle).hexdigest(),schema_sha256=None,
        seed_sha256=None,images=[None,None],tags=list(build.tags),containers={'db':None,'app':None},
        create_attempted={'db':False,'app':False},created=now,expires=now+TTL,
        timer='jsm-article-2760-expire-'+store.run,timer_armed=False,import_started=False,import_complete=False,pending=True)
    store.save(state);store.write('bundle.pyz',bundle,0o444);timer(store,state,deadline)
    return state


def stage(store,build,control_sha,bundle,deadline,docker_type=Docker):
    """Receiver has armed pending expiry before streaming the private archive."""
    require(os.geteuid()==0 and type(build) is Build and re.fullmatch('[0-9a-f]{40}',control_sha))
    until(deadline);archive=store.path/'artifact.zip';state=store.read()
    require(state['pending'] is True and state['timer_armed'] is True and state['build_sha']==build.sha
        and state['artifact_sha256']==build.archive_sha256 and state['control_sha']==control_sha
        and state['bundle_sha256']==sha256(bundle).hexdigest())
    inspected=inspect_archive(archive,build);proof=verify_images(archive,inspected,deadline)
    state.update(pending=False,schema_sha256=inspected.schema_sha256,seed_sha256=inspected.seed_sha256,
        images=[inspected.app_image,inspected.mysql_image]);store.save(state)
    docker=None
    try:
        docker=docker_type(store.path,deadline)
        resource_admission(store,archive.stat().st_size,proof,docker)
        docker.absent(store.run,build.tags)
        extract_metadata(archive,store.path,inspected)
        root=secrets.token_hex(32);reader=secrets.token_hex(32)
        store.write('root.password',root.encode(),0o444)
        store.write('root.cnf',('[client]\nuser=root\npassword='+root+'\n').encode(),0o444)
        store.write('reader.password',reader.encode(),0o444)
        os.mkdir('ingress',0o700,dir_fd=store.fd);os.chown(store.path/'ingress',10001,10001)
        state['import_started']=True;store.save(state)
        with image_stream(archive,inspected,deadline) as source:
            docker.run(('load','--quiet'),stream=source,seconds=120,input_limit=proof.docker_tar_bytes,limit=4096)
        require([docker.image_id(tag) for tag in build.tags]==state['images'],'ARTICLE_IMAGE_ID_REFUSED')
        state['import_complete']=True;store.save(state)
        create_role(docker,store,state,'db');initialize(docker,store,state,reader)
        create_role(docker,store,state,'app')
        from article_test_smoke import verify as smoke
        smoke_result=smoke(store,deadline)
        verify_container(docker,store,state,'db');verify_container(docker,store,state,'app')
        # The serving Unix socket is local/private. A later approved ingress is required for phone QA.
        return dict(status='STAGED_LOCAL_ONLY',run=store.run,expires=state['expires'],build_sha=build.sha,
                    artifact_sha256=build.archive_sha256,app_image=state['images'][0],mysql_image=state['images'][1],
                    ingress='PRIVATE_UNIX_ONLY',qa='NOT_TESTED',local_smoke=smoke_result)
    except BaseException:
        try:
            reserve=min(deadline+90,time.monotonic()+90)
            if docker is not None:docker.deadline=reserve
            cleanup(store,state,docker,reserve)
        except Exception:raise HostRefused('ARTICLE_CLEANUP_UNCONFIRMED') from None
        raise
