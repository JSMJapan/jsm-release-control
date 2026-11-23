"""Fixed local Docker command boundary for the new isolated objects only."""
from hashlib import sha256
import os
from pathlib import Path
import re
import selectors
import socket
import struct
import signal
import stat
import subprocess
import time
from apache_parity_bridge import strict_json
from article_test_actions import HeaderResponse

LABEL='com.jsmjapan.article-test.run'
ID=re.compile('[0-9a-f]{64}')
IMAGE=re.compile('sha256:[0-9a-f]{64}')


class DockerRefused(ValueError):pass


def require(ok,code='ARTICLE_DOCKER_REFUSED'):
    if not ok:raise DockerRefused(code)


FIELDS={'id':'.Id','image':'.Image','run':'(index .Config.Labels "'+LABEL+'")','pid':'.State.Pid',
 'network':'.HostConfig.NetworkMode','memory':'.HostConfig.Memory','swap':'.HostConfig.MemorySwap',
 'cpu':'.HostConfig.NanoCpus','pids':'.HostConfig.PidsLimit','privileged':'.HostConfig.Privileged',
 'readonly':'.HostConfig.ReadonlyRootfs','restart':'.HostConfig.RestartPolicy.Name','capdrop':'.HostConfig.CapDrop',
 'security':'.HostConfig.SecurityOpt','ports':'.HostConfig.PortBindings','pidmode':'.HostConfig.PidMode',
 'ipcmode':'.HostConfig.IpcMode','mounts':'.Mounts','log':'.HostConfig.LogConfig','hosts':'.HostConfig.ExtraHosts','tmpfs':'.HostConfig.Tmpfs'}
FORMAT='{'+','.join('"'+k+'":{{json '+v+'}}' for k,v in FIELDS.items())+'}'


def image_presence_reply(connection,identity,deadline):
    """Headers only for an existing image; never read its JSON Config/Env body."""
    response=HeaderResponse(connection,deadline=deadline)
    try:
        response.begin()
        if response.status==200:return True
        require(response.status==404,'ARTICLE_IMAGE_PRESENCE_UNCONFIRMED')
        headers=response.getheaders();lengths=[v for k,v in headers if k.lower()=='content-length']
        require(len(lengths)==1 and re.fullmatch('[1-9][0-9]{0,2}',lengths[0]) and int(lengths[0])<=512
            and not any(k.lower()=='transfer-encoding' or k.lower()=='content-encoding' for k,v in headers)
            and response.getheader('content-type','').split(';')[0].strip().lower()=='application/json',
            'ARTICLE_IMAGE_PRESENCE_UNCONFIRMED')
        size=int(lengths[0]);raw=bytearray()
        while len(raw)<size:
            left=deadline-time.monotonic();require(left>0,'ARTICLE_STAGE_DEADLINE');connection.settimeout(left)
            part=response.read1(size-len(raw));require(bool(part),'ARTICLE_IMAGE_PRESENCE_UNCONFIRMED');raw.extend(part)
        require(time.monotonic()<deadline,'ARTICLE_STAGE_DEADLINE')
        require(strict_json(raw.decode('utf-8'))=={'message':'No such image: '+identity},'ARTICLE_IMAGE_PRESENCE_UNCONFIRMED')
        return False
    finally:response.close()


class Docker:
    def __init__(self,directory,deadline):
        self.directory,self.deadline=Path(directory),deadline
        self.config=self.directory/'docker-config'
        try:self.config.mkdir(mode=0o700,exist_ok=False)
        except FileExistsError:
            info=os.stat(self.config,follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700 and os.listdir(self.config)==[])
        info=os.stat('/usr/bin/docker',follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)

    def run(self,args,data=None,stream=None,seconds=15,limit=32768,input_limit=0):
        require(type(args) is tuple and args and args[0] in ('image','container','create','start','exec','stop','rm','info','load'))
        require(all(type(x) is str and '\0' not in x for x in args))
        require(type(seconds) in (int,float) and 0<seconds<=120 and type(limit) is int and 0<limit<=32768)
        require(data is None or type(data) is bytes and len(data)<=131072)
        require(not (data is not None and stream is not None))
        require(stream is None or type(input_limit) is int and 0<input_limit<=6*1024**3)
        until=min(self.deadline,time.monotonic()+seconds)
        require(until>time.monotonic(),'ARTICLE_STAGE_DEADLINE')
        command=['/usr/bin/docker','--host','unix:///run/docker.sock','--config',str(self.config),*args]
        output=bytearray();process=None;pending=b'';sent=0;offset=0
        try:
            process=subprocess.Popen(command,stdin=subprocess.PIPE if data is not None or stream is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'},start_new_session=True)
            with selectors.DefaultSelector() as ready:
                os.set_blocking(process.stdout.fileno(),False)
                ready.register(process.stdout,selectors.EVENT_READ,'out')
                if process.stdin is not None:
                    os.set_blocking(process.stdin.fileno(),False)
                    ready.register(process.stdin,selectors.EVENT_WRITE,'in')
                while ready.get_map():
                    remaining=until-time.monotonic();require(remaining>0,'ARTICLE_STAGE_DEADLINE')
                    events=ready.select(remaining);require(bool(events),'ARTICLE_STAGE_DEADLINE')
                    for key,_ in events:
                        if key.data=='out':
                            raw=os.read(key.fd,min(4096,limit+1-len(output)))
                            if not raw:ready.unregister(key.fileobj)
                            else:output.extend(raw);require(len(output)<=limit)
                        else:
                            if not pending:
                                if data is not None:
                                    pending=data[offset:offset+65536];offset+=len(pending)
                                else:
                                    # Source is a previously bounded local ZIP/gzip reader, never a network stream.
                                    pending=stream.read(min(65536,input_limit+1-sent))
                                    require(type(pending) is bytes)
                                require(time.monotonic()<until,'ARTICLE_STAGE_DEADLINE')
                                if not pending:
                                    ready.unregister(key.fileobj);process.stdin.close();continue
                                sent+=len(pending)
                                require(sent<=(len(data) if data is not None else input_limit))
                            written=os.write(key.fd,pending);require(written>0);pending=pending[written:]
            remaining=until-time.monotonic();require(remaining>0,'ARTICLE_STAGE_DEADLINE')
            require(process.wait(timeout=remaining)==0)
            return bytes(output)
        except DockerRefused:raise
        except subprocess.TimeoutExpired:raise DockerRefused('ARTICLE_STAGE_DEADLINE') from None
        except Exception:raise DockerRefused('ARTICLE_DOCKER_REFUSED') from None
        finally:
            if process is not None:
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except OSError:pass
                    try:process.wait(timeout=.1)
                    except subprocess.TimeoutExpired:pass
                for pipe in (process.stdin,process.stdout):
                    if pipe is not None:pipe.close()

    def image_id(self,tag):
        require(type(tag) is str and re.fullmatch('jsm-article-(test|mysql):[0-9a-f]{40}',tag))
        rows=self.run(('image','ls','--quiet','--no-trunc','--filter','reference='+tag),limit=256).decode('ascii').splitlines()
        require(len(rows)<=1 and all(IMAGE.fullmatch(row) for row in rows));return rows[0] if rows else None

    def image_present(self,identity):
        require(type(identity) is str and IMAGE.fullmatch(identity))
        deadline=min(self.deadline,time.monotonic()+2);connection=None
        def stamp(info):return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_ctime_ns
        try:
            parent=os.stat('/run',follow_symlinks=False);first=os.stat('/run/docker.sock',follow_symlinks=False)
            require(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode&0o022
                and stat.S_ISSOCK(first.st_mode) and first.st_uid==0 and first.st_nlink==1 and not first.st_mode&0o002)
            require(time.monotonic()<deadline,'ARTICLE_STAGE_DEADLINE')
            connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(deadline-time.monotonic())
            connection.connect('/run/docker.sock')
            _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            require(uid==0)
            connection.settimeout(max(.001,deadline-time.monotonic()))
            connection.sendall(('GET /images/'+identity+'/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n').encode('ascii'))
            result=image_presence_reply(connection,identity,deadline)
            require(stamp(first)==stamp(os.stat('/run/docker.sock',follow_symlinks=False))
                and stamp(parent)==stamp(os.stat('/run',follow_symlinks=False)))
            return result
        except DockerRefused:raise
        except Exception:raise DockerRefused('ARTICLE_IMAGE_PRESENCE_UNCONFIRMED') from None
        finally:
            if connection is not None:connection.close()

    def absent(self,run,tags,aliases):
        require(type(run) is str and re.fullmatch('[0-9a-f]{12}',run))
        require(type(aliases) is tuple and len(aliases)==2 and all(type(pair) is tuple and 1<=len(pair)<=2 and all(type(x) is str and IMAGE.fullmatch(x) for x in pair) for pair in aliases))
        for tag in tags:require(self.image_id(tag) is None,'ARTICLE_NAME_COLLISION')
        for identity in dict.fromkeys(x for pair in aliases for x in pair):
            require(self.image_present(identity) is False,'ARTICLE_EXISTING_IMAGE_REFUSED')
        for role in ('db','app'):
            name='jsm-article-2760-'+role+'-'+run
            raw=self.run(('container','ls','--all','--quiet','--no-trunc','--filter','name=^'+name+'$'),limit=256)
            require(raw.strip()==b'','ARTICLE_NAME_COLLISION')

    def observe(self,identity,run,image):
        aliases=(image,) if type(image) is str else image
        require(type(identity) is str and ID.fullmatch(identity) and type(aliases) is tuple and 1<=len(aliases)<=2
            and all(type(x) is str and IMAGE.fullmatch(x) for x in aliases) and len(set(aliases))==len(aliases))
        value=strict_json(self.run(('container','inspect','--format',FORMAT,identity),limit=16384).decode('ascii'))
        require(type(value) is dict and set(value)==set(FIELDS) and value['id']==identity and value['run']==run and value['image'] in aliases)
        return value

    def create(self,args):
        value=self.run(('create',*args),seconds=20,limit=128).decode('ascii').strip()
        require(ID.fullmatch(value));return value

    def start(self,identity):
        require(ID.fullmatch(identity));require(self.run(('start',identity),seconds=20,limit=128).strip()==identity.encode())

    def sql(self,identity,raw):
        require(ID.fullmatch(identity))
        return self.run(('exec','-i','--user','0',identity,'mysql','--defaults-extra-file=/run/root.cnf',
            '--protocol=TCP','--host=127.0.0.1','--default-character-set=utf8mb4','--batch','--skip-column-names'),data=raw,seconds=4,limit=32768)
