"""Fixed local Docker command boundary for the new isolated objects only."""
from hashlib import sha256
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from apache_parity_bridge import strict_json

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
 'ipcmode':'.HostConfig.IpcMode','mounts':'.Mounts','log':'.HostConfig.LogConfig','hosts':'.HostConfig.ExtraHosts'}
FORMAT='{'+','.join('"'+k+'":{{json '+v+'}}' for k,v in FIELDS.items())+'}'


class Docker:
    def __init__(self,directory,deadline):
        self.directory,self.deadline=Path(directory),deadline
        self.config=self.directory/'docker-config';self.config.mkdir(mode=0o700,exist_ok=False)
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

    def absent(self,run,tags):
        require(type(run) is str and re.fullmatch('[0-9a-f]{12}',run))
        for tag in tags:require(self.image_id(tag) is None,'ARTICLE_NAME_COLLISION')
        for role in ('db','app'):
            name='jsm-article-2760-'+role+'-'+run
            raw=self.run(('container','ls','--all','--quiet','--no-trunc','--filter','name=^'+name+'$'),limit=256)
            require(raw.strip()==b'','ARTICLE_NAME_COLLISION')

    def observe(self,identity,run,image):
        require(type(identity) is str and ID.fullmatch(identity) and type(image) is str and IMAGE.fullmatch(image))
        value=strict_json(self.run(('container','inspect','--format',FORMAT,identity),limit=16384).decode('ascii'))
        require(type(value) is dict and set(value)==set(FIELDS) and value['id']==identity and value['run']==run and value['image']==image)
        return value

    def create(self,args):
        value=self.run(('create',*args),seconds=20,limit=128).decode('ascii').strip()
        require(ID.fullmatch(value));return value

    def start(self,identity):
        require(ID.fullmatch(identity));require(self.run(('start',identity),seconds=20,limit=128).strip()==identity.encode())

    def sql(self,identity,raw):
        require(ID.fullmatch(identity))
        return self.run(('exec','-i','--user','0',identity,'mysql','--defaults-extra-file=/run/root.cnf',
            '--protocol=TCP','--host=127.0.0.1','--batch','--skip-column-names'),data=raw,seconds=4,limit=32768)
