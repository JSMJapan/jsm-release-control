"""New finite streaming profile. Reuses existing TEST pin/key gates, not its read-only caps."""
from dataclasses import asdict
from hashlib import sha256
from io import BytesIO
import base64
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import sys
import time
from zipfile import ZipFile,ZIP_DEFLATED,ZipInfo

from apache_parity_bridge import strict_json
from article_test_receiver import MAGIC, VERSION
from article_test_state import canonical, valid_run
from article_test_host import HostRefused, require

MODULES=('apache_parity_bridge.py','hostinger_preflight.py','test_api_readonly_access.py',
    'article_test_artifact.py','article_test_actions.py','article_test_images.py','article_test_state.py',
    'article_test_docker.py','article_test_host.py','article_test_smoke.py','article_test_receiver.py','article_test_pins.json')
MAX_BUNDLE=131072
MAX_RECEIPT=8192


def package(root=None):
    root=Path(root) if root is not None else Path(__file__).resolve().parent
    output=BytesIO()
    with ZipFile(output,'w',compression=ZIP_DEFLATED,compresslevel=9) as archive:
        for name in MODULES:
            raw=(root/name).read_bytes();require(len(raw)<=131072,'ARTICLE_BUNDLE_REFUSED')
            info=ZipInfo(name,date_time=(2026,1,1,0,0,0));info.compress_type=ZIP_DEFLATED;info.external_attr=0o100444<<16
            archive.writestr(info,raw)
        archive.writestr('__main__.py',b'import sys\nfrom pathlib import Path\nfrom article_test_receiver import main\nmain(Path(sys.argv[0]).read_bytes())\n')
    result=output.getvalue();require(len(result)<=MAX_BUNDLE,'ARTICLE_BUNDLE_REFUSED');return result


def frame(operation,run,nonce,control_sha,build,size):
    require(operation in ('STAGE','CLEANUP') and valid_run(run) and re.fullmatch('[0-9a-f]{32}',nonce)
        and re.fullmatch('[0-9a-f]{40}',control_sha),'ARTICLE_CONTEXT_REFUSED')
    value=dict(version=VERSION,nonce=nonce,operation=operation,run=run,control_sha=control_sha,
               build=asdict(build) if build is not None else None,archive_size=size)
    raw=canonical(value);require(len(raw)<=4096,'ARTICLE_CONTEXT_REFUSED')
    return MAGIC+len(raw).to_bytes(4,'big')+raw


def outer_program(bundle,nonce):
    """No private archive, token, app source or password appears in this public program."""
    require(len(bundle)<=MAX_BUNDLE and re.fullmatch('[0-9a-f]{32}',nonce))
    # Linux memfd is a nonpersistent, code-owned public bundle. Root saves its verified copy for TTL cleanup.
    root=("import base64,os,sys; b=base64.b64decode("+repr(base64.b64encode(bundle).decode())+
        "); f=os.memfd_create('jsm-article-2760',0); os.write(f,b); sys.path.insert(0,'/proc/self/fd/'+str(f)); "
        "from article_test_receiver import main; main(b)")
    # -c must fit Linux's per-argument MAX_ARG_STRLEN. Keep the public source bundle conservative.
    require(len(root.encode())<131071,'ARTICLE_BUNDLE_REFUSED')
    source='''import json,os,pwd,selectors,signal,subprocess,time
nonce=NONCE
principal=pwd.getpwuid(os.geteuid()).pw_name
if principal!='marinagurina' or os.geteuid()<=0:raise SystemExit(1)
p=subprocess.Popen(['/usr/bin/sudo','-n','/usr/bin/timeout','--signal=TERM','--kill-after=10','700',
 '/usr/bin/python3','-I','-B','-S','-c',ROOT],stdin=0,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
 env={'PATH':'/usr/bin:/bin','LANG':'C'},start_new_session=True)
raw=bytearray();until=time.monotonic()+710
try:
 with selectors.DefaultSelector() as q:
  q.register(p.stdout,selectors.EVENT_READ)
  while True:
   left=until-time.monotonic()
   if left<=0 or not q.select(left):raise ValueError()
   part=os.read(p.stdout.fileno(),min(4096,8193-len(raw)))
   if not part:break
   raw.extend(part)
   if len(raw)>8192:raise ValueError()
  left=until-time.monotonic()
  if left<=0:raise ValueError()
  code=p.wait(timeout=left)
 value=json.loads(raw.decode('ascii'),object_pairs_hook=lambda rows:dict(rows))
 if type(value) is not dict or value.get('euid')!=0:raise ValueError()
 print(json.dumps({'version':'jsm-article-test-outer-v1','nonce':nonce,'principal':principal,'euid':os.geteuid(),'root':value},separators=(',',':')))
except BaseException:
 if p.poll() is None:
  try:os.killpg(p.pid,signal.SIGKILL)
  except OSError:pass
  try:p.wait(timeout=.2)
  except subprocess.TimeoutExpired:pass
 raise SystemExit(1)
finally:p.stdout.close()
'''.replace('NONCE',repr(nonce)).replace('ROOT',repr(root))
    require(len(source.encode())<131071,'ARTICLE_BUNDLE_REFUSED');return source


def ssh_command(identity,hosts,program):
    return ['/usr/bin/ssh','-F','/dev/null','-T','-i',str(identity),'-p','22',
        '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes',
        '-o','BatchMode=yes','-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
        '-o','KbdInteractiveAuthentication=no','-o','ClearAllForwardings=yes',
        '-o','UserKnownHostsFile='+str(hosts),'-o','GlobalKnownHostsFile=/dev/null',
        '-o','ConnectTimeout=7','-o','ConnectionAttempts=1','-o','ServerAliveInterval=3',
        '-o','ServerAliveCountMax=2','-o','LogLevel=ERROR','marinagurina@34.104.157.63',
        '/usr/bin/python3 -I -B -S -c '+shlex.quote(program)]


def transfer(command,prefix,archive,deadline):
    """One stream only, bounded memory and output; no retry or fallback SSH destination."""
    process=None;pending=prefix;output=bytearray();source=None
    try:
        if archive is not None:
            fd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);source=os.fdopen(fd,'rb')
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env={'PATH':'/usr/bin:/bin','LANG':'C'},start_new_session=True)
        os.set_blocking(process.stdin.fileno(),False);os.set_blocking(process.stdout.fileno(),False)
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdin,selectors.EVENT_WRITE,'in');ready.register(process.stdout,selectors.EVENT_READ,'out')
            while ready.get_map():
                left=deadline-time.monotonic();require(left>0,'ARTICLE_DELIVERY_DEADLINE')
                events=ready.select(left);require(bool(events),'ARTICLE_DELIVERY_DEADLINE')
                for key,_ in events:
                    if key.data=='in':
                        if not pending:pending=source.read(65536) if source is not None else b''
                        if not pending:ready.unregister(key.fileobj);process.stdin.close();continue
                        wrote=os.write(key.fd,pending);require(wrote>0);pending=pending[wrote:]
                    else:
                        raw=os.read(key.fd,min(4096,MAX_RECEIPT+1-len(output)))
                        if not raw:ready.unregister(key.fileobj)
                        else:output.extend(raw);require(len(output)<=MAX_RECEIPT,'ARTICLE_RECEIPT_REFUSED')
            left=deadline-time.monotonic();require(left>0,'ARTICLE_DELIVERY_DEADLINE')
            code=process.wait(timeout=left);require(code==0,'ARTICLE_DELIVERY_REFUSED');return bytes(output)
    except HostRefused:raise
    except Exception:raise HostRefused('ARTICLE_DELIVERY_REFUSED') from None
    finally:
        if source is not None:source.close()
        if process is not None:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except OSError:pass
                try:process.wait(timeout=.2)
                except subprocess.TimeoutExpired:pass
            for stream in (process.stdin,process.stdout):
                if stream is not None:stream.close()


def project(raw,nonce,operation,run,build,expected_images=None):
    require(type(raw) is bytes and len(raw)<=MAX_RECEIPT,'ARTICLE_RECEIPT_REFUSED')
    outer=strict_json(raw.decode('ascii'))
    require(type(outer) is dict and set(outer)=={'version','nonce','principal','euid','root'}
        and outer['version']=='jsm-article-test-outer-v1' and outer['nonce']==nonce
        and outer['principal']=='marinagurina' and type(outer['euid']) is int and 0<outer['euid']<2**32,'ARTICLE_RECEIPT_REFUSED')
    value=outer['root'];require(type(value) is dict and value.get('version')==VERSION and type(value.get('euid')) is int and value['euid']==0,'ARTICLE_RECEIPT_REFUSED')
    if value.get('status')=='BLOCKED':
        from article_test_receiver import SAFE
        require(set(value)=={'version','status','reason','euid'} and type(value['reason']) is str and value['reason'] in SAFE,'ARTICLE_RECEIPT_REFUSED')
        return dict(status='BLOCKED',reason=value['reason'],run=run)
    if operation=='CLEANUP':
        require(set(value)=={'version','nonce','euid','status','run','containers_removed','owned_tags_removed'}
            and value['nonce']==nonce and value['run']==run and value['status']=='CLEANED'
            and value['containers_removed'] is True and value['owned_tags_removed'] is True,'ARTICLE_RECEIPT_REFUSED')
    else:
        require(type(expected_images) is tuple and len(expected_images)==2,'ARTICLE_RECEIPT_REFUSED')
        require(set(value)=={'version','nonce','euid','status','run','expires','build_sha','artifact_sha256','app_image','mysql_image','ingress','qa','local_smoke'}
            and value['nonce']==nonce and value['run']==run and value['status']=='STAGED_LOCAL_ONLY'
            and value['build_sha']==build.sha and value['artifact_sha256']==build.archive_sha256
            and type(value['expires']) is int and int(time.time())<value['expires']<=int(time.time())+7200
            and all(type(value[k]) is str and re.fullmatch('sha256:[0-9a-f]{64}',value[k]) for k in ('app_image','mysql_image'))
            and (value['app_image'],value['mysql_image'])==expected_images
            and value['ingress']=='PRIVATE_UNIX_ONLY' and value['qa']=='NOT_TESTED'
            and value['local_smoke']=={'articles':5,'real_404':2,'visibility':'BASIC_HTML_ONLY','browser_handoff':'CI_ONLY'},'ARTICLE_RECEIPT_REFUSED')
    return value
