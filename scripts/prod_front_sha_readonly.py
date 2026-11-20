#!/usr/bin/env python3
"""Fixed production source metadata only. No source bytes or remote writes.

An existing protected admin identity may refuse the fixed command. Refusal is
terminal: no alternate key, forced-command bypass, shell or provider fallback.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_admin_readonly_probe import PIN_SHA256, Refused, bounded_ssh, private_file
from hostinger_preflight import Api, GH_ENV, GH_REPO, GITHUB, REPO, policy_ready
from hostinger_preflight import Refused as PolicyRefused

VERSION = 'jsm-prod-front-sha-v1'
EXPECTED = {
    'config/articleSeo.js': '8b6576b90cb6f1a3475805f976b15e906009c5652bff0f35db0747c23eab9a4b',
    'src/pages/MainFlow/BlogArticle/index.tsx': '725ba79b928ba95331fc8cd42e53b3bc32a01336900fe658e48392f32999a447',
    'src/helpers/blogArticleSchema.js': 'b887aac742a18da0e9c9714d1031c027ca56d17adfe1ff484e4f03522071ca40',
}

# No caller-controlled path, environment, code, HTTP, PHP or app execution.
# O_NOATIME avoids even file access-time updates. All directory components are
# opened by descriptor with O_NOFOLLOW; regular single-link files are required.
REMOTE = r'''import hashlib,json,os,stat
BASE='/var/www/jsmjapan.com-front'
PATHS=('config/articleSeo.js','src/pages/MainFlow/BlogArticle/index.tsx','src/helpers/blogArticleSchema.js')
LIMIT=1048576
NOATIME=0x40000
def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def one(path):
    row=dict(path=path,type='unreadable',sha256=None)
    directories=[]; parents=[]; fd=None
    try:
        directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        directories.append(directory)
        for component in (BASE+'/'+path).strip('/').split('/')[:-1]:
            parent=directory
            linked=os.stat(component,dir_fd=parent,follow_symlinks=False)
            directory=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            directories.append(directory)
            opened=os.fstat(directory)
            if identity(linked)!=identity(opened):
                row['type']='unstable';return row
            parents.append((parent,component,directory,identity(opened)))
        name=path.split('/')[-1]
        before=os.stat(name,dir_fd=directory,follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            row['type']='not_regular';return row
        if before.st_nlink!=1:
            row['type']='unsafe';return row
        if before.st_size>LIMIT:
            row['type']='oversize';return row
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|NOATIME,dir_fd=directory)
        opened=os.fstat(fd)
        if identity(before)!=identity(opened):
            row['type']='unstable';return row
        digest=hashlib.sha256(); total=0
        while True:
            data=os.read(fd,min(65536,LIMIT+1-total))
            if not data:break
            total+=len(data)
            if total>LIMIT:
                row['type']='oversize';return row
            digest.update(data)
        after=os.fstat(fd)
        linked=os.stat(name,dir_fd=directory,follow_symlinks=False)
        if identity(opened)!=identity(after) or identity(after)!=identity(linked) or total!=after.st_size:
            row['type']='unstable';return row
        for parent,component,directory,expected in parents:
            if identity(os.fstat(directory))!=expected or identity(os.stat(component,dir_fd=parent,follow_symlinks=False))!=expected:
                row['type']='unstable';return row
        row.update(type='regular',sha256=digest.hexdigest())
        return row
    except FileNotFoundError:
        row['type']='missing';return row
    except OSError:
        return row
    finally:
        if fd is not None:os.close(fd)
        for directory in reversed(directories):os.close(directory)
def read_files():
    return [one(path) for path in PATHS]
def main():
    rows=read_files() if getattr(os,'O_NOATIME',None)==NOATIME and os.geteuid()==0 else [dict(path=p,type='unreadable',sha256=None) for p in PATHS]
    print(json.dumps(dict(version='jsm-prod-front-sha-v1',nonce=NONCE,euid=os.geteuid(),files=rows,writes_performed=False),sort_keys=True))
if __name__=='__main__':main()
'''


def context_ready(env):
    expected = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
                    GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_WORKFLOW_REF=REPO+'/.github/workflows/prod-front-sha-readonly.yml@refs/heads/main')
    if (any(env.get(name) != value for name,value in expected.items())
            or not re.fullmatch('[0-9a-f]{40}',env.get('GITHUB_SHA',''))
            or env.get('GITHUB_WORKFLOW_SHA') != env.get('GITHUB_SHA')
            or not re.fullmatch('[0-9]{1,15}',env.get('GITHUB_RUN_ID',''))):
        raise Refused('OWNER_MANUAL_MAIN_FRONT_SHA_WORKFLOW_REQUIRED')


def remote_program(nonce):
    if type(nonce) is not str or not re.fullmatch('[0-9a-f]{32}',nonce):
        raise Refused('NONCE_REQUIRED')
    return ("NONCE='"+nonce+"'\n"+REMOTE).encode('ascii')


def project_remote(raw,nonce):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError()
            result[key]=value
        return result
    try:
        if type(raw) is not bytes or len(raw)>4096:raise ValueError()
        value=json.loads(raw.decode('ascii'),object_pairs_hook=pairs)
        if (type(value) is not dict or set(value)!={'version','nonce','euid','files','writes_performed'}
                or value['version']!=VERSION or value['nonce']!=nonce
                or type(value['euid']) is not int or value['euid']!=0
                or value['writes_performed'] is not False
                or type(value['files']) is not list or len(value['files'])!=3):raise ValueError()
        rows=[]
        for item,(path,expected) in zip(value['files'],EXPECTED.items()):
            if (type(item) is not dict or set(item)!={'path','type','sha256'} or item['path']!=path
                    or item['type'] not in ('regular','missing','not_regular','unsafe','unstable','oversize','unreadable')
                    or (item['type']=='regular' and (type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',item['sha256'])))
                    or (item['type']!='regular' and item['sha256'] is not None)):raise ValueError()
            rows.append(dict(item,expected_sha256=expected,matches_expected=item['sha256']==expected and item['type']=='regular'))
        matches=all(item['matches_expected'] for item in rows)
        return dict(receipt_version=VERSION,status='PROD_FRONT_EXPECTED_FILES_MATCH' if matches else 'BLOCKED',
                    reason='THREE_HISTORICAL_EXPECTED_FILES_MATCH' if matches else 'FILE_MISSING_TYPE_OR_DIGEST_DRIFT',
                    files=rows,root_identity=True,writes_performed=False,
                    installed_release_sha=None,deploy_acceptance='NOT_ESTABLISHED')
    except Exception:
        raise Refused('REMOTE_SCHEMA_NONCE_OR_ROOT_REJECTED') from None


def collect(api,env):
    context_ready(env)
    repo=api.get_json(GITHUB,GH_REPO)
    environment=api.get_json(GITHUB,GH_ENV)
    branches=api.get_json(GITHUB,GH_ENV+'/deployment-branch-policies')
    try:policy_ready(repo,environment,branches)
    except PolicyRefused:raise Refused('PROTECTED_OWNER_MAIN_ENVIRONMENT_REQUIRED') from None
    key=env.get('APACHE_BOOTSTRAP_ADMIN_SSH_KEY');known=env.get('APACHE_BOOTSTRAP_KNOWN_HOSTS')
    if not isinstance(key,str) or not 0<len(key)<=16384 or '\x00' in key:
        raise Refused('ADMIN_SSH_KEY_NOT_CONFIGURED')
    if not isinstance(known,str) or len(known)>16384 or hashlib.sha256(known.encode()).hexdigest()!=PIN_SHA256:
        raise Refused('EXACT_TRUSTED_HOST_PIN_REQUIRED')
    nonce=secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='jsm-front-sha-ro-') as folder:
        os.chmod(folder,0o700)
        identity,hosts=Path(folder)/'identity',Path(folder)/'known_hosts'
        private_file(identity,key.replace('\r\n','\n').rstrip('\n')+'\n');private_file(hosts,known)
        command=['ssh','-F','/dev/null','-T','-i',str(identity),'-p','17177',
                 '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes',
                 '-o','BatchMode=yes','-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
                 '-o','KbdInteractiveAuthentication=no','-o','ClearAllForwardings=yes',
                 '-o','UserKnownHostsFile='+str(hosts),'-o','GlobalKnownHostsFile=/dev/null',
                 '-o','ConnectTimeout=7','-o','ConnectionAttempts=1','-o','ServerAliveInterval=3',
                 '-o','ServerAliveCountMax=2','-o','LogLevel=ERROR',
                 'root@187.77.118.50','/usr/bin/python3','-I','-B','-']
        result=project_remote(bounded_ssh(command,remote_program(nonce)),nonce)
    return dict(result,resource='hostinger:srv1687281',domain='jsmjapan.com',ip='187.77.118.50',
                ssh_port=17177,known_hosts_sha256=PIN_SHA256,source_sha=env['GITHUB_SHA'],
                workflow_run_url='https://github.com/'+REPO+'/actions/runs/'+env['GITHUB_RUN_ID'])


def main():
    def expired(*_):raise Refused('OVERALL_DEADLINE')
    try:
        if len(sys.argv)!=1:raise Refused('NO_ARGUMENTS_OR_INPUTS_ACCEPTED')
        signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,60)
        result=collect(Api(),os.environ)
        result['verified_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        print(json.dumps(result,sort_keys=True))
        return 0 if result['status']=='PROD_FRONT_EXPECTED_FILES_MATCH' else 1
    except Exception as error:
        reason=str(error) if isinstance(error,Refused) else 'FRONT_SHA_PROBE_REJECTED'
        print(json.dumps(dict(receipt_version=VERSION,status='BLOCKED',reason=reason,writes_performed=False,
                              installed_release_sha=None,deploy_acceptance='NOT_ESTABLISHED'),sort_keys=True))
        return 1
    finally:signal.setitimer(signal.ITIMER_REAL,0)


if __name__=='__main__':raise SystemExit(main())
