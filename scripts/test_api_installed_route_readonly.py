#!/usr/bin/env python3
"""Fixed TEST disk/static-route observation. No application execution or request.

The reviewed constant diagnostic travels through SSH stdin; no remote code file
is installed. Disk fingerprints and literal directives do not prove an installed
release, active Apache configuration, PHP version, API302 cause or DB isolation.
File reads and SSH/sudo/systemd audit/OS bookkeeping may occur.
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
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _bounded, strict_json
from hostinger_preflight import policy_ready
from test_api_readonly_access import TestPolicyApi, PIN_SHA256, private_file, _at_stage, _safe_reason, _python_version

REPO = 'JSMJapan/jsm-release-control'
GH_REPO = '/repos/' + REPO
GH_ENV = GH_REPO + '/environments/test-api-readonly-access'
CODE_FILES = (
    ('lot', '/srv/jsm/app/backend/api/modules/v1/controllers/LotController.php', 14918,
     'dc50c9e035e9e1b89b185488e6277bd712194f56b9619c1b8599cf62c471aee1'),
    ('shopping_detail', '/srv/jsm/app/backend/api/modules/v1/controllers/ShoppingDetailController.php', 18815,
     '3554c01a60c3935aadc7054c727795dc0ce00fdb7c0a7733727cb67aee0aac8b'),
    ('public_seo_cache', '/srv/jsm/app/backend/common/services/PublicSeoSnapshotCache.php', 17532,
     '6b815aa35f5a136ba3c0bf3ae8d080fdd53dbb939a8baa12da82972e96d7a96a'),
    ('snapshot_policy', '/srv/jsm/app/backend/common/services/ShopSnapshotPolicy.php', 3850,
     '3618a711a3875283f81895f3e0e194cafc55e7b9ad4a70d7d44915ae6dcebb66'),
    ('snapshot_store', '/srv/jsm/app/backend/common/services/ShopSnapshotStore.php', 4653,
     '7aedffdfa4cba7cb9017df9ccfa4f20f400292a4c435ca3998c8c43d75a6c173'),
    ('amazon_snapshots', '/srv/jsm/app/backend/common/services/shops/Amazon/AmazonSnapshots.php', 6097,
     '0ce4e8a1ab7dbb634d52172f94e55693ac9db86d0505a9ebbd8c7f0f4b96b5c0'))
SITE_FILES = (('test_https', '/etc/apache2/sites-available/jsm-sandbox-443.conf'),
              ('test_http', '/etc/apache2/sites-available/jsm-sandbox-80.conf'),
              ('sslip_https', '/etc/apache2/sites-available/jsm-sandbox-sslip-443.conf'))
UNITS = ('jsm-front.service', 'apache2.service', 'php7.4-fpm.service', 'php8.5-fpm.service')
FLAGS = ('test_server_name_literal_present', 'api_alias_literal_present', 'api_proxy_exclusion_literal_present',
         'loopback_front_proxy_literal_present', 'rewrite_rule_present', 'include_or_conditional_present')

# Fixed diagnostic definitions; tests execute these same bytes on synthetic
# owned fixtures. This library has no entry point, input parser or application import.
_ROOT_LIBRARY = r'''
import errno,hashlib,json,os,re,selectors,signal,stat,subprocess,time
class Deadline(Exception): pass
def _check(deadline):
    if time.monotonic()>=deadline: raise Deadline()
def _stamp(row):
    return tuple(getattr(row,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def _empty(state):
    return dict(present=None,regular=None,mode=None,read_state=state,raw=None)
def _dir_stamp(row):
    return row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid
def _parents(path,deadline):
    fds=[]
    try:
        if not path.startswith('/') or any(part in ('','.','..') for part in path[1:].split('/')): raise ValueError()
        parts=path[1:].split('/')
        _check(deadline)
        fds.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
        for part in parts[:-1]:
            _check(deadline)
            fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
        return fds,parts[-1]
    except BaseException:
        for fd in reversed(fds): os.close(fd)
        raise
def _binding(path,deadline,directories,expected):
    fds=[]
    try:
        fds,name=_parents(path,deadline)
        if directories!=[_dir_stamp(os.fstat(fd)) for fd in fds]: return False
        try: current=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        except FileNotFoundError: return expected is None
        return expected is not None and _stamp(current)==_stamp(expected)
    except OSError: return False
    finally:
        for fd in reversed(fds): os.close(fd)
def _read_fixed(path,deadline):
    fds=[]; leaf=None
    try:
        fds,name=_parents(path,deadline)
        directories=[_dir_stamp(os.fstat(fd)) for fd in fds]
        _check(deadline)
        try: before=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        except FileNotFoundError:
            return (dict(present=False,regular=None,mode=None,read_state='absent',raw=None)
                    if _binding(path,deadline,directories,None) else _empty('unsafe_path'))
        if not stat.S_ISREG(before.st_mode):
            return (dict(present=True,regular=False,mode=None,read_state='not_regular',raw=None)
                    if _binding(path,deadline,directories,before) else _empty('unsafe_path'))
        if before.st_nlink!=1: return _empty('unsafe_path')
        result=dict(present=True,regular=True,mode=stat.S_IMODE(before.st_mode),read_state='too_large',raw=None)
        if before.st_size>65536:
            return result if _binding(path,deadline,directories,before) else dict(result,read_state='changed')
        leaf=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1])
        if _stamp(before)!=_stamp(os.fstat(leaf)): return dict(result,read_state='changed')
        raw=bytearray()
        while True:
            _check(deadline)
            part=os.read(leaf,min(4096,65537-len(raw)))
            raw.extend(part)
            if len(raw)>65536: return dict(result,read_state='too_large')
            if not part: break
        after=os.fstat(leaf)
        if (len(raw)!=before.st_size or _stamp(before)!=_stamp(after)
            or not _binding(path,deadline,directories,before)): return dict(result,read_state='changed')
        return dict(result,read_state='ok',raw=bytes(raw))
    except Deadline: return _empty('deadline')
    except OSError as error:
        return _empty('unsafe_path' if error.errno in (errno.ELOOP,errno.ENOTDIR,errno.ENOENT) else 'unreadable')
    except ValueError: return _empty('unsafe_path')
    finally:
        if leaf is not None: os.close(leaf)
        for fd in reversed(fds): os.close(fd)
def _tokens(line):
    result=[]; token=''; quote=None; closed=False; escaped=False
    for char in line:
        if escaped:
            # Preserve ordinary regex escapes as opaque token bytes. Escaped
            # lexical delimiters/continuations are outside this supported subset.
            if char in "\\\"'# \t" or ord(char)<32 or ord(char)>126: raise ValueError()
            token+=char; escaped=False
        elif quote:
            if char==quote: quote=None; closed=True
            elif char=='\\': token+=char; escaped=True
            elif ord(char)<32: raise ValueError()
            else: token+=char
        elif char=='#':
            if token or result or closed: raise ValueError()
            break
        elif char in ' \t':
            if token or closed: result.append(token); token=''; closed=False
        elif char in "\"'":
            if token or closed: raise ValueError()
            quote=char
        elif closed and char=='>' and line.lstrip().startswith('<'):
            token+=char; closed=False
        else:
            if closed or ord(char)<32 or ord(char)>126: raise ValueError()
            token+=char
            if char=='\\': escaped=True
        if len(token)>512 or len(result)>32: raise ValueError()
    if quote or escaped: raise ValueError()
    if token or closed: result.append(token)
    return result
def _parse_site(raw):
    unknown={name:None for name in FLAGS}
    try:
        text=raw.decode('utf-8')
        if len(raw)>65536 or '\x00' in text: raise ValueError()
        flags={name:False for name in FLAGS}; stack=[]
        containers={'virtualhost','directory','directorymatch','files','filesmatch','location','locationmatch',
                    'proxy','proxymatch','limit','limitexcept','ifmodule','ifdefine','if','elseif','else','macro'}
        for line in text.split('\n'):
            if line.endswith('\r'): line=line[:-1]
            if len(line.encode('utf-8'))>4096 or line.rstrip(' \t').endswith('\\'): raise ValueError()
            tokens=_tokens(line)
            if not tokens: continue
            if tokens[0].startswith('<'):
                tag=' '.join(tokens)
                if not tokens[-1].endswith('>') or tag.count('<')!=1 or tag.count('>')!=1: raise ValueError()
                closing=tokens[0].startswith('</')
                name=tokens[0][2 if closing else 1:].rstrip('>').lower()
                if name not in containers: raise ValueError()
                if closing:
                    if len(tokens)!=1 or not stack or stack.pop()!=name: raise ValueError()
                else:
                    args=tokens[1:]
                    if args:
                        args[-1]=args[-1][:-1]
                        if not args[-1]: args.pop()
                    if (name=='else' and args) or (name!='else' and not args): raise ValueError()
                    stack.append(name)
                    if name in ('if','elseif','else','ifmodule','ifdefine','macro'): flags['include_or_conditional_present']=True
                continue
            name=tokens[0].lower(); args=tokens[1:]
            if not re.fullmatch('[a-z][a-z0-9]*',name): raise ValueError()
            if name in ('servername','serveralias'):
                if not args or (name=='servername' and len(args)!=1): raise ValueError()
                if 'develop.jsmjapan.com' in args: flags['test_server_name_literal_present']=True
            elif name=='alias':
                if len(args)!=2: raise ValueError()
                if args==['/api','/srv/jsm/app/backend/api/web']: flags['api_alias_literal_present']=True
            elif name=='proxypass':
                if len(args)<2: raise ValueError()
                if len(args)==2 and args[0] in ('/api','/api/') and args[1]=='!': flags['api_proxy_exclusion_literal_present']=True
                if args==['/','http://127.0.0.1:3000/']: flags['loopback_front_proxy_literal_present']=True
            elif name=='rewriterule':
                if len(args) not in (2,3): raise ValueError()
                flags['rewrite_rule_present']=True
            elif name in ('include','includeoptional','define','use'):
                if not args: raise ValueError()
                flags['include_or_conditional_present']=True
        if stack: raise ValueError()
        return 'ok',flags
    except (ValueError,UnicodeError): return 'unsupported',unknown
def _parse_services(raw):
    try:
        if type(raw) is not bytes or not 0<len(raw)<=4096: return None
        text=raw.decode('ascii'); records={}
        if any(ord(char)<32 and char!='\n' for char in text): return None
        for block in text.strip().split('\n\n'):
            row={}
            for line in block.splitlines():
                key,value=line.split('=',1)
                if key not in ('Id','LoadState','ActiveState','SubState') or key in row or len(value)>128: return None
                row[key]=value
            if set(row)!={'Id','LoadState','ActiveState','SubState'} or row['Id'] not in UNITS or row['Id'] in records: return None
            records[row['Id']]=dict(id=row['Id'],load_state=row['LoadState'] if row['LoadState'] in ('loaded','not-found') else 'unknown',
                active_state=row['ActiveState'] if row['ActiveState'] in ('active','inactive','failed') else 'unknown',
                sub_state=row['SubState'] if row['SubState'] in ('running','dead','exited','failed') else 'unknown')
        return [records[name] for name in UNITS] if set(records)==set(UNITS) else None
    except (ValueError,UnicodeError): return None
def _unknown_services():
    return [dict(id=name,load_state='unknown',active_state='unknown',sub_state='unknown') for name in UNITS]
def _services(deadline):
    process=None
    try:
        # The independent root-owned timeout bounds its own group even if this
        # root diagnostic dies. Never kill that wrapper before its .9s bound.
        _check(deadline-1.1)
        end=time.monotonic()+1
        process=subprocess.Popen(['/usr/bin/timeout','--signal=TERM','--kill-after=0.2','0.7',
            '/usr/bin/systemctl','--no-pager','show','--property=Id,LoadState,ActiveState,SubState',*UNITS],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'})
        output=bytearray(); complete=False
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout,selectors.EVENT_READ)
            while time.monotonic()<end:
                if process.poll() is not None:
                    try: os.killpg(process.pid,signal.SIGKILL)
                    except OSError: pass
                for key,_ in ready.select(min(.05,max(0,end-time.monotonic()))):
                    part=os.read(key.fileobj.fileno(),min(4096,4097-len(output)))
                    output.extend(part)
                    if len(output)>4096: raise ValueError()
                    if not part: complete=True; break
                if complete: break
        if not complete or process.wait(timeout=max(.001,end-time.monotonic()))!=0: raise ValueError()
        records=_parse_services(bytes(output))
        return records if records is not None else _unknown_services()
    except (OSError,ValueError,Deadline,subprocess.TimeoutExpired): return _unknown_services()
    finally:
        if process is not None:
            # Give the fixed timeout its independent deadline before group
            # cleanup; killing a still-running wrapper early would remove its timer.
            remaining=max(0,end-time.monotonic())
            if remaining:
                try: process.wait(timeout=remaining)
                except subprocess.TimeoutExpired: pass
            try: os.killpg(process.pid,signal.SIGKILL)
            except OSError: pass
            if process.poll() is None:
                process.kill()
                try: process.wait(timeout=.05)
                except subprocess.TimeoutExpired: pass
            process.stdout.close()
def _observe(nonce):
    deadline=time.monotonic()+3
    code=[]; sites=[]; partial=False
    for name,path,size,digest in CODE_FILES:
        row=_read_fixed(path,deadline); raw=row.pop('raw')
        hashed=hashlib.sha256(raw).hexdigest() if raw is not None else None
        code.append(dict(row,id=name,sha256=hashed,matches_reviewed=(hashed==digest and len(raw)==size) if raw is not None else None))
        partial=partial or row['read_state'] not in ('ok','absent','not_regular')
    for name,path in SITE_FILES:
        row=_read_fixed(path,deadline); raw=row.pop('raw'); row.pop('mode')
        parsed,flags=_parse_site(raw) if raw is not None else ('unavailable',{name:None for name in FLAGS})
        sites.append(dict(row,id=name,parse_state=parsed,**flags))
        partial=partial or row['read_state'] not in ('ok','absent','not_regular') or parsed=='unsupported'
    services=_services(deadline)
    partial=partial or any('unknown' in (row['load_state'],row['active_state'],row['sub_state']) for row in services)
    return dict(version='jsm-test-installed-route-v1',nonce=nonce,euid=os.geteuid(),code_files=code,sites=sites,services=services,
                observation_state='PARTIAL' if partial else 'OBSERVED')
'''


def need(condition, reason):
    if not condition: raise Refused(reason)


def context_ready(env):
    fixed = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
        GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
        GITHUB_WORKFLOW_REF=REPO+'/.github/workflows/test-api-installed-route-readonly.yml@refs/heads/main')
    need(all(env.get(key)==value for key,value in fixed.items()) and type(env.get('GITHUB_SHA')) is str
        and re.fullmatch('[0-9a-f]{40}',env['GITHUB_SHA']) and env.get('GITHUB_WORKFLOW_SHA')==env['GITHUB_SHA']
        and type(env.get('GITHUB_RUN_ID')) is str and re.fullmatch('[0-9]{1,15}',env['GITHUB_RUN_ID']),
        'OWNER_MANUAL_MAIN_TEST_WORKFLOW_REQUIRED')


def remote_program(nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'NONCE_REQUIRED')
    child = ('CODE_FILES='+repr(CODE_FILES)+'\nSITE_FILES='+repr(SITE_FILES)+'\nUNITS='+repr(UNITS)+'\nFLAGS='+repr(FLAGS)+'\n'
        + _ROOT_LIBRARY + '\nprint(json.dumps(_observe('+repr(nonce)+'),separators=(",",":"),sort_keys=True))\n')
    # OS identity is independent from child data. A missing/refused/malformed
    # child remains unknown, not a false root identity.
    outer = r'''
import json,os,pwd,selectors,signal,subprocess,time
nonce=@NONCE@
euid=os.geteuid(); principal=pwd.getpwuid(euid).pw_name
child=None; process=None; deadline=time.monotonic()+5
def pairs(rows):
    out={}
    for key,value in rows:
        if key in out: raise ValueError()
        out[key]=value
    return out
def invalid(value): raise ValueError()
try:
    process=subprocess.Popen(['/usr/bin/sudo','-n','/usr/bin/timeout','--signal=TERM','--kill-after=1','4',
        '/usr/bin/python3','-I','-B','-S','-c',@CHILD@],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,start_new_session=True,env={'PATH':'/usr/bin:/bin','LANG':'C'})
    raw=bytearray(); eof=False
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout,selectors.EVENT_READ)
        while time.monotonic()<deadline-.1:
            if process.poll() is not None:
                try: os.killpg(process.pid,signal.SIGKILL)
                except OSError: pass
            for key,_ in ready.select(min(.1,max(0,deadline-time.monotonic()-.1))):
                part=os.read(key.fileobj.fileno(),min(3072,3073-len(raw))); raw.extend(part)
                if len(raw)>3072: raise ValueError()
                if not part: eof=True; break
            if eof: break
    remaining=deadline-time.monotonic()-.1
    if not eof or remaining<=0 or process.wait(timeout=remaining)!=0: raise ValueError()
    child=json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=invalid)
except Exception: child=None
finally:
    if process is not None:
        try: os.killpg(process.pid,signal.SIGKILL)
        except OSError: pass
        if process.poll() is None:
            remaining=deadline-time.monotonic()
            if remaining>0:
                try: process.wait(timeout=remaining)
                except subprocess.TimeoutExpired: pass
        process.stdout.close()
print(json.dumps(dict(version='jsm-test-installed-route-outer-v1',nonce=nonce,principal=principal,euid=euid,
    root_diagnostic=child),separators=(',',':'),sort_keys=True))
'''
    return outer.replace('@NONCE@',repr(nonce)).replace('@CHILD@',repr(child)).encode('ascii')


def _identity(value, version, nonce):
    return (type(value) is dict and value.get('version')==version and value.get('nonce')==nonce
            and type(value.get('euid')) is int and 0<=value['euid']<=4294967295)


def _metadata(row, *, mode):
    state=row.get('read_state')
    if state not in ('ok','absent','not_regular','unsafe_path','too_large','changed','unreadable','deadline'): return False
    present,regular=row.get('present'),row.get('regular')
    if state=='absent': valid=present is False and regular is None
    elif state=='not_regular': valid=present is True and regular is False
    elif state in ('ok','too_large','changed'): valid=present is True and regular is True
    else: valid=present is None and regular is None
    if mode:
        value=row.get('mode')
        valid=valid and ((type(value) is int and 0<=value<=4095) if regular is True else value is None)
    return valid


def _code_record(row, reference):
    if type(row) is not dict or set(row)!={'id','present','regular','mode','read_state','sha256','matches_reviewed'}: return None
    if not _metadata(row,mode=True): return None
    digest,matched=row['sha256'],row['matches_reviewed']
    if row['read_state']=='ok':
        if (type(digest) is not str or not re.fullmatch('[0-9a-f]{64}',digest) or type(matched) is not bool
                or matched != (digest==reference[3])): return None
    elif digest is not None or matched is not None: return None
    return dict(row)


def _site_record(row, reference):
    if type(row) is not dict or set(row)!={'id','present','regular','read_state','parse_state'}|set(FLAGS): return None
    if not _metadata(row,mode=False): return None
    parsed=row['parse_state']
    if parsed=='ok': valid=row['read_state']=='ok' and all(type(row[name]) is bool for name in FLAGS)
    elif parsed=='unsupported': valid=row['read_state']=='ok' and all(row[name] is None for name in FLAGS)
    elif parsed=='unavailable': valid=row['read_state']!='ok' and all(row[name] is None for name in FLAGS)
    else: valid=False
    return dict(row) if valid else None


def _service_record(row, reference):
    if type(row) is not dict or set(row)!={'id','load_state','active_state','sub_state'}: return None
    if (row['load_state'] not in ('loaded','not-found','unknown') or row['active_state'] not in ('active','inactive','failed','unknown')
            or row['sub_state'] not in ('running','dead','exited','failed','unknown')): return None
    return dict(row)


def _records(rows, references, validator):
    names=[row if type(row) is str else row[0] for row in references]
    if type(rows) is not list or len(rows)!=len(names): return [None]*len(names)
    if any(type(row) is not dict or type(row.get('id')) is not str for row in rows): return [None]*len(names)
    mapping={row['id']:row for row in rows}
    if len(mapping)!=len(names) or set(mapping)!=set(names): return [None]*len(names)
    return [validator(mapping[name],reference) for name,reference in zip(names,references)]


def project_remote(raw, nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'NONCE_REQUIRED')
    try:
        need(type(raw) is bytes and 0<len(raw)<=4096,'REMOTE_IDENTITY_SCHEMA_REJECTED')
        outer=strict_json(raw.decode('ascii'))
        need(_identity(outer,'jsm-test-installed-route-outer-v1',nonce)
             and set(outer)=={'version','nonce','principal','euid','root_diagnostic'}
             and outer['principal']=='marinagurina','REMOTE_IDENTITY_SCHEMA_REJECTED')
    except Exception: raise Refused('REMOTE_IDENTITY_SCHEMA_REJECTED') from None
    result=dict(ssh_identity=True,ssh_principal='marinagurina',ssh_euid=outer['euid'],sudo_root_identity=None,
                code_files=[None]*6,sites=[None]*3,services=[None]*4,observation_state='PARTIAL')
    child=outer['root_diagnostic']
    if not (_identity(child,'jsm-test-installed-route-v1',nonce)
            and set(child)=={'version','nonce','euid','code_files','sites','services','observation_state'}): return result
    result['sudo_root_identity']=child['euid']==0
    if child['euid']!=0: return result
    code=_records(child['code_files'],CODE_FILES,_code_record)
    sites=_records(child['sites'],SITE_FILES,_site_record)
    services=_records(child['services'],UNITS,_service_record)
    result.update(code_files=code,sites=sites,services=services)
    complete=(all(row is not None and row['read_state'] in ('ok','absent','not_regular') for row in code)
        and all(row is not None and row['read_state'] in ('ok','absent','not_regular') and row['parse_state']!='unsupported' for row in sites)
        and all(row is not None and 'unknown' not in (row['load_state'],row['active_state'],row['sub_state']) for row in services))
    if complete and child['observation_state']=='OBSERVED': result['observation_state']='OBSERVED'
    return result


def collect(api, env):
    deadline=time.monotonic()+60
    context_ready(env)
    repo=_at_stage('policy_repository',api.get_json,GH_REPO)
    environment=_at_stage('policy_environment',api.get_json,GH_ENV)
    branches=_at_stage('policy_branches',api.get_json,GH_ENV+'/deployment-branch-policies')
    try:
        policy_ready(repo,environment,branches)
        reviewer=[row for row in environment['protection_rules'] if row.get('type')=='required_reviewers'][0]['reviewers'][0]['reviewer']
        need(environment.get('name')=='test-api-readonly-access' and type(reviewer.get('id')) is int
             and reviewer['id']==327623967 and type(branches.get('total_count')) is int and branches['total_count']==1,
             'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED')
    except Exception: raise Refused('PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED') from None
    key,known=env.get('TEST_API_ADMIN_SSH_KEY'),env.get('TEST_API_KNOWN_HOSTS')
    need(type(key) is str and 0<len(key)<=16384 and '\x00' not in key,'TEST_SSH_KEY_NOT_CONFIGURED')
    need(type(known) is str and len(known)<=16384 and hashlib.sha256(known.encode()).hexdigest()==PIN_SHA256,'EXACT_TEST_HOST_PIN_REQUIRED')
    nonce=secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='jsm-test-installed-ro-') as folder:
        os.chmod(folder,0o700); identity,hosts=Path(folder)/'identity',Path(folder)/'known_hosts'
        private_file(identity,key.replace('\r\n','\n').rstrip('\n')+'\n'); private_file(hosts,known)
        command=['/usr/bin/ssh','-F','/dev/null','-T','-i',str(identity),'-p','22',
            '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes',
            '-o','BatchMode=yes','-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
            '-o','KbdInteractiveAuthentication=no','-o','ClearAllForwardings=yes',
            '-o','UserKnownHostsFile='+str(hosts),'-o','GlobalKnownHostsFile=/dev/null',
            '-o','ConnectTimeout=7','-o','ConnectionAttempts=1','-o','ServerAliveInterval=3',
            '-o','ServerAliveCountMax=2','-o','LogLevel=ERROR',
            'marinagurina@34.104.157.63','/usr/bin/python3','-I','-B','-S','-']
        budget=min(15,deadline-time.monotonic()-2); need(budget>0,'OVERALL_DEADLINE')
        code,raw=_at_stage('ssh_transport',_bounded,command,data=remote_program(nonce),limit=4096,timeout=budget)
        need(code==0,'SSH_TRANSPORT_NOT_CONFIRMED')
        observed=_at_stage('remote_identity',project_remote,raw,nonce)
    complete=observed['observation_state']=='OBSERVED'
    return dict(observed,status='TEST_INSTALLED_ROUTE_OBSERVED' if complete else 'PARTIAL',
        reason='FIXED_OBSERVATION_COMPLETE' if complete else 'FIXED_OBSERVATION_INCOMPLETE',failure_stage=None if complete else 'remote_identity',
        resource='gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713',ip='34.104.157.63',ssh_port=22,
        known_hosts_sha256=PIN_SHA256,reviewed_candidate_sha='779227312a9b5faa20ca9567f97909ae6a8f32fc',
        source_sha=env['GITHUB_SHA'],workflow_run_url='https://github.com/'+REPO+'/actions/runs/'+env['GITHUB_RUN_ID'],
        installed_release_sha=None,active_include_binding='NOT_ESTABLISHED',api302_cause='UNKNOWN',api_health='NOT_TESTED',
        db_isolation='NOT_ESTABLISHED',provider_requests='NOT_PERFORMED',application_execution='NOT_PERFORMED',deploy_acceptance='NOT_ESTABLISHED')


def main():
    def expired(*_): raise Refused('OVERALL_DEADLINE')
    try:
        need(len(sys.argv)==1,'NO_ARGUMENTS_OR_INPUTS_ACCEPTED')
        signal.signal(signal.SIGALRM,expired); signal.setitimer(signal.ITIMER_REAL,60)
        result=collect(TestPolicyApi(),os.environ)
        result.update(verified_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),python_version=_python_version())
        print(json.dumps(result,separators=(',',':'),sort_keys=True))
        return 0 if result['status']=='TEST_INSTALLED_ROUTE_OBSERVED' else 1
    except Exception as error:
        reason=_safe_reason(error)
        stage=getattr(error,'failure_stage','unknown')
        stage=stage if stage in ('policy_repository','policy_environment','policy_branches','ssh_transport','remote_identity') else 'unknown'
        print(json.dumps(dict(status='BLOCKED',reason=reason,failure_stage=stage,python_version=_python_version(),
            ssh_identity=None,sudo_root_identity=None,installed_release_sha=None,active_include_binding='NOT_ESTABLISHED',
            api302_cause='UNKNOWN',api_health='NOT_TESTED',db_isolation='NOT_ESTABLISHED',provider_requests='NOT_PERFORMED',
            application_execution='NOT_PERFORMED',deploy_acceptance='NOT_ESTABLISHED'),separators=(',',':'),sort_keys=True))
        return 1
    finally: signal.setitimer(signal.ITIMER_REAL,0)


if __name__=='__main__': raise SystemExit(main())
