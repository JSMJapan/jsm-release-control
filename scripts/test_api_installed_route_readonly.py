#!/usr/bin/env python3
"""Fixed TEST disk/static-route/readiness observation. No application execution or request.

The reviewed constant diagnostic travels through SSH stdin; no remote code file
is installed. Disk fingerprints and literal directives do not prove an installed
release, active Apache configuration, PHP version, API302 cause or DB isolation.
Fixed application configs can contain credentials: private bounded reads expose
only selected nonsecret literal predicates, never contents or whole-config hashes.
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
# Fixed 8b07cd006859650b35bffee3eda2c5ee07919f1b source scope: 19 SEO + 6 finance files.
# Frontend root/mapping: storefront infra/sandbox/build/frontend_996_host.py
# (FRONT and WorkingDirectory guard), frontend_1005_install.py (FRONT / path).
# These source fingerprints do not establish the running bundle or active release.
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
     '0ce4e8a1ab7dbb634d52172f94e55693ac9db86d0505a9ebbd8c7f0f4b96b5c0'),
    ('seo_article_config', '/srv/jsm/app/frontend/config/articleSeo.js', 14775,
     '53f21b3177ed7ecb72ee1fc9917a88b271b8d69decc4ace1ae655087064acd26'),
    ('seo_catalog_config', '/srv/jsm/app/frontend/config/catalogSeo.js', 10698,
     'c482d771b418872a01f2591befaf7651b004e743e03c8ff9747f18c4ceaadc78'),
    ('seo_public_data_config', '/srv/jsm/app/frontend/config/publicDataSeo.js', 9478,
     '2d4d8ecb4ae131a8970776119002becf00eae5c0d4b8f1dc1d88d825dd743096'),
    ('seo_server', '/srv/jsm/app/frontend/config/server.js', 14304,
     'b95096ba57ba16090b08e01cf2ae7be30759fabd08d099677191a3a44f79c43d'),
    ('seo_app', '/srv/jsm/app/frontend/src/App.tsx', 4931,
     'b4f53741a6a127673e80fa6bbaea461ebce047da8f8f1096f8c16a43bc7c630f'),
    ('seo_blog_helper', '/srv/jsm/app/frontend/src/helpers/blogArticleSeo.js', 5611,
     '0b5fb27feecc1311eb89f29b35636a2f3765a49ea49b9fa366e0beff607247ed'),
    ('seo_public_routes', '/srv/jsm/app/frontend/src/helpers/publicSeoRoutes.js', 5262,
     'b0c0266de29204ed0645d5aedb31632e5d222e085b5a5ec3edb5a6fdb1bb9d99'),
    ('seo_blog_article', '/srv/jsm/app/frontend/src/pages/MainFlow/BlogArticle/index.tsx', 7734,
     '3349f62e1bbd00c4e9fbbeba280f635efcf185a9e12504f2459c29a70206486c'),
    ('seo_catalog_meta', '/srv/jsm/app/frontend/src/pages/MainFlow/Catalog/components/Meta/index.tsx', 3234,
     'b17d8951b530159d3e107f00df6b6d887a6bae0d4bed1383eda32be04c7afb06'),
    ('seo_catalog', '/srv/jsm/app/frontend/src/pages/MainFlow/Catalog/index.tsx', 8736,
     '06e73efd1e67ac8320a35fe7769489e49095dc9c7d1deeab4fe778171d0183f5'),
    ('seo_shopping_product', '/srv/jsm/app/frontend/src/pages/MainFlow/Product/ShoppingProduct/index.tsx', 18684,
     '6fb072438cd9fc3fbc2def9776ca4c2ac2319ed450104cbf157db437ed5e7c99'),
    ('seo_product_actions', '/srv/jsm/app/frontend/src/redux/asyncActions/productPage.ts', 2448,
     '65123e884a589603b5ae2f40137cffb13fb828a06584c5135c66d07d8864c56f'),
    ('seo_common_service', '/srv/jsm/app/frontend/src/services/Common.ts', 5806,
     '6351a572a142e773489a376196e7c1458fbe7ab43da2feda9db8248323c3f8ef'),
    ('finance_bonus_controller', '/srv/jsm/app/backend/backend/controllers/BonusReportController.php', 7441,
     '2978800daa540f9b356d86ac4a59611e04ba55bd00ed94fb7ce13c40bca34b56'),
    ('finance_bonus_view', '/srv/jsm/app/backend/backend/views/bonus-report/index.php', 13084,
     'f4729560cf0c09e446312b7724dce8918023dec232ce355b1268871042d7b225'),
    ('finance_menu_translation', '/srv/jsm/app/backend/common/components/translateAdminMenuRu.php', 5839,
     '427ab6eedf3e127906e725fc3424dc68d161c14536218c752bb0d1393199d28f'),
    ('finance_admin_menu', '/srv/jsm/app/backend/common/helper/AdminMenuHelper.php', 25636,
     '06900cfe86ae01a7b112fb2393d6ece309482c2ca485eef3689a5e235927afe9'),
    ('finance_period_summary', '/srv/jsm/app/backend/common/helper/BonusPeriodSummary.php', 4762,
     '6cd3dd42e9c70927ebc156c981d3362071a306c9fe2708f86b5468d125fd58e8'),
    ('finance_bonus_report', '/srv/jsm/app/backend/common/helper/BonusReport.php', 16551,
     '18a66be58e71c9609d85c5e16ae90a2f13b24565b8dc83d486fd42e44cb62020'))
SITE_FILES = (('test_https', '/etc/apache2/sites-available/jsm-sandbox-443.conf'),
              ('test_http', '/etc/apache2/sites-available/jsm-sandbox-80.conf'),
              ('sslip_https', '/etc/apache2/sites-available/jsm-sandbox-sslip-443.conf'))
UNITS = ('jsm-front.service', 'apache2.service', 'php7.4-fpm.service', 'php8.5-fpm.service')
FLAGS = ('test_server_name_literal_present', 'api_alias_literal_present', 'api_proxy_exclusion_literal_present',
         'loopback_front_proxy_literal_present', 'rewrite_rule_present', 'include_or_conditional_present')

CONFIG_FILES = (('dotenv', '/srv/jsm/app/backend/.env', 'dotenv'),
    ('common_local', '/srv/jsm/app/backend/common/config/main-local.php', 'php'),
    ('params_local', '/srv/jsm/app/backend/common/config/params-local.php', 'php'),
    ('console_local', '/srv/jsm/app/backend/console/config/main-local.php', 'php'),
    ('api_local', '/srv/jsm/app/backend/api/config/main-local.php', 'php'),
    ('common_main', '/srv/jsm/app/backend/common/config/main.php', 'php'),
    ('api_main', '/srv/jsm/app/backend/api/config/main.php', 'php'))
BOOTSTRAP_FILES = (('api_entry', '/srv/jsm/app/backend/api/web/index.php'),
    ('common_bootstrap', '/srv/jsm/app/backend/common/config/bootstrap.php'))
DEPLOYER = ('deployer', '/usr/local/sbin/jsm-sandbox-deploy', '4b0815ff755c6b29165a8102f2bc47c2a7dd49a567b367b2c55637522996a6cc')
CURRENT = '/srv/jsm/deploy/current.json'
DEPLOY_LOCK = '/run/jsm-sandbox-deploy.lock'

# Fixed diagnostic definitions; tests execute these same bytes on synthetic
# owned fixtures. This library has no entry point, input parser or application import.
_ROOT_LIBRARY = r'''
import datetime,errno,hashlib,json,os,re,selectors,signal,stat,subprocess,time
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
        return dict(result,read_state='ok',raw=bytes(raw),identity=_stamp(before))
    except Deadline: return _empty('deadline')
    except OSError as error:
        return _empty('unsafe_path' if error.errno in (errno.ELOOP,errno.ENOTDIR,errno.ENOENT) else 'unreadable')
    except ValueError: return _empty('unsafe_path')
    finally:
        if leaf is not None: os.close(leaf)
        for fd in reversed(fds): os.close(fd)
def _metadata_fixed(path,deadline):
    fds=[]
    try:
        fds,name=_parents(path,deadline); directories=[_dir_stamp(os.fstat(fd)) for fd in fds]
        _check(deadline)
        try: before=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        except FileNotFoundError:
            row=dict(present=False,regular=None,mode=None,read_state='absent')
            return row if _binding(path,deadline,directories,None) else {key:value for key,value in _empty('unsafe_path').items() if key!='raw'}
        regular=stat.S_ISREG(before.st_mode)
        row=dict(present=True,regular=regular,mode=stat.S_IMODE(before.st_mode) if regular else None,
                 read_state='ok' if regular else 'not_regular')
        if not _binding(path,deadline,directories,before): raise ValueError()
        return row
    except Deadline: state='deadline'
    except OSError as error: state='unsafe_path' if error.errno in (errno.ELOOP,errno.ENOTDIR,errno.ENOENT) else 'unreadable'
    except ValueError: state='unsafe_path'
    finally:
        for fd in reversed(fds): os.close(fd)
    return dict(present=None,regular=None,mode=None,read_state=state)
def _pairs(rows):
    out={}
    for key,value in rows:
        if key in out: raise ValueError()
        out[key]=value
    return out
def _invalid(value): raise ValueError()
def _timestamp(value):
    if type(value) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})',value): return None
    try:
        stamp=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
        return stamp.astimezone(datetime.timezone.utc).isoformat(timespec='microseconds' if '.' in value else 'seconds').replace('+00:00','Z')
    except (ValueError,OverflowError): return None
def _deployment_record(row):
    result=dict(read_state=row['read_state'],sha=None,deployed_at=None)
    if row['raw'] is None: return result
    try:
        value=json.loads(row['raw'].decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_invalid)
        if type(value) is not dict: return result
        sha=value.get('sha')
        if type(sha) is str and re.fullmatch('[0-9a-f]{40}',sha): result['sha']=sha
        result['deployed_at']=_timestamp(value.get('deployed_at'))
    except (ValueError,UnicodeError,RecursionError): pass
    return result
def _config_unknown(state='unsupported'):
    return dict(profile_parse=state,db_loopback_literal=None,db_test_namespace_literal=None,
        db_target_descriptor_sha256=None,cache_filecache_literal=None,mail_file_transport_literal=None,indirection_or_override='UNKNOWN')
def _dsn(value):
    if type(value) is not str or not value.startswith('mysql:') or len(value)>512: return None
    parts={}
    for item in value[6:].split(';'):
        if item.count('=')!=1: return None
        key,text=item.split('=')
        if key not in ('host','dbname') or key in parts or not text: return None
        parts[key]=text
    return (parts['host'],parts['dbname']) if set(parts)=={'host','dbname'} else None
def _db_facts(pair):
    if pair is None: return {}
    host,name=pair
    if (type(host) is not str or type(name) is not str or not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}',host)
            or not re.fullmatch('[A-Za-z0-9_]{1,128}',name)): return {}
    loopback=host in ('localhost','127.0.0.1','::1')
    namespace=len(name)<=64 and re.fullmatch('(?:jsm_)?(?:test|sandbox)(?:_[a-z0-9]+)*',name) is not None
    descriptor=None
    if loopback and namespace:
        descriptor=hashlib.sha256(json.dumps(dict(host=host,db_name=name),sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
    return dict(db_loopback_literal=loopback,db_test_namespace_literal=namespace,db_target_descriptor_sha256=descriptor)
def _dotenv(text):
    selected={}; seen=set()
    for line in text.split('\n'):
        if line.endswith('\r'): line=line[:-1]
        if (len(line)>4096 or any(ord(c)<32 and c!='\t' for c in line)
                or line.rstrip(' \t').endswith('\\')): raise ValueError()
        line=line.strip(' \t')
        if not line or line.startswith('#'): continue
        match=re.match(r'([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*',line)
        if not match: raise ValueError()
        key=match[1]
        if key in seen: raise ValueError()
        seen.add(key); value=line[match.end():]
        if value.startswith(('"',"'")):
            quote=value[0]; out=''; pos=1
            while pos<len(value) and value[pos]!=quote:
                char=value[pos]
                if char in ('\\','$','`') or ord(char)<32: raise ValueError()
                out+=char; pos+=1
            if pos>=len(value): raise ValueError()
            tail=value[pos+1:]
            if tail and not re.fullmatch(r'[ \t]+(?:#.*)?',tail): raise ValueError()
            value=out
        else:
            value=re.split(r'[ \t]+#',value,1)[0].rstrip(' \t')
            if any(c in value for c in ('\\','$','`','"',"'",'#')) or any(c.isspace() for c in value): raise ValueError()
        if key in ('DB_DSN','DB_HOST','DB_NAME','DB_DATABASE'): selected[key]=value
    pairs=[]
    if 'DB_DSN' in selected:
        pair=_dsn(selected['DB_DSN'])
        if pair is None: return None
        pairs.append(pair)
    hosts=selected.get('DB_HOST'); names=[selected[key] for key in ('DB_NAME','DB_DATABASE') if key in selected]
    if hosts is not None or names:
        if hosts is None or not names or len(set(names))!=1: return None
        pairs.append((hosts,names[0]))
    return pairs[0] if pairs and all(pair==pairs[0] for pair in pairs) else None
def _php_tokens(text):
    # Tokenize boundaries, never execute PHP. Comments/quoted secrets cannot
    # create keys. Opaque expressions below are skipped, never interpreted.
    tokens=[]; pos=0; depth=0
    while pos<len(text):
        c=text[pos]
        if c in ' \t\r\n': pos+=1; continue
        if any(text.startswith(marker,pos) for marker in ('?>','#[','<<<')): raise ValueError()
        if text.startswith('//',pos) or c=='#':
            end=text.find('\n',pos); end=len(text) if end<0 else end
            if '?>' in text[pos:end]: raise ValueError()
            pos=end+1; continue
        if text.startswith('/*',pos):
            end=text.find('*/',pos+2)
            if end<0: raise ValueError()
            pos=end+2; continue
        if text.startswith('<?php',pos):
            if tokens or (pos+5<len(text) and text[pos+5] not in ' \t\r\n'): raise ValueError()
            tokens.append(('tag','<?php')); pos+=5
        elif c in "\"'":
            quote=c; pos+=1; value=''; dynamic=False
            while pos<len(text) and text[pos]!=quote:
                c=text[pos]
                if ord(c)<32 and c not in '\r\n\t': raise ValueError()
                # Interpolation has nested lexical boundaries outside this subset.
                if quote=='"' and c=='$': raise ValueError()
                if c=='\\':
                    pos+=1
                    if pos>=len(text): raise ValueError()
                    c=text[pos]
                    if c in ('\\',quote): value+=c
                    elif quote=="'": value+='\\'+c
                    else: dynamic=True; value+='\\'+c
                else: value+=c
                pos+=1
            if pos>=len(text): raise ValueError()
            tokens.append(('dynamic' if dynamic else 'string',value)); pos+=1
        elif c.isascii() and (c.isalpha() or c=='_'):
            end=pos+1
            while end<len(text) and text[end].isascii() and (text[end].isalnum() or text[end]=='_'): end+=1
            tokens.append(('word',text[pos:end])); pos=end
        elif c.isascii() and c.isdigit():
            end=pos+1
            while end<len(text) and text[end].isascii() and text[end].isdigit(): end+=1
            if end-pos>16: raise ValueError()
            tokens.append(('number',text[pos:end])); pos=end
        elif text.startswith('=>',pos): tokens.append(('punct','=>')); pos+=2
        elif c in '[](),;.:?\\$+-*/!<>=&|%':
            if c in '[(': depth+=1
            if c in '])': depth-=1
            if depth<0 or depth>16: raise ValueError()
            tokens.append(('punct',c)); pos+=1
        else: raise ValueError()
        if len(tokens)>8192: raise ValueError()
    if depth: raise ValueError()
    return tokens
def _php_selected(text):
    tokens=_php_tokens(text); pos=0
    if tokens and tokens[0][0]=='tag': pos+=1
    if tokens[pos:pos+1]!=[('word','return')]: raise ValueError()
    pos+=1
    targets={():{'components'},('components',):{'db','cache','mailer'},
             ('components','db'):{'dsn'},('components','cache'):{'class'},('components','mailer'):{'useFileTransport'}}
    facts={}
    def expression():
        nonlocal pos
        start=pos; stack=[]
        while pos<len(tokens):
            kind,value=tokens[pos]
            if kind=='punct' and not stack and value in (',',']',')',';'): break
            if kind=='punct' and value in ('[','('): stack.append(']' if value=='[' else ')')
            elif kind=='punct' and value in (']',')'):
                if not stack or stack.pop()!=value: raise ValueError()
            pos+=1
        if stack or pos==start: raise ValueError()
        return tokens[start:pos]
    def array(path):
        nonlocal pos
        if pos>=len(tokens): raise ValueError()
        if tokens[pos]==('punct','['): close=']'; pos+=1
        elif tokens[pos:pos+2]==[('word','array'),('punct','(')]: close=')'; pos+=2
        else:
            if not path: raise ValueError()
            expression(); return
        seen=set()
        while pos<len(tokens) and tokens[pos]!=('punct',close):
            if tokens[pos][0]!='string' or tokens[pos][1] in seen: raise ValueError()
            key=tokens[pos][1]; seen.add(key); pos+=1
            if tokens[pos:pos+1]!=[('punct','=>')]: raise ValueError()
            pos+=1; child=path+(key,)
            if key in targets.get(path,set()):
                if child in targets: array(child)
                else:
                    value=expression()
                    if len(value)==1:
                        kind,text=value[0]
                        if kind=='string': facts[child]=text
                        elif kind=='word' and text.lower() in ('true','false','null'):
                            facts[child]={'true':True,'false':False,'null':None}[text.lower()]
            else: expression()
            if pos<len(tokens) and tokens[pos]==('punct',','): pos+=1
            elif pos>=len(tokens) or tokens[pos]!=('punct',close): raise ValueError()
        if pos>=len(tokens): raise ValueError()
        pos+=1
    array(())
    if tokens[pos:]==[('punct',';')]: return facts
    raise ValueError()
def _parse_config(raw,profile):
    result=_config_unknown()
    try:
        if type(raw) is not bytes or len(raw)>65536: raise ValueError()
        text=raw.decode('utf-8')
        if '\x00' in text or '\r' in text.replace('\r\n',''): raise ValueError()
        if profile=='dotenv': pair=_dotenv(text)
        elif profile=='php':
            values=_php_selected(text); pair=_dsn(values.get(('components','db','dsn')))
            cache=values.get(('components','cache','class'))
            mail=values.get(('components','mailer','useFileTransport'))
            if type(cache) is str: result['cache_filecache_literal']=cache=='yii\\caching\\FileCache'
            if type(mail) is bool: result['mail_file_transport_literal']=mail
        else: raise ValueError()
        result.update(profile_parse='supported',**_db_facts(pair))
    except (ValueError,UnicodeError,RecursionError): pass
    return result
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
    begin=_read_fixed(CURRENT,deadline)
    code=[]; sites=[]; partial=False
    for name,path,size,digest in CODE_FILES:
        row=_read_fixed(path,deadline); raw=row.pop('raw'); row.pop('identity',None)
        hashed=hashlib.sha256(raw).hexdigest() if raw is not None else None
        code.append(dict(row,id=name,sha256=hashed,matches_reviewed=(hashed==digest and len(raw)==size) if raw is not None else None))
        partial=partial or row['read_state'] not in ('ok','absent','not_regular')
    for name,path in SITE_FILES:
        row=_read_fixed(path,deadline); raw=row.pop('raw'); row.pop('identity',None); row.pop('mode')
        parsed,flags=_parse_site(raw) if raw is not None else ('unavailable',{name:None for name in FLAGS})
        sites.append(dict(row,id=name,parse_state=parsed,**flags))
        partial=partial or row['read_state'] not in ('ok','absent','not_regular') or parsed=='unsupported'
    row=_read_fixed(DEPLOYER[1],deadline); raw=row.pop('raw'); row.pop('identity',None)
    hashed=hashlib.sha256(raw).hexdigest() if raw is not None else None
    deployer=dict(row,id=DEPLOYER[0],sha256=hashed,matches_historical=(hashed==DEPLOYER[2]) if raw is not None else None)
    partial=partial or row['read_state'] not in ('ok','absent','not_regular')
    bootstrap=[]
    for name,path in BOOTSTRAP_FILES:
        row=_read_fixed(path,deadline); raw=row.pop('raw'); row.pop('identity',None)
        bootstrap.append(dict(row,id=name,sha256=hashlib.sha256(raw).hexdigest() if raw is not None else None,
            legacy_reference_only_literal_present=b'LEGACY_REFERENCE_ONLY' in raw if raw is not None else None))
        partial=partial or row['read_state'] not in ('ok','absent','not_regular')
    configs=[]
    for name,path,profile in CONFIG_FILES:
        row=_read_fixed(path,deadline); raw=row.pop('raw')
        facts=_parse_config(raw,profile) if raw is not None else _config_unknown('unavailable')
        configs.append(dict(id=name,read_state=row['read_state'],**facts))
        partial=partial or row['read_state'] not in ('ok','absent','not_regular') or facts['profile_parse']=='unsupported'
    lock=_metadata_fixed(DEPLOY_LOCK,deadline)
    services=_services(deadline)
    end=_read_fixed(CURRENT,deadline)
    first,last=_deployment_record(begin),_deployment_record(end)
    stable=None
    if begin['raw'] is not None and end['raw'] is not None:
        stable=begin.get('identity') is not None and begin['raw']==end['raw'] and begin['identity']==end.get('identity') and first==last
    partial=(partial or stable is not True or any(row['sha'] is None or row['deployed_at'] is None for row in (first,last))
        or lock['read_state'] not in ('ok','absent','not_regular')
        or any('unknown' in (row['load_state'],row['active_state'],row['sub_state']) for row in services))
    return dict(version='jsm-test-installed-route-v2',nonce=nonce,euid=os.geteuid(),code_files=code,sites=sites,services=services,
        configs=configs,bootstrap_files=bootstrap,deployer=deployer,deployment_record_begin=first,deployment_record_end=last,
        deployment_record_stable=stable,deploy_lock=lock,observation_state='PARTIAL' if partial else 'OBSERVED')
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
        + ''.join(name+'='+repr(globals()[name])+'\n' for name in ('CONFIG_FILES','BOOTSTRAP_FILES','DEPLOYER','CURRENT','DEPLOY_LOCK'))
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
                part=os.read(key.fileobj.fileno(),min(12288,12289-len(raw))); raw.extend(part)
                if len(raw)>12288: raise ValueError()
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
print(json.dumps(dict(version='jsm-test-installed-route-outer-v2',nonce=nonce,principal=principal,euid=euid,
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


def _fingerprint(row, flag):
    if type(row) is not dict or set(row)!={'id','present','regular','mode','read_state','sha256',flag}: return False
    if not _metadata(row,mode=True): return False
    if row['read_state']=='ok':
        return type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) and type(row[flag]) is bool
    return row['sha256'] is None and row[flag] is None


def _bootstrap_record(row, reference):
    return dict(row) if _fingerprint(row,'legacy_reference_only_literal_present') else None


def _deployer_record(row):
    if not _fingerprint(row,'matches_historical') or row['id']!=DEPLOYER[0]: return None
    if row['read_state']=='ok' and row['matches_historical']!=(row['sha256']==DEPLOYER[2]): return None
    return dict(row)


def _config_record(row, reference):
    keys={'id','read_state','profile_parse','db_loopback_literal','db_test_namespace_literal','db_target_descriptor_sha256',
          'cache_filecache_literal','mail_file_transport_literal','indirection_or_override'}
    if type(row) is not dict or set(row)!=keys or row['indirection_or_override']!='UNKNOWN': return None
    state=row['read_state']; parsed=row['profile_parse']
    if state not in ('ok','absent','not_regular','unsafe_path','too_large','changed','unreadable','deadline'): return None
    if parsed not in ('supported','unsupported','unavailable') or (state=='ok')!=(parsed!='unavailable'): return None
    predicates=('db_loopback_literal','db_test_namespace_literal','cache_filecache_literal','mail_file_transport_literal')
    if any(value is not None and type(value) is not bool for value in (row[key] for key in predicates)): return None
    digest=row['db_target_descriptor_sha256']
    if parsed!='supported' and (any(row[key] is not None for key in predicates) or digest is not None): return None
    if row['db_loopback_literal'] is True and row['db_test_namespace_literal'] is True:
        if type(digest) is not str or not re.fullmatch('[0-9a-f]{64}',digest): return None
    elif digest is not None: return None
    return dict(row)


def _deployment_projection(row):
    if type(row) is not dict or set(row)!={'read_state','sha','deployed_at'}: return None
    state=row['read_state']
    if state not in ('ok','absent','not_regular','unsafe_path','too_large','changed','unreadable','deadline'): return None
    if state!='ok' and (row['sha'] is not None or row['deployed_at'] is not None): return None
    if row['sha'] is not None and (type(row['sha']) is not str or not re.fullmatch('[0-9a-f]{40}',row['sha'])): return None
    stamp=row['deployed_at']
    if stamp is not None:
        if type(stamp) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z',stamp): return None
        try: datetime.datetime.fromisoformat(stamp[:-1]+'+00:00')
        except ValueError: return None
    return dict(row)


def _lock_projection(row):
    if type(row) is not dict or set(row)!={'present','regular','mode','read_state'} or not _metadata(row,mode=True): return None
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
        need(type(raw) is bytes and 0<len(raw)<=16384,'REMOTE_IDENTITY_SCHEMA_REJECTED')
        outer=strict_json(raw.decode('ascii'))
        need(_identity(outer,'jsm-test-installed-route-outer-v2',nonce)
             and set(outer)=={'version','nonce','principal','euid','root_diagnostic'}
             and outer['principal']=='marinagurina','REMOTE_IDENTITY_SCHEMA_REJECTED')
    except Exception: raise Refused('REMOTE_IDENTITY_SCHEMA_REJECTED') from None
    result=dict(ssh_identity=True,ssh_principal='marinagurina',ssh_euid=outer['euid'],sudo_root_identity=None,
                code_files=[None]*25,sites=[None]*3,services=[None]*4,configs=[None]*7,bootstrap_files=[None]*2,deployer=None,
                deployment_record_begin=None,deployment_record_end=None,deployment_record_stable=None,deploy_lock=None,observation_state='PARTIAL')
    child=outer['root_diagnostic']
    if not (_identity(child,'jsm-test-installed-route-v2',nonce)
            and set(child)=={'version','nonce','euid','code_files','sites','services','observation_state','configs','bootstrap_files','deployer',
                'deployment_record_begin','deployment_record_end','deployment_record_stable','deploy_lock'}): return result
    result['sudo_root_identity']=child['euid']==0
    if child['euid']!=0: return result
    code=_records(child['code_files'],CODE_FILES,_code_record)
    sites=_records(child['sites'],SITE_FILES,_site_record)
    services=_records(child['services'],UNITS,_service_record)
    configs=_records(child['configs'],CONFIG_FILES,_config_record)
    bootstrap=_records(child['bootstrap_files'],BOOTSTRAP_FILES,_bootstrap_record)
    deployer=_deployer_record(child['deployer'])
    first,last=_deployment_projection(child['deployment_record_begin']),_deployment_projection(child['deployment_record_end'])
    stable=child['deployment_record_stable']
    if stable is not None and type(stable) is not bool: stable=None
    if first is None or last is None or first['read_state']!='ok' or last['read_state']!='ok': stable=None
    if stable is True and first!=last: stable=None
    lock=_lock_projection(child['deploy_lock'])
    result.update(code_files=code,sites=sites,services=services,configs=configs,bootstrap_files=bootstrap,deployer=deployer,
        deployment_record_begin=first,deployment_record_end=last,deployment_record_stable=stable,deploy_lock=lock)
    complete=(all(row is not None and row['read_state'] in ('ok','absent','not_regular') for row in code)
        and all(row is not None and row['read_state'] in ('ok','absent','not_regular') and row['parse_state']!='unsupported' for row in sites)
        and all(row is not None and 'unknown' not in (row['load_state'],row['active_state'],row['sub_state']) for row in services)
        and all(row is not None and row['read_state'] in ('ok','absent','not_regular') and row['profile_parse']!='unsupported' for row in configs)
        and all(row is not None and row['read_state'] in ('ok','absent','not_regular') for row in bootstrap+[deployer,lock])
        and stable is True and all(row is not None and row['sha'] is not None and row['deployed_at'] is not None for row in (first,last)))
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
        code,raw=_at_stage('ssh_transport',_bounded,command,data=remote_program(nonce),limit=16384,timeout=budget)
        need(code==0,'SSH_TRANSPORT_NOT_CONFIRMED')
        observed=_at_stage('remote_identity',project_remote,raw,nonce)
    complete=observed['observation_state']=='OBSERVED'
    return dict(observed,receipt_version='jsm-test-installed-route-v2',serving_php_version=None,
        db_target_identity='NOT_ESTABLISHED',db_grants='NOT_ESTABLISHED',db_data_provenance='NOT_ESTABLISHED',egress_isolation='NOT_ESTABLISHED',status='TEST_INSTALLED_ROUTE_OBSERVED' if complete else 'PARTIAL',
        reason='FIXED_OBSERVATION_COMPLETE' if complete else 'FIXED_OBSERVATION_INCOMPLETE',failure_stage=None if complete else 'remote_identity',
        resource='gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713',ip='34.104.157.63',ssh_port=22,
        known_hosts_sha256=PIN_SHA256,reviewed_candidate_sha='8b07cd006859650b35bffee3eda2c5ee07919f1b',
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
        print(json.dumps(dict(status='BLOCKED',receipt_version='jsm-test-installed-route-v2',reason=reason,failure_stage=stage,python_version=_python_version(),
            serving_php_version=None,db_target_identity='NOT_ESTABLISHED',db_grants='NOT_ESTABLISHED',db_data_provenance='NOT_ESTABLISHED',egress_isolation='NOT_ESTABLISHED',
            ssh_identity=None,sudo_root_identity=None,installed_release_sha=None,active_include_binding='NOT_ESTABLISHED',
            api302_cause='UNKNOWN',api_health='NOT_TESTED',db_isolation='NOT_ESTABLISHED',provider_requests='NOT_PERFORMED',
            application_execution='NOT_PERFORMED',deploy_acceptance='NOT_ESTABLISHED'),separators=(',',':'),sort_keys=True))
        return 1
    finally: signal.setitimer(signal.ITIMER_REAL,0)


if __name__=='__main__': raise SystemExit(main())
