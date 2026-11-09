"""Offline TEST diagnostic contracts; all file/process data are synthetic."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test_api_installed_route_readonly.py'
NONCE = 'b' * 32
KNOWN = '34.104.157.63 ssh-ed25519 SYNTHETIC_HOST_KEY'
FLAGS = ('test_server_name_literal_present', 'api_alias_literal_present',
         'api_proxy_exclusion_literal_present', 'loopback_front_proxy_literal_present',
         'rewrite_rule_present', 'include_or_conditional_present')


class InstalledRouteTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'Missing fixed installed-code/route diagnostic')
        spec = importlib.util.spec_from_file_location('test_api_installed_route_readonly', SCRIPT)
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)

    def library(self):
        ns = dict(CODE_FILES=self.m.CODE_FILES, SITE_FILES=self.m.SITE_FILES, UNITS=self.m.UNITS,
                  FLAGS=self.m.FLAGS, NONCE=NONCE)
        exec(compile(self.m._ROOT_LIBRARY, '<reviewed-diagnostic-library>', 'exec'), ns)
        return ns

    def context(self):
        return dict(GITHUB_REPOSITORY='JSMJapan/jsm-release-control', GITHUB_ACTOR='JSMJapan',
                    GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
                    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_RUN_ID='123456789',
                    GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/test-api-installed-route-readonly.yml@refs/heads/main',
                    TEST_API_ADMIN_SSH_KEY='SYNTHETIC_PRIVATE_KEY', TEST_API_KNOWN_HOSTS=KNOWN)

    def api(self, mutate=None, bad_index=None):
        rows = [dict(full_name='JSMJapan/jsm-release-control', private=False),
            dict(name='test-api-readonly-access', can_admins_bypass=False,
                protection_rules=[dict(type='required_reviewers', prevent_self_review=False,
                    reviewers=[dict(type='User', reviewer=dict(login='JSMJapan', id=327623967))])],
                deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True)),
            dict(total_count=1, branch_policies=[dict(name='main', type='branch')])]
        if mutate: mutate(rows)
        calls = []
        class Api:
            def get_json(inner, path):
                calls.append(path)
                if len(calls) - 1 == bad_index: raise self.m.Refused('GITHUB_RESPONSE_LENGTH_MISMATCH')
                return copy.deepcopy(rows[len(calls) - 1])
        return Api(), calls

    def root_receipt(self):
        return dict(version='jsm-test-installed-route-v1', nonce=NONCE, euid=0,
            code_files=[dict(id=row[0], present=True, regular=True, mode=0o644, read_state='ok',
                sha256=row[3], matches_reviewed=True) for row in self.m.CODE_FILES],
            sites=[dict(id=row[0], present=True, regular=True, read_state='ok', parse_state='ok',
                **{name: False for name in FLAGS}) for row in self.m.SITE_FILES],
            services=[dict(id=name, load_state='loaded', active_state='active', sub_state='running') for name in self.m.UNITS],
            observation_state='OBSERVED')

    def outer(self, child=None):
        return dict(version='jsm-test-installed-route-outer-v1', nonce=NONCE,
                    principal='marinagurina', euid=1001,
                    root_diagnostic=self.root_receipt() if child is None else child)

    def test_source_pins_paths_and_no_live_inputs_are_fixed(self):
        self.assertEqual(len(self.m.CODE_FILES), 6); self.assertEqual(len(self.m.SITE_FILES), 3)
        self.assertEqual(self.m.CODE_FILES[0], ('lot', '/srv/jsm/app/backend/api/modules/v1/controllers/LotController.php',
            14918, 'dc50c9e035e9e1b89b185488e6277bd712194f56b9619c1b8599cf62c471aee1'))
        self.assertEqual(self.m.UNITS, ('jsm-front.service', 'apache2.service', 'php7.4-fpm.service', 'php8.5-fpm.service'))
        self.assertEqual(self.m.FLAGS, FLAGS)
        for bad in ('', 'B' * 32, None, ';echo PRIVATE'):
            with self.assertRaises(self.m.Refused): self.m.remote_program(bad)

    def test_reader_bounds_regular_hash_modes_and_absence_without_following_links(self):
        ns = self.library(); read = ns['_read_fixed']
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); good = root / 'code.php'; good.write_bytes(b'synthetic code')
            result = read(str(good), time.monotonic() + 2)
            self.assertEqual(result['raw'], b'synthetic code'); self.assertTrue(result['present']); self.assertTrue(result['regular'])
            self.assertEqual(result['mode'], good.stat().st_mode & 0o7777)
            absent = read(str(root / 'absent'), time.monotonic() + 2)
            self.assertEqual(absent, dict(present=False, regular=None, mode=None, read_state='absent', raw=None))
            link = root / 'link'; link.symlink_to(good)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            for path in (link, fifo, root):
                row = read(str(path), time.monotonic() + 2)
                self.assertEqual(row['read_state'], 'not_regular'); self.assertIs(row['regular'], False)
                self.assertIsNone(row['raw'])
            alias = root / 'alias'; alias.symlink_to(root, target_is_directory=True)
            row = read(str(alias / 'code.php'), time.monotonic() + 2)
            self.assertEqual(row['read_state'], 'unsafe_path'); self.assertIsNone(row['present'])
            large = root / 'large'; large.write_bytes(b'x' * 65537)
            row = read(str(large), time.monotonic() + 2)
            self.assertEqual(row['read_state'], 'too_large'); self.assertIsNone(row['raw'])

    def test_reader_refuses_hardlinks_races_inaccessible_and_deadline(self):
        ns = self.library()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); path = root / 'code'; path.write_bytes(b'original')
            os.link(path, root / 'other')
            self.assertEqual(ns['_read_fixed'](str(path), time.monotonic()+2)['read_state'], 'unsafe_path')
            (root / 'other').unlink()
            actual_read = os.read; changed = [False]
            def changing(fd, count):
                data = actual_read(fd, count)
                if not changed[0]: changed[0] = True; path.write_bytes(b'changed!')
                return data
            with patch.object(os, 'read', side_effect=changing):
                self.assertEqual(ns['_read_fixed'](str(path), time.monotonic()+2)['read_state'], 'changed')
            with patch.object(os, 'open', side_effect=PermissionError('PRIVATE_PATH')):
                row = ns['_read_fixed'](str(path), time.monotonic()+2)
            self.assertIsNone(row['present']); self.assertEqual(row['read_state'], 'unreadable')
            self.assertEqual(ns['_read_fixed'](str(path), time.monotonic()-1)['read_state'], 'deadline')

    def test_absence_is_not_proved_when_parent_path_changes_after_lookup(self):
        ns=self.library()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); parent=root/'parent'; parent.mkdir(); path=parent/'absent'
            actual_stat=os.stat; changed=[False]
            def replacing(name,*args,**kwargs):
                try: return actual_stat(name,*args,**kwargs)
                except FileNotFoundError:
                    if name=='absent' and not changed[0]:
                        changed[0]=True; parent.rename(root/'old'); parent.mkdir(); path.write_bytes(b'new')
                    raise
            with patch.object(os,'stat',side_effect=replacing): row=ns['_read_fixed'](str(path),time.monotonic()+2)
            self.assertIsNone(row['present']); self.assertIsNone(row['raw'])

    def test_lexer_flags_are_literal_not_comments_operands_or_active_binding(self):
        parse = self.library()['_parse_site']
        raw = b'''# Alias /api /srv/jsm/app/backend/api/web
<VirtualHost *:443>
ServerName develop.jsmjapan.com
Alias "/api" "/srv/jsm/app/backend/api/web"
ProxyPass /api !
ProxyPass / http://127.0.0.1:3000/
RewriteRule ^ /somewhere [R=302]
<IfModule mod_alias.c>
IncludeOptional /some/other.conf
</IfModule>
</VirtualHost>
'''
        state, flags = parse(raw)
        self.assertEqual(state, 'ok'); self.assertTrue(all(flags.values()))
        state, flags = parse(b'CustomLog "Alias /api /srv/jsm/app/backend/api/web" combined\n# RewriteRule ^ /x\n')
        self.assertEqual(state, 'ok'); self.assertFalse(any(flags.values()))
        state, flags = parse(b'Alias /api /PRIVATE\nProxyPass / http://PRIVATE/\n')
        self.assertFalse(flags['api_alias_literal_present']); self.assertFalse(flags['loopback_front_proxy_literal_present'])
        self.assertNotIn('PRIVATE', json.dumps(flags))

    def test_unsupported_lexical_containers_continuations_and_limits_stay_unknown(self):
        parse = self.library()['_parse_site']
        for raw in [b'Alias "unterminated', b'Alias /api \\\n/path', b'<VirtualHost *:443>\n</Directory>',
                    b'<Unknown thing>\n</Unknown>', b'<Directory>\n</Directory>', b'<Directory /x>\n</Directory>>',
                    b'Alias /api', b'X ' + b'a'*4097, b'\xff', b'\x00']:
            state, flags = parse(raw)
            self.assertEqual(state, 'unsupported'); self.assertTrue(all(value is None for value in flags.values()))
        state, flags = parse('# комментарий\nServerName develop.jsmjapan.com\n'.encode())
        self.assertEqual(state, 'ok'); self.assertTrue(flags['test_server_name_literal_present'])

    def test_non_linefeed_separators_cannot_turn_comment_text_into_a_directive(self):
        parse=self.library()['_parse_site']
        for separator in ('\x0b','\x0c','\x85','\u2028','\u2029'):
            state,flags=parse(('# comment'+separator+'ServerName develop.jsmjapan.com\n').encode())
            self.assertEqual(state,'ok'); self.assertFalse(any(flags.values()))
        state,flags=parse(b'<VirtualHost *:443>\r\nServerName develop.jsmjapan.com\r\n</VirtualHost>\r\n')
        self.assertEqual(state,'ok'); self.assertTrue(flags['test_server_name_literal_present'])

    def test_only_full_line_apache_comments_and_no_physical_continuations_are_supported(self):
        parse=self.library()['_parse_site']
        for raw in [b'Alias /api /srv/jsm/app/backend/api/web#other',
                    b'Alias /api /srv/jsm/app/backend/api/web # trailing',
                    b'# continued comment \\\nAlias /api /srv/jsm/app/backend/api/web\n']:
            state,flags=parse(raw)
            self.assertEqual(state,'unsupported'); self.assertTrue(all(value is None for value in flags.values()))
        state,flags=parse(b'# full-line comment\nAlias "/api" "/srv/jsm/app/backend/api/web#other"\n')
        self.assertEqual(state,'ok'); self.assertFalse(flags['api_alias_literal_present'])

    def test_ordinary_regex_escapes_are_opaque_without_enabling_continuations_or_escaped_delimiters(self):
        parse=self.library()['_parse_site']
        raw=b'<FilesMatch "\\.php$">\nSetHandler "some:opaque-handler"\n</FilesMatch>\nRewriteRule ^/foo\\.php$ /bar [L]\nAlias /api /srv/jsm/app/backend/api/web\n'
        state,flags=parse(raw)
        self.assertEqual(state,'ok'); self.assertTrue(flags['rewrite_rule_present']); self.assertTrue(flags['api_alias_literal_present'])
        for raw in [b'ServerName "develop.jsmjapan.com\\""',b'Alias /api\\ /srv/jsm/app/backend/api/web',b'X a\\#comment']:
            state,flags=parse(raw)
            self.assertEqual(state,'unsupported'); self.assertTrue(all(value is None for value in flags.values()))

    def service_bytes(self):
        return b'\n'.join(('Id='+name+'\nLoadState=loaded\nActiveState=active\nSubState=running\n').encode() for name in self.m.UNITS)

    def test_service_projection_requires_exact_ids_keys_and_never_returns_unexpected_values(self):
        parse = self.library()['_parse_services']
        records = parse(self.service_bytes()); self.assertEqual(len(records), 4)
        for raw in [self.service_bytes()+b'\nSecret=PRIVATE', self.service_bytes().replace(b'Id=apache2.service', b'Id=jsm-front.service'),
                    self.service_bytes().replace(b'SubState=running\n', b'', 1),
                    self.service_bytes().replace(b'\nLoadState=',b'\vLoadState=',1),
                    self.service_bytes().replace(b'LoadState=loaded', b'LoadState=loaded\nLoadState=loaded', 1)]:
            self.assertIsNone(parse(raw))
        records = parse(self.service_bytes().replace(b'ActiveState=active', b'ActiveState=PRIVATE'))
        self.assertTrue(all(row['active_state']=='unknown' for row in records)); self.assertNotIn('PRIVATE', json.dumps(records))

    def test_closed_projection_retains_ssh_root_and_valid_data_when_data_is_malformed(self):
        good = self.outer(); projected = self.m.project_remote(json.dumps(good).encode(), NONCE)
        self.assertTrue(projected['ssh_identity']); self.assertTrue(projected['sudo_root_identity'])
        self.assertEqual(projected['observation_state'], 'OBSERVED')
        for mutate in [lambda r:r['code_files'][0].update(sha256='PRIVATE'),
                       lambda r:r['sites'][0].update(extra='PRIVATE'),
                       lambda r:r['services'][0].update(active_state='PRIVATE')]:
            value = self.outer(); mutate(value['root_diagnostic'])
            result = self.m.project_remote(json.dumps(value).encode(), NONCE)
            self.assertTrue(result['ssh_identity']); self.assertTrue(result['sudo_root_identity'])
            self.assertEqual(result['observation_state'], 'PARTIAL'); self.assertNotIn('PRIVATE', json.dumps(result))
        for value in [dict(good, nonce='c'*32), dict(good, principal='root'), dict(good, euid=True), dict(good, extra='PRIVATE')]:
            with self.assertRaises(self.m.Refused): self.m.project_remote(json.dumps(value).encode(), NONCE)
        for raw in [b'PRIVATE', b'x'*4097, b'\xff', json.dumps(good).replace('"euid": 1001','"euid": 1001, "euid": 1001').encode()]:
            with self.assertRaises(self.m.Refused): self.m.project_remote(raw, NONCE)

    def test_child_failure_and_wrong_nonce_never_become_false_root_identity(self):
        for child in [False, {}, dict(self.root_receipt(), nonce='c'*32)]:
            result = self.m.project_remote(json.dumps(self.outer(child)).encode(), NONCE)
            self.assertTrue(result['ssh_identity']); self.assertIsNone(result['sudo_root_identity'])
            self.assertEqual(result['observation_state'], 'PARTIAL')
        result = self.m.project_remote(json.dumps(self.outer(dict(self.root_receipt(), euid=1001))).encode(), NONCE)
        self.assertIs(result['sudo_root_identity'], False)

    def test_correlated_read_metadata_and_hash_match_cannot_be_forged(self):
        for change in [dict(present=False), dict(regular=False), dict(mode=True), dict(read_state='absent'),
                       dict(matches_reviewed=False), dict(sha256='0'*64), dict(extra='PRIVATE')]:
            value = self.outer(); value['root_diagnostic']['code_files'][0].update(change)
            row = self.m.project_remote(json.dumps(value).encode(), NONCE)
            self.assertEqual(row['observation_state'], 'PARTIAL')
            self.assertIsNone(row['code_files'][0])

    def test_scope_policy_precedes_key_and_fixed_transport_cleans_private_files(self):
        class Guard(dict):
            def get(inner, name, default=None):
                if name.startswith('TEST_API_'): self.fail('credential accessed before admission')
                return super().get(name, default)
        for key, value in [('GITHUB_ACTOR','other'), ('GITHUB_REF','refs/heads/x'), ('GITHUB_RUN_ATTEMPT','2'),
                           ('GITHUB_WORKFLOW_SHA','c'*40), ('GITHUB_WORKFLOW_REF','other')]:
            env = Guard(self.context()); env[key]=value; api,calls=self.api()
            with self.assertRaises(self.m.Refused): self.m.collect(api,env)
            self.assertEqual(calls,[])
        for mutate in [lambda r:r[1].update(name='other'), lambda r:r[1].update(can_admins_bypass=True),
                       lambda r:r[2].update(total_count=True),
                       lambda r:r[1]['protection_rules'][0]['reviewers'][0]['reviewer'].update(id=True)]:
            api,calls=self.api(mutate)
            with self.assertRaises(self.m.Refused): self.m.collect(api,Guard(self.context()))
            self.assertEqual(len(calls),3)
        folders=[]
        def transport(command, *, data, limit, timeout):
            self.assertEqual(command[-6:],['marinagurina@34.104.157.63','/usr/bin/python3','-I','-B','-S','-'])
            self.assertEqual(command[command.index('-p')+1],'22')
            for item in ['BatchMode=yes','StrictHostKeyChecking=yes','IdentityAgent=none','IdentitiesOnly=yes',
                         'PasswordAuthentication=no','KbdInteractiveAuthentication=no','ClearAllForwardings=yes']:
                self.assertIn(item,command)
            key=Path(command[command.index('-i')+1]); folders.append(key.parent)
            self.assertEqual(key.read_bytes(),b'SYNTHETIC_PRIVATE_KEY\n')
            self.assertEqual(key.stat().st_mode&0o777,0o600); self.assertEqual(key.parent.stat().st_mode&0o777,0o700)
            self.assertEqual((key.parent/'known_hosts').read_bytes(),KNOWN.encode())
            self.assertEqual(limit,4096); self.assertTrue(0<timeout<=15)
            return 0,json.dumps(self.outer()).encode()
        api,calls=self.api()
        with patch.object(self.m,'PIN_SHA256',hashlib.sha256(KNOWN.encode()).hexdigest()), \
                patch.object(self.m.secrets,'token_hex',return_value=NONCE), patch.object(self.m,'_bounded',side_effect=transport):
            result=self.m.collect(api,self.context())
        self.assertEqual(result['status'],'TEST_INSTALLED_ROUTE_OBSERVED')
        for name in ('installed_release_sha',): self.assertIsNone(result[name])
        self.assertEqual(result['active_include_binding'],'NOT_ESTABLISHED'); self.assertEqual(result['api302_cause'],'UNKNOWN')
        self.assertEqual(result['api_health'],'NOT_TESTED'); self.assertNotIn('PRIVATE_KEY',json.dumps(result))
        self.assertTrue(folders); self.assertTrue(all(not path.exists() for path in folders))

    def test_maximum_closed_receipt_fits_child_and_outer_caps_and_rejects_child_oversize(self):
        child=self.root_receipt()
        child['euid']=4294967295
        # Loose independent scalar maxima also bound every correlated valid
        # record; no raw path/content/error string is admitted by this schema.
        for row in child['code_files']: row.update(present=False,regular=False,mode=4095,read_state='not_regular',matches_reviewed=False,sha256='f'*64)
        for row in child['sites']:
            row.update(present=False,regular=False,read_state='not_regular',parse_state='unsupported')
            row.update({name:False for name in FLAGS})
        for row in child['services']: row.update(load_state='not-found',active_state='inactive',sub_state='running')
        compact=json.dumps(child,separators=(',',':')).encode()+b'\n'
        self.assertEqual(len(compact),2760)
        self.assertLessEqual(len(compact),3072)
        self.assertLessEqual(len(json.dumps(self.outer(child),separators=(',',':')).encode()),4096)
        self.assertNotIn('PRIVATE',compact.decode())
        valid=json.dumps(self.outer(),separators=(',',':')).encode()
        with self.assertRaises(self.m.Refused): self.m.project_remote(valid+b' '*(4097-len(valid)),NONCE)

    def test_observer_reads_only_nine_fixed_files_and_emits_no_raw_bytes(self):
        ns=self.library(); calls=[]
        def read(path,deadline):
            calls.append(path)
            raw=b'ServerName develop.jsmjapan.com\n' if path.startswith('/etc/apache2/') else b'SYNTHETIC_CODE'
            return dict(present=True,regular=True,mode=0o644,read_state='ok',raw=raw)
        ns['_read_fixed']=read
        ns['_services']=lambda deadline:self.root_receipt()['services']
        with patch.object(os,'geteuid',return_value=0): root=ns['_observe'](NONCE)
        self.assertEqual(calls,[row[1] for row in self.m.CODE_FILES]+[row[1] for row in self.m.SITE_FILES])
        self.assertTrue(all(row['matches_reviewed'] is False for row in root['code_files']))
        self.assertTrue(all(row['sha256']==hashlib.sha256(b'SYNTHETIC_CODE').hexdigest() for row in root['code_files']))
        self.assertNotIn('SYNTHETIC_CODE',json.dumps(root)); self.assertNotIn('/etc/',json.dumps(root))
        result=self.m.project_remote(json.dumps(self.outer(root)).encode(),NONCE)
        self.assertEqual(result['observation_state'],'OBSERVED')

    def service_transport(self, program):
        ns=self.library(); real=subprocess.Popen; children=[]
        def launch(command,**kwargs):
            self.assertEqual(command,['/usr/bin/timeout','--signal=TERM','--kill-after=0.2','0.7',
                '/usr/bin/systemctl','--no-pager','show','--property=Id,LoadState,ActiveState,SubState',*self.m.UNITS])
            self.assertEqual(kwargs['stdin'],subprocess.DEVNULL); self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
            self.assertNotIn('start_new_session',kwargs)
            # Simulate the fixed GNU timeout's own process group with an
            # unprivileged Python child; no local timeout/systemctl/sudo executes.
            child=real([sys.executable,'-I','-B','-S','-c',program],start_new_session=True,**kwargs)
            children.append(child); return child
        start=time.monotonic()
        with patch.object(subprocess,'Popen',side_effect=launch): result=ns['_services'](time.monotonic()+3)
        self.assertLess(time.monotonic()-start,1.3)
        self.assertTrue(all(child.poll() is not None for child in children))
        return result

    def test_service_fixed_command_cap_timeout_nonzero_and_cleanup(self):
        valid=self.service_bytes()
        result=self.service_transport('import sys;sys.stdout.buffer.write(%r)'%valid)
        self.assertTrue(all(row['active_state']=='active' for row in result))
        for program in ['import sys;sys.stdout.write("x"*5000)',
                        'import time;time.sleep(2)',
                        'import sys;sys.stdout.buffer.write(%r);sys.exit(1)'%valid]:
            result=self.service_transport(program)
            self.assertTrue(all(row['active_state']=='unknown' for row in result))
        ns=self.library()
        with patch.object(subprocess,'Popen',side_effect=AssertionError('late command started')):
            self.assertEqual(ns['_services'](time.monotonic()+.5),ns['_unknown_services']())

    def test_service_early_exit_cleans_descendant_before_delayed_side_effect(self):
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'escaped'
            program=('import os,sys,time,pathlib\npid=os.fork()\n'
                'if pid==0:\n time.sleep(.3)\n pathlib.Path(%r).write_text("escaped")\n time.sleep(2)\n'
                'else:\n sys.stdout.buffer.write(%r)\n sys.stdout.flush()\n os._exit(0)\n')%(str(marker),self.service_bytes())
            self.service_transport(program)
            time.sleep(.35)
            self.assertFalse(marker.exists(),'descendant survived early wrapper-exit cleanup')

    def execute_outer(self, raw, *, code=0, delay=0):
        real=subprocess.Popen; children=[]
        def launch(command,**kwargs):
            self.assertEqual(command[:11],['/usr/bin/sudo','-n','/usr/bin/timeout','--signal=TERM','--kill-after=1','4',
                '/usr/bin/python3','-I','-B','-S','-c'])
            tree=ast.parse(command[11])
            imports={item.name for node in ast.walk(tree) if isinstance(node,ast.Import) for item in node.names}
            self.assertEqual(imports,{'errno','hashlib','json','os','re','selectors','signal','stat','subprocess','time'})
            self.assertEqual(kwargs['stdin'],subprocess.DEVNULL); self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
            self.assertTrue(kwargs['start_new_session'])
            program='import sys,time;time.sleep(%r);sys.stdout.buffer.write(%r);sys.stdout.flush();sys.exit(%d)'%(delay,raw,code)
            child=real([sys.executable,'-I','-B','-S','-c',program],**kwargs); children.append(child); return child
        output=io.StringIO()
        with patch.object(subprocess,'Popen',side_effect=launch),patch.object(os,'geteuid',return_value=1001), \
                patch('pwd.getpwuid',return_value=types.SimpleNamespace(pw_name='marinagurina')),contextlib.redirect_stdout(output):
            exec(compile(self.m.remote_program(NONCE),'<constant-outer-diagnostic>','exec'),{})
        self.assertTrue(all(child.poll() is not None for child in children))
        return self.m.project_remote(output.getvalue().encode(),NONCE)

    def test_actual_outer_constant_enforces_child_caps_nonce_and_five_second_budget(self):
        valid=json.dumps(self.root_receipt(),separators=(',',':')).encode()
        result=self.execute_outer(valid); self.assertTrue(result['sudo_root_identity'])
        for raw,code in [(valid,1),(valid+b' '*(3073-len(valid)),0),(b'PRIVATE_RAW',0),(b'\xff',0),
                         (valid.replace(b'"euid":0',b'"euid":0,"euid":0'),0)]:
            result=self.execute_outer(raw,code=code)
            self.assertTrue(result['ssh_identity']); self.assertIsNone(result['sudo_root_identity'])
            self.assertNotIn('PRIVATE',json.dumps(result))
        start=time.monotonic(); result=self.execute_outer(b'',delay=6)
        self.assertLess(time.monotonic()-start,5.6)
        self.assertTrue(result['ssh_identity']); self.assertIsNone(result['sudo_root_identity'])

    def test_shared_overall_budget_keeps_cleanup_reserve_and_failure_cleans_key(self):
        clock=[0]; api,_=self.api(); original=api.get_json; folders=[]
        def get(path): clock[0]+=17; return original(path)
        api.get_json=get
        def transport(command,**kwargs):
            self.assertLessEqual(kwargs['timeout'],7)
            folders.append(Path(command[command.index('-i')+1]).parent)
            raise OSError('PRIVATE_KEY PRIVATE_STDERR')
        with patch.object(self.m.time,'monotonic',side_effect=lambda:clock[0]), \
                patch.object(self.m,'PIN_SHA256',hashlib.sha256(KNOWN.encode()).hexdigest()), \
                patch.object(self.m,'_bounded',side_effect=transport):
            with self.assertRaises(self.m.Refused): self.m.collect(api,self.context())
        self.assertTrue(folders); self.assertTrue(all(not path.exists() for path in folders))

    def test_main_no_arguments_safe_stage_and_unknown_receipt(self):
        output=io.StringIO()
        with patch.object(self.m.sys,'argv',['probe','--path','PRIVATE']), patch.object(self.m.signal,'setitimer'), \
                patch.object(self.m,'collect',side_effect=AssertionError('must not run')),contextlib.redirect_stdout(output):
            self.assertEqual(self.m.main(),1)
        receipt=json.loads(output.getvalue()); self.assertIsNone(receipt['ssh_identity'])
        self.assertIsNone(receipt['sudo_root_identity']); self.assertNotIn('PRIVATE',output.getvalue())


class WorkflowContractTests(unittest.TestCase):
    def workflow(self):
        path = ROOT / '.github/workflows/test-api-installed-route-readonly.yml'
        self.assertTrue(path.is_file(), 'fixed installed-route workflow is missing')
        return json.loads(path.read_text(encoding='utf-8'))

    @staticmethod
    def admitted(expression, context):
        """Evaluate the fixed AND/equality guard without executing a workflow."""
        clauses = expression.split('&&')
        comparisons = []
        for clause in clauses:
            match = re.fullmatch(r"\s*(github\.[a-z_.]+)\s*==\s*('[^']*'|false|true|[0-9]+)\s*", clause)
            if match is None:
                raise AssertionError('guard must contain only fixed conjunctive equalities')
            name, literal = match.groups()
            value = literal[1:-1] if literal.startswith("'") else json.loads(literal)
            comparisons.append(context.get(name) == value)
        return all(comparisons)

    def test_only_approved_public_owner_first_attempt_main_dispatch_is_admitted(self):
        workflow = self.workflow()
        self.assertEqual(workflow['on'], {'workflow_dispatch': {}})
        context = {
            'github.event_name': 'workflow_dispatch',
            'github.repository': 'JSMJapan/jsm-release-control',
            'github.event.repository.private': False,
            'github.actor': 'JSMJapan',
            'github.triggering_actor': 'JSMJapan',
            'github.ref': 'refs/heads/main',
            'github.run_attempt': 1,
        }
        expression = workflow['jobs']['probe']['if']
        self.assertTrue(self.admitted(expression, context))
        for key, denied in [
            ('github.event_name', 'push'),
            ('github.event_name', 'pull_request'),
            ('github.repository', 'other/jsm-release-control'),
            ('github.event.repository.private', True),
            ('github.actor', 'other'),
            ('github.triggering_actor', 'other'),
            ('github.ref', 'refs/heads/other'),
            ('github.run_attempt', 2),
        ]:
            with self.subTest(key=key, denied=denied):
                changed = copy.deepcopy(context)
                changed[key] = denied
                self.assertFalse(self.admitted(expression, changed))

    def test_fixed_runner_pipeline_scopes_credentials_to_named_protected_step(self):
        workflow = self.workflow()
        self.assertEqual(set(workflow), {'name', 'on', 'permissions', 'concurrency', 'jobs'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(workflow['concurrency'], {
            'group': 'test-api-installed-route-readonly', 'cancel-in-progress': False})
        self.assertEqual(set(workflow['jobs']), {'offline', 'probe'})
        offline, probe = workflow['jobs']['offline'], workflow['jobs']['probe']
        self.assertEqual(set(offline), {'name', 'runs-on', 'timeout-minutes', 'steps'})
        self.assertEqual(set(probe), {
            'name', 'needs', 'if', 'runs-on', 'timeout-minutes', 'environment', 'steps'})
        self.assertEqual(probe['needs'], 'offline')
        self.assertEqual(probe['environment'], 'test-api-readonly-access')
        for job, timeout in [(offline, 3), (probe, 2)]:
            self.assertEqual(job['runs-on'], 'ubuntu-latest')
            self.assertEqual(job['timeout-minutes'], timeout)
            self.assertEqual(len(job['steps']), 2)
            self.assertEqual(job['steps'][0], {
                'uses': 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
                'with': {'ref': '${{ github.sha }}', 'persist-credentials': False}})
        self.assertEqual(offline['steps'][1], {
            'run': "python3 -B -m unittest discover -s tests -p 'test_*.py'"})
        self.assertEqual(probe['steps'][1], {
            'name': 'Verify fixed public policy and host pin, then observe only fixed TEST files, route literals and service states',
            'env': {
                'TEST_API_ADMIN_SSH_KEY': '${{ secrets.TEST_API_ADMIN_SSH_KEY }}',
                'TEST_API_KNOWN_HOSTS': '${{ vars.TEST_API_KNOWN_HOSTS }}'},
            'run': 'python3 -I -B scripts/test_api_installed_route_readonly.py'})

    def test_existing_offline_ci_is_triggered_for_all_three_new_paths(self):
        source = (ROOT / '.github/workflows/hostinger-readonly-preflight.yml').read_text(encoding='utf-8')
        filters = [ast.literal_eval(line.split('paths:', 1)[1].strip())
                   for line in source.splitlines() if line.strip().startswith('paths:')]
        self.assertEqual(len(filters), 2)
        for paths in filters:
            for path in [
                '.github/workflows/test-api-installed-route-readonly.yml',
                'scripts/test_api_installed_route_readonly.py',
                'tests/test_test_api_installed_route_readonly.py',
            ]:
                with self.subTest(path=path):
                    self.assertEqual(paths.count(path), 1)



if __name__=='__main__': unittest.main()
