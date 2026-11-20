import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/prod_front_sha_readonly.py'
NONCE = 'b' * 32
KNOWN = 'test-only-host-pin\n'
PATHS = ('config/articleSeo.js', 'src/pages/MainFlow/BlogArticle/index.tsx',
         'src/helpers/blogArticleSchema.js')
EXPECTED = ('8b6576b90cb6f1a3475805f976b15e906009c5652bff0f35db0747c23eab9a4b',
            '725ba79b928ba95331fc8cd42e53b3bc32a01336900fe658e48392f32999a447',
            'b887aac742a18da0e9c9714d1031c027ca56d17adfe1ff484e4f03522071ca40')


class FrontShaTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'Missing three-fixed-file metadata reader')
        spec = importlib.util.spec_from_file_location('prod_front_sha_readonly', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def context(self):
        return dict(GITHUB_REPOSITORY='JSMJapan/jsm-release-control', GITHUB_ACTOR='JSMJapan',
                    GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
                    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_SHA='a'*40, GITHUB_WORKFLOW_SHA='a'*40, GITHUB_RUN_ID='123',
                    GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/prod-front-sha-readonly.yml@refs/heads/main',
                    APACHE_BOOTSTRAP_ADMIN_SSH_KEY='dummy-key', APACHE_BOOTSTRAP_KNOWN_HOSTS=KNOWN)

    def api(self, protected=True):
        fixtures = [dict(full_name='JSMJapan/jsm-release-control', private=False),
                    dict(can_admins_bypass=False, protection_rules=[dict(type='required_reviewers',
                         prevent_self_review=False, reviewers=[dict(type='User',reviewer=dict(login='JSMJapan'))])] if protected else [],
                         deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True)),
                    dict(total_count=1, branch_policies=[dict(name='main',type='branch')])]
        calls=[]
        class Api:
            def get_json(inner, host, path, token=None):
                calls.append((host,path,token))
                return fixtures[len(calls)-1]
        return Api(), calls

    def payload(self):
        return dict(version='jsm-prod-front-sha-v1',nonce=NONCE,euid=0,writes_performed=False,
                    files=[dict(path=p,type='regular',sha256=h) for p,h in zip(PATHS,EXPECTED)])

    def capsule(self):
        namespace={'__name__':'fixture_only'}
        exec(compile(self.module.remote_program(NONCE),'<fixed-reader>','exec'), namespace)
        return namespace

    def test_remote_reads_three_files_without_source_output(self):
        ns=self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            for p,data in zip(PATHS,(b'abc',b'',b'hello\n')):
                f=Path(folder)/p; f.parent.mkdir(parents=True,exist_ok=True); f.write_bytes(data)
            ns['BASE']=str(Path(folder).resolve())
            # Linux O_NOATIME is mandatory in production; on macOS remove only
            # that platform flag in this filesystem fixture, never in the CLI.
            real_open=os.open
            def local_open(path, flags, *a, **kw):
                return real_open(path, flags & ~0x40000, *a, **kw)
            with patch.object(os,'open',side_effect=local_open):
                rows=ns['read_files']()
            self.assertEqual([r['path'] for r in rows],list(PATHS))
            self.assertEqual([r['type'] for r in rows],['regular']*3)
            self.assertEqual([r['sha256'] for r in rows],[
                'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03'])
            self.assertNotIn('hello',json.dumps(rows))
            self.assertEqual(sorted(str(f.relative_to(folder)) for f in Path(folder).rglob('*') if f.is_file()),sorted(PATHS))

    def test_missing_symlink_hardlink_directory_and_oversize_refuse_file_bytes(self):
        for case in ('missing','symlink','parent_symlink','hardlink','directory','oversize'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                ns=self.capsule(); ns['BASE']=str(Path(folder).resolve())
                for p in PATHS:
                    f=Path(folder)/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'PRIVATE_SOURCE')
                f=Path(folder)/PATHS[0]
                if case=='missing': f.unlink()
                elif case=='symlink': f.unlink();f.symlink_to(Path(folder)/PATHS[1])
                elif case=='parent_symlink':
                    f.unlink();f.parent.rmdir();f.parent.symlink_to(Path(folder)/'src')
                elif case=='hardlink': f.unlink();os.link(Path(folder)/PATHS[1],f)
                elif case=='directory': f.unlink();f.mkdir()
                elif case=='oversize': f.write_bytes(b'x'*(1024*1024+1))
                real_open=os.open
                with patch.object(os,'open',side_effect=lambda path,flags,*a,**kw:real_open(path,flags & ~0x40000,*a,**kw)):
                    rows=ns['read_files']()
                self.assertNotEqual(rows[0]['type'],'regular')
                self.assertIsNone(rows[0]['sha256'])
                self.assertNotIn('PRIVATE_SOURCE',json.dumps(rows))

    def test_closed_nonce_schema_and_expected_hash_gate(self):
        receipt=self.module.project_remote(json.dumps(self.payload()).encode(),NONCE)
        self.assertEqual(receipt['status'],'PROD_FRONT_EXPECTED_FILES_MATCH')
        self.assertEqual(receipt['files'][0]['matches_expected'],True)
        for case in ('drift','missing','extra','nonce','uid','duplicate','banner','oversize','path'):
            v=self.payload()
            if case=='drift': v['files'][0]['sha256']='c'*64
            if case=='missing': v['files'][0].update(type='missing',sha256=None)
            if case=='extra': v['source']='PRIVATE_BODY'
            if case=='nonce': v['nonce']='c'*32
            if case=='uid': v['euid']=1
            if case=='path': v['files'][0]['path']='.env'
            raw=json.dumps(v).encode()
            if case=='duplicate': raw=raw.replace(b'"euid": 0',b'"euid": 1, "euid": 0')
            if case=='banner': raw=b'PRIVATE_BANNER\n'+raw
            if case=='oversize': raw=b'x'*5000
            if case in ('drift','missing'):
                value=self.module.project_remote(raw,NONCE)
                self.assertEqual(value['status'],'BLOCKED')
                self.assertFalse(value['files'][0]['matches_expected'])
            else:
                with self.assertRaises(self.module.Refused) as error:self.module.project_remote(raw,NONCE)
                self.assertNotIn('PRIVATE',str(error.exception))

    def test_parent_path_replacement_during_read_is_not_a_current_file_proof(self):
        ns=self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            for p in PATHS:
                f=Path(folder)/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'abc')
            ns['BASE']=str(Path(folder).resolve())
            real_read,real_open=os.read,os.open
            changed=[]
            def replace_parent(fd,size):
                data=real_read(fd,size)
                if not changed:
                    (Path(folder)/'config').rename(Path(folder)/'old-config')
                    (Path(folder)/'config').mkdir()
                    (Path(folder)/PATHS[0]).write_bytes(b'different')
                    changed.append(True)
                return data
            with patch.object(os,'read',side_effect=replace_parent),patch.object(os,'open',side_effect=lambda path,flags,*a,**kw:real_open(path,flags & ~0x40000,*a,**kw)):
                row=ns['read_files']()[0]
            self.assertEqual(row['type'],'unstable')
            self.assertIsNone(row['sha256'])

    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux O_NOATIME syscall proof; macOS fixtures mask only this flag')
    def test_linux_read_preserves_file_access_times_without_masking_open_flags(self):
        ns=self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            before={}
            for p in PATHS:
                f=Path(folder)/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'abc')
                os.utime(f,ns=(1000000000000000000,1000000000000000000))
                before[p]=f.stat().st_atime_ns
            ns['BASE']=str(Path(folder).resolve())
            self.assertEqual([r['type'] for r in ns['read_files']()],['regular']*3)
            self.assertEqual({p:(Path(folder)/p).stat().st_atime_ns for p in PATHS},before)

    def test_unprivileged_linux_fixture_needs_no_directory_noatime_capability(self):
        ns=self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            for p in PATHS:
                f=Path(folder)/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'abc')
            ns['BASE']=str(Path(folder).resolve())
            real_open=os.open;file_opens=[]
            def linux_open(path,flags,*a,**kw):
                if flags & os.O_DIRECTORY:
                    if flags & 0x40000:raise PermissionError('non-owner root directory NOATIME')
                else:
                    file_opens.append(path)
                    self.assertTrue(flags & 0x40000,'source file access time must stay protected')
                return real_open(path,flags & ~0x40000,*a,**kw)
            with patch.object(os,'open',side_effect=linux_open):
                self.assertEqual([r['type'] for r in ns['read_files']()],['regular']*3)
            self.assertEqual(len(file_opens),3)

    def test_context_policy_key_and_pin_fail_before_any_transport(self):
        for case in ('actor','trigger','workflow','sha','ref','event','attempt','policy','key','pin'):
            env=self.context();api,_=self.api(case!='policy')
            names={'actor':'GITHUB_ACTOR','trigger':'GITHUB_TRIGGERING_ACTOR','workflow':'GITHUB_WORKFLOW_REF',
                   'sha':'GITHUB_WORKFLOW_SHA','ref':'GITHUB_REF','event':'GITHUB_EVENT_NAME','attempt':'GITHUB_RUN_ATTEMPT',
                   'key':'APACHE_BOOTSTRAP_ADMIN_SSH_KEY','pin':'APACHE_BOOTSTRAP_KNOWN_HOSTS'}
            if case!='policy':env[names[case]]=''
            with patch.object(self.module,'PIN_SHA256',hashlib.sha256(KNOWN.encode()).hexdigest()),patch.object(self.module,'bounded_ssh') as transport:
                with self.assertRaises(self.module.Refused):self.module.collect(api,env)
                transport.assert_not_called()

    def test_transport_exact_destination_keyonly_no_forwarding_and_temp_cleanup(self):
        api,calls=self.api();folders=[]
        def transport(command,program):
            self.assertEqual(command[-5:],['root@187.77.118.50','/usr/bin/python3','-I','-B','-'])
            self.assertEqual(command[command.index('-p')+1],'17177')
            for option in ('StrictHostKeyChecking=yes','IdentityAgent=none','BatchMode=yes','ClearAllForwardings=yes','PreferredAuthentications=publickey','PasswordAuthentication=no','KbdInteractiveAuthentication=no'):
                self.assertIn(option,command)
            identity=Path(command[command.index('-i')+1]);folders.append(identity.parent)
            self.assertEqual(identity.stat().st_mode & 0o777,0o600)
            self.assertEqual(identity.parent.stat().st_mode & 0o777,0o700)
            return json.dumps(self.payload()).encode()
        with patch.object(self.module,'PIN_SHA256',hashlib.sha256(KNOWN.encode()).hexdigest()),patch.object(self.module.secrets,'token_hex',return_value=NONCE),patch.object(self.module,'bounded_ssh',side_effect=transport):
            value=self.module.collect(api,self.context())
        self.assertEqual(value['status'],'PROD_FRONT_EXPECTED_FILES_MATCH')
        self.assertTrue(all(not f.exists() for f in folders))
        self.assertEqual(len(calls),3)
        self.assertNotIn('dummy-key',json.dumps(value))

    def test_forced_command_denial_and_unknown_exceptions_never_leak_stderr(self):
        with self.assertRaisesRegex(self.module.Refused,'SSH_KEY_LOAD_OR_AUTH_OR_COMMAND_FAILED') as denied:
            self.module.bounded_ssh([sys.executable,'-B','-c',
                'import sys;sys.stdout.write("PRIVATE_STDOUT");sys.stderr.write("PRIVATE_STDERR");sys.exit(13)'],b'')
        self.assertNotIn('PRIVATE',str(denied.exception))
        output=io.StringIO()
        with patch.object(self.module,'collect',side_effect=RuntimeError('PRIVATE_STDERR PRIVATE_KEY')),patch.object(self.module.sys,'argv',['probe.py']),contextlib.redirect_stdout(output):
            self.assertEqual(self.module.main(),1)
        self.assertNotIn('PRIVATE',output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'],'BLOCKED')

    def test_main_drift_is_nonzero_with_safe_metadata_and_no_release_claim(self):
        p=self.payload();p['files'][0]['sha256']='c'*64
        result=self.module.project_remote(json.dumps(p).encode(),NONCE)
        output=io.StringIO()
        with patch.object(self.module,'collect',return_value=result),patch.object(self.module.sys,'argv',['probe.py']),contextlib.redirect_stdout(output):
            self.assertEqual(self.module.main(),1)
        receipt=json.loads(output.getvalue())
        self.assertEqual(receipt['status'],'BLOCKED')
        self.assertIsNone(receipt['installed_release_sha'])
        self.assertEqual(receipt['deploy_acceptance'],'NOT_ESTABLISHED')

    def test_remote_file_change_during_read_is_rejected(self):
        ns=self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            for p in PATHS:
                f=Path(folder)/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'abc')
            ns['BASE']=str(Path(folder).resolve())
            real_read,real_open=os.read,os.open;changed=[]
            def change_file(fd,size):
                data=real_read(fd,size)
                if not changed:
                    (Path(folder)/PATHS[0]).write_bytes(b'changed-source')
                    changed.append(True)
                return data
            with patch.object(os,'read',side_effect=change_file),patch.object(os,'open',side_effect=lambda path,flags,*a,**kw:real_open(path,flags & ~0x40000,*a,**kw)):
                row=ns['read_files']()[0]
            self.assertEqual(row['type'],'unstable')
            self.assertIsNone(row['sha256'])


if __name__=='__main__':unittest.main()
