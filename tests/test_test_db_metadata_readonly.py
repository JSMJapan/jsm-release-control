"""Offline #2760 scope barrier. No server, SQL or private credentials."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test_db_metadata_readonly.py'


class DbScopeBarrierTests(unittest.TestCase):
    def test_unapproved_local_context_returns_closed_blocked_receipt_not_an_execution(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT)],
            env={'PATH': os.defpath, 'LANG': 'C'}, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        value = json.loads(result.stdout)
        self.assertEqual(value['status'], 'BLOCKED')
        self.assertEqual(value['sql'], 'NOT_ATTEMPTED')
        self.assertEqual(value['reason'], 'OWNER_MANUAL_MAIN_TEST_DB_WORKFLOW_REQUIRED')
        self.assertEqual(result.stderr, b'')


class ScopePolicyTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'Missing non-admitting TEST DB scope barrier')
        spec = importlib.util.spec_from_file_location('db_scope_2760', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)

    def context(self):
        return dict(GITHUB_REPOSITORY='JSMJapan/jsm-release-control', GITHUB_ACTOR='JSMJapan',
            GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
            GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
            GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
            GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_RUN_ID='123456789',
            GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/test-db-metadata-readonly.yml@refs/heads/main')

    def api(self, mutate=None, fail_at=None):
        rows = [dict(full_name='JSMJapan/jsm-release-control', private=False),
            dict(name='test-api-readonly-access', can_admins_bypass=False,
                protection_rules=[dict(type='required_reviewers', prevent_self_review=False,
                    reviewers=[dict(type='User', reviewer=dict(login='JSMJapan', id=327623967))])],
                deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True)),
            dict(total_count=1, branch_policies=[dict(name='main', type='branch')])]
        if mutate:
            mutate(rows)
        calls = []
        class Api:
            def get_json(inner, path):
                calls.append(path)
                if len(calls) - 1 == fail_at:
                    raise RuntimeError('PRIVATE mysql://user:password@production/customer')
                return copy.deepcopy(rows[len(calls) - 1])
        return Api(), calls

    def test_verified_github_policy_still_cannot_admit_a_database_or_access_credentials(self):
        class SecretTrap(dict):
            def get(inner, key, default=None):
                if key.startswith('TEST_') or 'SECRET' in key or 'PASSWORD' in key:
                    raise AssertionError('Credential access before target admission')
                return super().get(key, default)
        api, calls = self.api()
        with patch('socket.create_connection', side_effect=AssertionError('DB/network connection attempted')), \
                patch('subprocess.Popen', side_effect=AssertionError('Remote/process attempted')):
            value = self.m.policy_gate(api, SecretTrap(self.context()))
        self.assertEqual(calls, ['/repos/JSMJapan/jsm-release-control',
            '/repos/JSMJapan/jsm-release-control/environments/test-api-readonly-access',
            '/repos/JSMJapan/jsm-release-control/environments/test-api-readonly-access/deployment-branch-policies'])
        self.assertEqual(value['status'], 'BLOCKED')
        self.assertEqual(value['scope_state'], 'PREPARED')
        self.assertEqual(value['db_proof'], 'BLOCKED_TARGET_ADMISSION')
        self.assertEqual(value['reason'], 'INDEPENDENT_TARGET_ADMISSION_REQUIRED')
        self.assertEqual(value['sql'], 'NOT_ATTEMPTED')
        self.assertEqual(value['database_credentials'], 'NOT_ACCESSED')
        self.assertTrue(value['protected_policy_verified'])
        self.assertEqual(value['db_target_identity'], 'NOT_ESTABLISHED')
        self.assertEqual(value['effective_api_binding'], 'NOT_ESTABLISHED')
        self.assertEqual(value['diagnostic_db_principal'], 'NOT_OBSERVED')
        self.assertEqual(value['application_db_principal'], 'NOT_OBSERVED')
        for field in ('db_grants', 'db_data_provenance', 'db_isolation', 'egress_isolation'):
            self.assertEqual(value[field], 'NOT_ESTABLISHED')

    def test_forged_env_baseline_sql_and_private_target_cannot_promote_scope_to_db_proof(self):
        env = self.context()
        env.update(TEST_DB_BASELINE='{"approved":true,"signature":"PRIVATE"}',
            TEST_DB_DSN='mysql:host=production;dbname=PRIVATE', TEST_DB_SQL='SELECT * FROM customer',
            TEST_API_ADMIN_SSH_KEY='PRIVATE', TEST_API_KNOWN_HOSTS='PRIVATE')
        api, _ = self.api()
        result = self.m.policy_gate(api, env)
        self.assertEqual(result['db_proof'], 'BLOCKED_TARGET_ADMISSION')
        self.assertEqual(result['sql'], 'NOT_ATTEMPTED')
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('customer', json.dumps(result))

    def test_owner_main_first_attempt_and_exact_workflow_are_required_before_policy_gets(self):
        changes = dict(GITHUB_REPOSITORY='other/repo', GITHUB_ACTOR='other',
            GITHUB_TRIGGERING_ACTOR='other', GITHUB_REF='refs/heads/feature',
            GITHUB_EVENT_NAME='push', GITHUB_RUN_ATTEMPT='2',
            GITHUB_SERVER_URL='https://evil.invalid', GITHUB_API_URL='https://evil.invalid',
            GITHUB_SHA='PRIVATE', GITHUB_WORKFLOW_SHA='b' * 40, GITHUB_RUN_ID='PRIVATE',
            GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/test-api-installed-route-readonly.yml@refs/heads/main')
        for key, value in changes.items():
            with self.subTest(key=key):
                env = self.context(); env[key] = value
                api, calls = self.api()
                with self.assertRaises(self.m.Refused):
                    self.m.collect(api, env)
                self.assertEqual(calls, [])

    def test_policy_drift_refuses_without_admitting_target(self):
        mutators = [lambda r: r[0].update(private=True),
            lambda r: r[0].update(full_name='other/repo'),
            lambda r: r[1].update(name='apache-parity-bootstrap'),
            lambda r: r[1].update(can_admins_bypass=True),
            lambda r: r[1]['protection_rules'][0]['reviewers'][0]['reviewer'].update(id=1),
            lambda r: r[1]['protection_rules'][0]['reviewers'][0]['reviewer'].update(login='other'),
            lambda r: r[2]['branch_policies'][0].update(name='*'),
            lambda r: r[2]['branch_policies'][0].update(type='tag'),
            lambda r: r[2].update(total_count=2)]
        for mutate in mutators:
            with self.subTest(mutate=mutate):
                api, _ = self.api(mutate)
                with self.assertRaises(self.m.Refused):
                    self.m.collect(api, self.context())

    def test_policy_get_failure_keeps_error_details_private(self):
        for index in range(3):
            api, _ = self.api(fail_at=index)
            with self.assertRaises(Exception) as raised:
                self.m.collect(api, self.context())
            self.assertEqual(self.m.safe_reason(raised.exception), 'TEST_DB_SCOPE_REJECTED')

    def test_misleading_policy_fields_and_source_records_do_not_become_evidence(self):
        def mutate(rows):
            for row in rows:
                row.update(db_isolation='PASS', synthetic_seed=True, active_api_binding=True,
                    baseline_signature='PRIVATE', db_dsn='PRIVATE')
        api, _ = self.api(mutate)
        value = self.m.policy_gate(api, self.context())
        self.assertEqual(value['db_isolation'], 'NOT_ESTABLISHED')
        self.assertEqual(value['sql'], 'NOT_ATTEMPTED')
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_arbitrary_cli_input_is_rejected_without_echoing_it(self):
        for argument in ('--sql=SELECT PRIVATE', '--dsn=mysql:PRIVATE', '/PRIVATE/config.php'):
            result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), argument],
                env={'PATH': os.defpath, 'LANG': 'C'}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)['reason'], 'NO_ARGUMENTS_OR_INPUTS_ACCEPTED')
            self.assertNotIn(b'PRIVATE', result.stdout + result.stderr)

    def test_closed_receipt_does_not_accept_raw_details_or_non_admitted_facts(self):
        value = self.m.blocked_receipt('INDEPENDENT_TARGET_ADMISSION_REQUIRED', policy_verified=True)
        expected = {'receipt_version', 'status', 'scope_state', 'db_proof', 'reason',
            'target_resource', 'target_domain', 'protected_policy_verified', 'admitted_baseline',
            'effective_api_binding', 'db_target_identity', 'diagnostic_db_principal',
            'application_db_principal', 'db_grants', 'db_data_provenance', 'db_isolation',
            'egress_isolation', 'sql', 'database_credentials', 'ssh', 'application_execution',
            'provider_requests', 'database_writes', 'missing_evidence', 'os_observation',
            'sudo_root_identity', 'test_disk_identity'}
        self.assertEqual(set(value), expected)
        self.assertIsNone(value['admitted_baseline'])
        self.assertLessEqual(len(json.dumps(value).encode('ascii')), 2048)
        self.assertGreater(len(value['missing_evidence']), 0)
        self.assertEqual(self.m.safe_reason(RuntimeError('PRIVATE')), 'TEST_DB_SCOPE_REJECTED')
        self.assertEqual(self.m.safe_reason(self.m.Refused('PRIVATE')), 'TEST_DB_SCOPE_REJECTED')


class TransportTests(unittest.TestCase):
    setUp=ScopePolicyTests.setUp
    context=ScopePolicyTests.context
    api=ScopePolicyTests.api
    def fixture(self, nonce):
        child = dict(version='jsm-test-db-os-2760-v1', nonce=nonce, euid=0,
            observation_state='OBSERVED',
            processes=[dict(id=r,state='observed',exe_matches=True,namespace_matches=True,stable=True)
                for r in ('apache','php','mysql')],
            sockets=[dict(id=r,state='observed',is_socket=True,kernel_listener=True,owned_by_service_mainpid=True)
                for r in ('php','mysql')],
            datadir=dict(state='observed',is_directory=True,filesystem='local_block',device_matches=True),
            effective_api_binding='NOT_ESTABLISHED',test_disk_identity='NOT_ESTABLISHED',
            db_proof='BLOCKED_TARGET_ADMISSION',sql='NOT_ATTEMPTED')
        return dict(version='jsm-test-installed-route-outer-v2',nonce=nonce,principal='marinagurina',
            euid=1001,root_diagnostic=child)

    def test_valid_os_observation_still_cannot_admit_sql_or_database_identity(self):
        nonce='b'*32
        result=self.m.project_remote(json.dumps(self.fixture(nonce)).encode('ascii'),nonce)
        self.assertEqual(result['os_observation']['observation_state'],'OBSERVED')
        self.assertTrue(result['sudo_root_identity'])
        self.assertEqual(result['sql'],'NOT_ATTEMPTED')
        self.assertEqual(result['db_proof'],'BLOCKED_TARGET_ADMISSION')
        self.assertEqual(result['effective_api_binding'],'NOT_ESTABLISHED')

    def test_malformed_duplicate_private_or_forged_observation_never_escapes(self):
        nonce='b'*32
        cases=[]
        for change in ('extra','boolpid','nonce','principal','childextra','root','claims','state','order'):
            row=self.fixture(nonce);child=row['root_diagnostic']
            if change=='extra':row['PRIVATE']='PRIVATE'
            elif change=='boolpid':row['euid']=True
            elif change=='nonce':row['nonce']='c'*32
            elif change=='principal':row['principal']='root'
            elif change=='childextra':child['raw_fd']='PRIVATE'
            elif change=='root':child['euid']=1001
            elif change=='claims':child['effective_api_binding']='PROVED'
            elif change=='state':child['processes'][0]['stable']='PRIVATE'
            else:child['sockets'].reverse()
            cases.append(json.dumps(row).encode())
        cases.extend((b'{"nonce":1,"nonce":2}',b'{"x":NaN}',b'x'*16385))
        for raw in cases:
            try:result=self.m.project_remote(raw,nonce)
            except self.m.Refused:continue
            self.assertIsNone(result['os_observation'])
            self.assertNotIn('PRIVATE',json.dumps(result))

    def test_fixed_transport_pin_flags_and_caps_with_private_synthetic_key(self):
        import hashlib
        nonce='b'*32;env=self.context();known='synthetic-pinned-key\n'
        env.update(TEST_API_ADMIN_SSH_KEY='synthetic-private-fixture',TEST_API_KNOWN_HOSTS=known)
        api,_=self.api();seen=[];identities=[]
        def bounded(command,**kwargs):
            seen.append(command)
            self.assertEqual(command[-6:],['marinagurina@34.104.157.63','/usr/bin/python3','-I','-B','-S','-'])
            self.assertIn('IdentityAgent=none',command)
            self.assertIn('StrictHostKeyChecking=yes',command)
            self.assertIn('ClearAllForwardings=yes',command)
            self.assertIn('PasswordAuthentication=no',command)
            self.assertEqual(kwargs['limit'],16384)
            self.assertLessEqual(kwargs['timeout'],15)
            self.assertIn(b'/usr/bin/sudo',kwargs['data'])
            self.assertIn(b'--kill-after=1',kwargs['data'])
            self.assertNotIn(b'mysql.connector',kwargs['data'])
            identity=Path(command[command.index('-i')+1])
            identities.append(identity)
            self.assertEqual(identity.stat().st_mode&0o777,0o600)
            self.assertEqual(identity.parent.stat().st_mode&0o777,0o700)
            self.assertEqual(identity.read_text(),'synthetic-private-fixture\n')
            return 0,json.dumps(self.fixture(nonce)).encode('ascii')
        with patch.object(self.m,'PIN_SHA256',hashlib.sha256(known.encode()).hexdigest()), \
                patch.object(self.m.secrets,'token_hex',return_value=nonce), \
                patch.object(self.m,'_bounded',side_effect=bounded), \
                patch('socket.create_connection',side_effect=AssertionError('No DB/network in offline fixture')):
            result=self.m.collect(api,env)
        self.assertEqual(len(seen),1)
        self.assertFalse(identities[0].exists())
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['ssh'],'OBSERVED')
        self.assertEqual(result['database_credentials'],'NOT_ACCESSED')

    def test_bad_pin_or_missing_key_prevents_transport_and_redacts_failures(self):
        for fields in ({},{'TEST_API_ADMIN_SSH_KEY':'PRIVATE','TEST_API_KNOWN_HOSTS':'PRIVATE'}):
            env=self.context();env.update(fields);api,_=self.api()
            with patch.object(self.m,'_bounded',side_effect=AssertionError('No transport before pin')):
                with self.assertRaises(self.m.Refused):self.m.collect(api,env)

    def test_remote_capsule_reuses_original_wrapper_without_changing_original_bytes(self):
        import hashlib
        from test_api_installed_route_readonly import remote_program
        expected='e56a18831efd18b31b18d9d0f7ad4c938bae241bd0b21d5a53afe4c95b2f7e65'
        self.assertEqual(hashlib.sha256(remote_program('b'*32)).hexdigest(),expected)
        code=self.m.remote_program('b'*32)
        compile(code.decode('ascii'),'<fixed-capsule>','exec')
        for forbidden in (b'/environ',b'/cmdline',b'getenv',b'SELECT ',b'--execute'):
            self.assertNotIn(forbidden,code)

    def test_manual_workflow_has_no_inputs_and_preserves_owner_environment_and_checkout(self):
        workflow=json.loads((ROOT/'.github/workflows/test-db-metadata-readonly.yml').read_text())
        self.assertEqual(workflow['on'],{'workflow_dispatch':{}})
        self.assertEqual(workflow['permissions'],{'contents':'read'})
        self.assertIs(workflow['concurrency']['cancel-in-progress'],False)
        probe=workflow['jobs']['probe']
        self.assertEqual(probe['environment'],'test-api-readonly-access')
        self.assertEqual(probe['needs'],'offline')
        for guard in ("github.actor == 'JSMJapan'","github.triggering_actor == 'JSMJapan'",
                "github.ref == 'refs/heads/main'",'github.run_attempt == 1',
                'github.event.repository.private == false'):
            self.assertIn(guard,probe['if'])
        self.assertEqual(probe['steps'][0]['uses'],'actions/checkout@11d5960a326750d5838078e36cf38b85af677262')
        self.assertEqual(probe['steps'][0]['with'],{'ref':'${{ github.sha }}','persist-credentials':False})
        step=probe['steps'][1]
        self.assertEqual(set(step['env']),{'TEST_API_ADMIN_SSH_KEY','TEST_API_KNOWN_HOSTS'})
        self.assertEqual(step['run'],'python3 -I -B scripts/test_db_metadata_readonly.py')


if __name__ == '__main__':
    unittest.main()
