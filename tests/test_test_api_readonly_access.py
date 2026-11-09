"""Offline boundary tests. All identities, pins and process outputs are synthetic."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test_api_readonly_access.py'
KNOWN = '34.104.157.63 ssh-ed25519 SYNTHETIC_PUBLIC_HOST_KEY'
NONCE = 'b' * 32


class TestAccessProbe(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'Missing fixed TEST identity probe')
        spec = importlib.util.spec_from_file_location('test_api_readonly_access', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def context(self):
        return dict(GITHUB_REPOSITORY='JSMJapan/jsm-release-control', GITHUB_ACTOR='JSMJapan',
                    GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
                    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_RUN_ID='123456789',
                    GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/test-api-readonly-access.yml@refs/heads/main',
                    TEST_API_ADMIN_SSH_KEY='SYNTHETIC_PRIVATE_VALUE', TEST_API_KNOWN_HOSTS=KNOWN)

    def policy(self):
        return [dict(full_name='JSMJapan/jsm-release-control', private=False),
                dict(name='test-api-readonly-access', can_admins_bypass=False,
                     protection_rules=[dict(type='required_reviewers', prevent_self_review=False,
                         reviewers=[dict(type='User', reviewer=dict(login='JSMJapan', id=327623967))])],
                     deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True)),
                dict(total_count=1, branch_policies=[dict(name='main', type='branch')])]

    def api(self, fixtures=None):
        calls = []
        rows = self.policy() if fixtures is None else fixtures
        class Api:
            def get_json(inner, path):
                calls.append(path)
                return copy.deepcopy(rows[len(calls) - 1])
        return Api(), calls

    def payload(self, *, child_euid=0):
        child = None if child_euid is None else dict(version='jsm-test-sudo-identity-v1', nonce=NONCE, euid=child_euid)
        return dict(version='jsm-test-access-v1', nonce=NONCE, principal='marinagurina', euid=1000,
                    sudo_identity=child)

    def collect(self, transport, env=None, fixtures=None):
        api, calls = self.api(fixtures)
        with patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                patch.object(self.module.secrets, 'token_hex', return_value=NONCE), \
                patch.object(self.module, '_bounded', side_effect=transport):
            result = self.module.collect(api, self.context() if env is None else env)
        return result, calls

    def test_invocation_scope_is_checked_before_http_or_key_access(self):
        for name, bad in [('GITHUB_REPOSITORY', 'other/repo'), ('GITHUB_ACTOR', 'other'),
                          ('GITHUB_TRIGGERING_ACTOR', 'other'), ('GITHUB_REF', 'refs/heads/other'),
                          ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_RUN_ATTEMPT', '2'),
                          ('GITHUB_SHA', 'bad'), ('GITHUB_WORKFLOW_SHA', 'c' * 40),
                          ('GITHUB_SERVER_URL', 'https://elsewhere'), ('GITHUB_API_URL', 'https://elsewhere'),
                          ('GITHUB_RUN_ID', 1), ('GITHUB_WORKFLOW_REF', 'other-workflow')]:
            class Guard(dict):
                def get(inner, key, default=None):
                    if key.startswith('TEST_API_'): self.fail('credential read before context')
                    return super().get(key, default)
            env = Guard(self.context()); env[name] = bad; api, calls = self.api()
            with self.subTest(name=name), self.assertRaises(self.module.Refused):
                self.module.collect(api, env)
            self.assertEqual(calls, [])

    def test_protection_and_exact_reviewer_id_environment_branch_count_precede_key(self):
        mutations = [lambda p: p[0].update(private=True), lambda p: p[1].update(name='apache-parity-bootstrap'),
                     lambda p: p[1].update(can_admins_bypass=True),
                     lambda p: p[1]['protection_rules'][0].update(prevent_self_review=True),
                     lambda p: p[1]['protection_rules'][0].update(reviewers=[]),
                     lambda p: p[1]['protection_rules'][0]['reviewers'].append(dict(type='User', reviewer=dict(login='other'))),
                     lambda p: p[1]['protection_rules'][0]['reviewers'][0]['reviewer'].update(id=True),
                     lambda p: p[1]['protection_rules'][0]['reviewers'][0]['reviewer'].update(id=327623968),
                     lambda p: p[1]['protection_rules'][0]['reviewers'][0]['reviewer'].update(login='other'),
                     lambda p: p[2].update(total_count=True), lambda p: p[2]['branch_policies'][0].update(name='*'),
                     lambda p: p[2]['branch_policies'].append(dict(name='other', type='branch')),
                     lambda p: p[1].update(protection_rules=None)]
        class Guard(dict):
            def get(inner, key, default=None):
                if key.startswith('TEST_API_'): self.fail('credential read before policy')
                return super().get(key, default)
        for mutate in mutations:
            rows = self.policy(); mutate(rows); api, calls = self.api(rows)
            with self.subTest(policy=rows), self.assertRaises(self.module.Refused):
                self.module.collect(api, Guard(self.context()))
            self.assertEqual(len(calls), 3)

    def test_exact_three_unauthenticated_public_paths_and_no_optional_credentials(self):
        api = self.module.TestPolicyApi()
        self.assertIsNone(api.token)
        self.assertEqual(api.paths, frozenset(['/repos/JSMJapan/jsm-release-control',
            '/repos/JSMJapan/jsm-release-control/environments/test-api-readonly-access',
            '/repos/JSMJapan/jsm-release-control/environments/test-api-readonly-access/deployment-branch-policies']))
        for bad in ['/repos/JSMJapan/jsm-storefront', '/projects/dark-berm-508215-d2', 'https://api.github.com/anything']:
            with self.assertRaises(self.module.Refused): api.get_json(bad)
        with self.assertRaises(TypeError): self.module.TestPolicyApi('SYNTHETIC_TOKEN')

    def test_fixed_ssh_scope_private_files_cleanup_and_no_secret_receipt(self):
        folders = []
        def transport(command, *, data, limit, timeout):
            self.assertEqual(command[:4], ['/usr/bin/ssh', '-F', '/dev/null', '-T'])
            self.assertEqual(command[-6:], ['marinagurina@34.104.157.63', '/usr/bin/python3', '-I', '-B', '-S', '-'])
            self.assertEqual(command[command.index('-p') + 1], '22')
            for option in ['IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes',
                           'BatchMode=yes', 'PreferredAuthentications=publickey', 'PasswordAuthentication=no',
                           'KbdInteractiveAuthentication=no', 'ClearAllForwardings=yes',
                           'GlobalKnownHostsFile=/dev/null', 'ConnectionAttempts=1', 'LogLevel=ERROR']:
                self.assertIn(option, command)
            identity = Path(command[command.index('-i') + 1]); folders.append(identity.parent)
            hosts = Path(next(v.split('=', 1)[1] for v in command if v.startswith('UserKnownHostsFile=')))
            self.assertEqual(identity.read_bytes(), b'SYNTHETIC_PRIVATE_VALUE\n')
            self.assertEqual(hosts.read_bytes(), KNOWN.encode())
            self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
            self.assertEqual(hosts.stat().st_mode & 0o777, 0o600)
            self.assertEqual(identity.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn(NONCE.encode(), data)
            self.assertEqual(limit, 4096); self.assertGreater(timeout, 0); self.assertLessEqual(timeout, 15)
            return 0, json.dumps(self.payload()).encode()
        result, calls = self.collect(transport)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result['status'], 'TEST_ACCESS_IDENTITY_CONFIRMED')
        self.assertTrue(result['ssh_identity']); self.assertTrue(result['sudo_root_identity'])
        self.assertEqual(result['ssh_euid'], 1000)
        self.assertEqual(result['resource'], 'gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713')
        self.assertEqual(result['test_api_acceptance'], 'NOT_ESTABLISHED')
        self.assertNotIn('SYNTHETIC', json.dumps(result))
        self.assertTrue(folders); self.assertTrue(all(not path.exists() for path in folders))

    def test_missing_credential_or_changed_pin_never_starts_process(self):
        for name, value in [('TEST_API_ADMIN_SSH_KEY', ''), ('TEST_API_ADMIN_SSH_KEY', 'x\x00y'),
                            ('TEST_API_ADMIN_SSH_KEY', 'x' * 16385), ('TEST_API_KNOWN_HOSTS', KNOWN + '\n')]:
            env = self.context(); env[name] = value
            with self.assertRaises(self.module.Refused): self.collect(lambda *a, **k: self.fail('process started'), env)

    def test_only_validated_child_euid_distinguishes_false_from_unknown(self):
        for uid, expected in [(0, True), (1000, False), (None, None)]:
            raw = json.dumps(self.payload(child_euid=uid)).encode()
            result = self.module.project_remote(raw, NONCE)
            self.assertTrue(result['ssh_identity']); self.assertEqual(result['ssh_euid'], 1000)
            self.assertIs(result['sudo_root_identity'], expected)
            receipt, _ = self.collect(lambda *a, **k: (0, raw))
            self.assertEqual(receipt['status'], 'TEST_ACCESS_IDENTITY_CONFIRMED' if uid == 0 else 'BLOCKED')
            self.assertIs(receipt['sudo_root_identity'], expected)

    def test_outer_and_child_closed_schema_nonce_types_duplicates_and_ascii(self):
        mutations = [lambda p: p.update(nonce='c' * 32), lambda p: p.update(principal='root'),
                     lambda p: p.update(euid=True), lambda p: p.update(euid=-1), lambda p: p.update(extra='PRIVATE')]
        for mutate in mutations:
            value = self.payload(); mutate(value)
            with self.subTest(value=value), self.assertRaises(self.module.Refused) as failed:
                self.module.project_remote(json.dumps(value).encode(), NONCE)
            self.assertNotIn('PRIVATE', str(failed.exception))
        for raw in [b'PRIVATE_BANNER', b'x' * 4097, b'\xff',
                    json.dumps(self.payload()).replace('"euid": 1000', '"euid": 1000, "euid": 1000').encode()]:
            with self.assertRaises(self.module.Refused): self.module.project_remote(raw, NONCE)
        for bad in ['', 'B' * 32, 'x; print(1)', None]:
            with self.assertRaises(self.module.Refused): self.module.remote_program(bad)
            with self.assertRaises(self.module.Refused): self.module.project_remote(b'{}', bad)

    def test_invalid_nested_child_preserves_independently_verified_outer_identity(self):
        mutations = [lambda p: p['sudo_identity'].update(extra='PRIVATE'),
                     lambda p: p['sudo_identity'].update(nonce='c' * 32),
                     lambda p: p['sudo_identity'].update(version='other'),
                     lambda p: p['sudo_identity'].update(euid=True),
                     lambda p: p['sudo_identity'].update(euid=1.0),
                     lambda p: p.update(sudo_identity=False)]
        for mutate in mutations:
            value = self.payload(); mutate(value); raw = json.dumps(value).encode()
            with self.subTest(value=value):
                result = self.module.project_remote(raw, NONCE)
                self.assertTrue(result['ssh_identity']); self.assertEqual(result['ssh_euid'], 1000)
                self.assertIsNone(result['sudo_root_identity'])
                receipt, _ = self.collect(lambda *a, **k: (0, raw))
                self.assertEqual(receipt['status'], 'BLOCKED'); self.assertTrue(receipt['ssh_identity'])
                self.assertNotIn('PRIVATE', json.dumps(receipt))

    def execute_remote(self, child_raw, code=0, *, failure=None, delay=0):
        """Execute the actual constant outer program; replace only external child exec."""
        processes = []
        real_popen = subprocess.Popen
        def fake_popen(command, **kwargs):
            self.assertEqual(command[:9], ['/usr/bin/sudo', '-n', '/usr/bin/timeout', '--signal=TERM',
                '--kill-after=1', '4', '/usr/bin/python3', '-I', '-B'])
            self.assertEqual(command[9:11], ['-S', '-c'])
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertTrue(kwargs['start_new_session'])
            # The root program itself is exercised with synthetic euid, never sudo.
            child_out = io.StringIO()
            with patch.object(os, 'geteuid', return_value=0), contextlib.redirect_stdout(child_out):
                exec(compile(command[11], '<synthetic-root-identity>', 'exec'), {})
            self.assertEqual(json.loads(child_out.getvalue()), dict(version='jsm-test-sudo-identity-v1', nonce=NONCE, euid=0))
            if failure: raise failure
            program = 'import sys,time;time.sleep(%r);sys.stdout.buffer.write(%r);sys.stdout.flush();sys.exit(%d)' % (delay, child_raw, code)
            process = real_popen([sys.executable, '-I', '-B', '-S', '-c', program], **kwargs)
            processes.append(process)
            return process
        output = io.StringIO()
        with patch.object(subprocess, 'Popen', side_effect=fake_popen), \
                patch.object(os, 'geteuid', return_value=1000), \
                patch.object(self.module.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_name='marinagurina')), \
                contextlib.redirect_stdout(output):
            exec(compile(self.module.remote_program(NONCE), '<synthetic-outer-identity>', 'exec'), {})
        return json.loads(output.getvalue()), processes

    def test_actual_remote_program_reports_identity_with_fixed_bounded_root_child(self):
        child = json.dumps(dict(version='jsm-test-sudo-identity-v1', nonce=NONCE, euid=0)).encode()
        result, processes = self.execute_remote(child)
        self.assertEqual(result, self.payload())
        self.assertTrue(all(process.poll() is not None for process in processes))
        # Reject accidental application/config/file/network/service operations in either program.
        tree = ast.parse(self.module.remote_program(NONCE))
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imported, {'json', 'os', 'pwd', 'selectors', 'signal', 'subprocess', 'time'})
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in {'open', 'eval', 'exec', 'compile', '__import__'} for node in ast.walk(tree)))

    def test_child_nonzero_malformed_duplicate_oversize_nonascii_start_failure_retain_outer(self):
        valid = json.dumps(dict(version='jsm-test-sudo-identity-v1', nonce=NONCE, euid=0)).encode()
        bad = [valid + b'PRIVATE', b'\xff', b'x' * 513,
               valid.replace(b'"euid": 0', b'"euid": 0, "euid": 0'),
               valid.replace(b'"euid": 0', b'"euid": true'), valid.replace(NONCE.encode(), b'c' * 32)]
        for raw, code, failure in [(v, 0, None) for v in bad] + [(valid, 1, None), (valid, 0, OSError('PRIVATE'))]:
            result, processes = self.execute_remote(raw, code, failure=failure)
            self.assertEqual(result, self.payload(child_euid=None))
            projected = self.module.project_remote(json.dumps(result).encode(), NONCE)
            self.assertTrue(projected['ssh_identity']); self.assertIsNone(projected['sudo_root_identity'])
            self.assertNotIn('PRIVATE', json.dumps(result))
            self.assertTrue(all(process.poll() is not None for process in processes))

    def test_child_shared_five_second_deadline_and_cleanup_without_local_sudo(self):
        started = time.monotonic()
        result, processes = self.execute_remote(b'', delay=6)
        self.assertLess(time.monotonic() - started, 5.6)
        self.assertEqual(result, self.payload(child_euid=None))
        self.assertTrue(all(process.poll() is not None for process in processes))

    def test_ssh_nonzero_or_invalid_outer_evidence_never_claims_identity_and_cleans_files(self):
        for code, raw in [(1, json.dumps(self.payload()).encode()), (0, b'PRIVATE_BAD_JSON')]:
            folders = []
            def transport(command, **kwargs):
                folders.append(Path(command[command.index('-i') + 1]).parent)
                return code, raw
            with self.assertRaises(self.module.Refused): self.collect(transport)
            self.assertTrue(folders); self.assertTrue(all(not path.exists() for path in folders))

    def test_ssh_budget_reserves_cleanup_after_http_and_key_preparation(self):
        now = [100.0]; api, _ = self.api()
        original = api.get_json
        def request(path):
            now[0] += 17
            return original(path)
        api.get_json = request
        def transport(command, *, data, limit, timeout):
            self.assertLessEqual(timeout, 7)
            self.assertGreater(timeout, 0)
            return 0, json.dumps(self.payload()).encode()
        with patch.object(self.module.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                patch.object(self.module.secrets, 'token_hex', return_value=NONCE), \
                patch.object(self.module, '_bounded', side_effect=transport):
            self.assertEqual(self.module.collect(api, self.context())['status'], 'TEST_ACCESS_IDENTITY_CONFIRMED')

    def test_unchanged_bounded_transport_limits_stdin_eof_output_timeout_and_descendant(self):
        from apache_parity_bridge import _bounded, Refused
        self.assertIs(self.module._bounded, _bounded)
        with self.assertRaises(Refused): _bounded([sys.executable, '-c', 'import sys;sys.stdout.write("x"*5000)'], limit=4096)
        # Temporary-file stdin prevents an unconsumed large program from blocking writes.
        start = time.monotonic()
        with self.assertRaises(Refused):
            _bounded([sys.executable, '-c', 'import time;time.sleep(2)'], data=b'x' * 1024 * 1024, timeout=.1)
        self.assertLess(time.monotonic() - start, 1.5)
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'escaped-child'
            program = ('import os,time,pathlib\npid=os.fork()\n'
                       'if pid == 0:\n time.sleep(.5)\n pathlib.Path(%r).write_text("escaped")\n'
                       'time.sleep(5)' % str(marker))
            with self.assertRaises(Refused): _bounded([sys.executable, '-c', program], timeout=.2)
            # A live descendant would perform this harmless delayed write.
            time.sleep(.5)
            self.assertFalse(marker.exists(), 'descendant survived process-group cleanup')

    def test_main_no_arguments_deadline_safe_unknown_receipt_and_partial_exit_status(self):
        for argv, error in [(['probe.py', '--host', 'OTHER'], None),
                            (['probe.py'], RuntimeError('SYNTHETIC_PRIVATE_VALUE PRIVATE_STDERR'))]:
            output = io.StringIO(); alarms = []
            with patch.object(self.module.sys, 'argv', argv), patch.object(self.module.signal, 'signal'), \
                    patch.object(self.module.signal, 'setitimer', side_effect=lambda *args: alarms.append(args)), \
                    patch.object(self.module, 'collect', side_effect=error) as collect, contextlib.redirect_stdout(output):
                self.assertEqual(self.module.main(), 1)
            result = json.loads(output.getvalue())
            self.assertEqual(result['status'], 'BLOCKED'); self.assertIsNone(result['ssh_identity'])
            self.assertIsNone(result['sudo_root_identity']); self.assertNotIn('PRIVATE', output.getvalue())
            if len(argv) > 1: collect.assert_not_called()
            else: self.assertIn((signal.ITIMER_REAL, 60), alarms)
            self.assertEqual(alarms[-1], (signal.ITIMER_REAL, 0))
        output = io.StringIO()
        with patch.object(self.module.sys, 'argv', ['probe.py']), patch.object(self.module.signal, 'signal'), \
                patch.object(self.module.signal, 'setitimer'), \
                patch.object(self.module, 'collect', return_value=dict(status='BLOCKED', ssh_identity=True, sudo_root_identity=None)), \
                contextlib.redirect_stdout(output):
            self.assertEqual(self.module.main(), 1)
        self.assertTrue(json.loads(output.getvalue())['ssh_identity'])

    def run_main(self, api, transport=None):
        output = io.StringIO()
        with patch.object(self.module.sys, 'argv', ['probe.py']), \
                patch.object(self.module.signal, 'signal'), patch.object(self.module.signal, 'setitimer'), \
                patch.object(self.module, 'TestPolicyApi', return_value=api), \
                patch.dict(self.module.os.environ, self.context(), clear=True), \
                patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                patch.object(self.module.secrets, 'token_hex', return_value=NONCE), \
                patch.object(self.module, '_bounded', side_effect=transport), contextlib.redirect_stdout(output):
            code = self.module.main()
        return code, json.loads(output.getvalue())

    def test_policy_http_failures_report_closed_stage_and_safe_shared_reason(self):
        for index, stage in enumerate(('policy_repository', 'policy_environment', 'policy_branches')):
            for error, expected in [(self.module.Refused('GITHUB_RESPONSE_LENGTH_MISMATCH'), 'GITHUB_RESPONSE_LENGTH_MISMATCH'),
                                    (RuntimeError('PRIVATE_BODY PRIVATE_HEADER'), 'TEST_ACCESS_PROBE_REJECTED'),
                                    (self.module.Refused('PRIVATE_BODY'), 'TEST_ACCESS_PROBE_REJECTED')]:
                api, _ = self.api(); original = api.get_json; calls = []
                def request(path):
                    calls.append(path)
                    if len(calls) == index + 1: raise error
                    return original(path)
                api.get_json = request
                code, result = self.run_main(api, lambda *a, **k: self.fail('SSH started after policy failure'))
                self.assertEqual(code, 1); self.assertEqual(result['failure_stage'], stage)
                self.assertEqual(result['reason'], expected)
                self.assertIsNone(result['ssh_identity']); self.assertIsNone(result['sudo_root_identity'])
                self.assertRegex(result['python_version'], r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
                self.assertNotIn('PRIVATE', json.dumps(result))

    def test_ssh_and_remote_failures_report_distinct_closed_stages_without_raw_data(self):
        for result_or_error, stage, reason in [
                (self.module.Refused('PRIVATE_PROCESS_DEADLINE'), 'ssh_transport', 'PRIVATE_PROCESS_DEADLINE'),
                (OSError('PRIVATE_KEY PRIVATE_STDERR'), 'ssh_transport', 'TEST_ACCESS_PROBE_REJECTED'),
                ((1, b'PRIVATE_STDOUT'), 'ssh_transport', 'SSH_TRANSPORT_NOT_CONFIRMED'),
                ((0, b'PRIVATE_STDOUT'), 'remote_identity', 'REMOTE_IDENTITY_SCHEMA_REJECTED')]:
            api, _ = self.api()
            def transport(*args, **kwargs):
                if isinstance(result_or_error, Exception): raise result_or_error
                return result_or_error
            code, result = self.run_main(api, transport)
            self.assertEqual(code, 1); self.assertEqual(result['failure_stage'], stage)
            self.assertEqual(result['reason'], reason)
            self.assertIsNone(result['ssh_identity']); self.assertIsNone(result['sudo_root_identity'])
            self.assertNotIn('PRIVATE_KEY', json.dumps(result)); self.assertNotIn('PRIVATE_STDOUT', json.dumps(result))
            self.assertNotIn('PRIVATE_STDERR', json.dumps(result))

    def test_partial_identity_failure_stage_keeps_confirmed_ssh_and_unknown_sudo(self):
        api, _ = self.api()
        code, result = self.run_main(api, lambda *args, **kwargs: (0, json.dumps(self.payload(child_euid=None)).encode()))
        self.assertEqual(code, 1); self.assertEqual(result['failure_stage'], 'remote_identity')
        self.assertTrue(result['ssh_identity']); self.assertEqual(result['ssh_euid'], 1000)
        self.assertIsNone(result['sudo_root_identity'])

    def test_workflow_has_no_inputs_and_scopes_secret_to_fixed_protected_probe_step(self):
        # Validate the actual YAML structure, including no probe on pull requests.
        # JSON is a YAML subset, keeping this offline suite stdlib-only.
        workflow = json.loads((ROOT / '.github/workflows/test-api-readonly-access.yml').read_text())
        events = workflow['on']
        self.assertEqual(events, {'workflow_dispatch': {}})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(set(workflow['jobs']), {'offline', 'probe'})
        probe = workflow['jobs']['probe']
        self.assertEqual(probe['environment'], 'test-api-readonly-access'); self.assertEqual(probe['needs'], 'offline')
        for guard in ["github.event_name == 'workflow_dispatch'", "github.repository == 'JSMJapan/jsm-release-control'",
                      'github.event.repository.private == false', "github.actor == 'JSMJapan'",
                      "github.triggering_actor == 'JSMJapan'", "github.ref == 'refs/heads/main'", 'github.run_attempt == 1']:
            self.assertIn(guard, probe['if'])
        self.assertNotIn('env', workflow); self.assertNotIn('env', probe)
        self.assertEqual(len(probe['steps']), 2)
        self.assertEqual(probe['steps'][0], {'uses': 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
            'with': {'ref': '${{ github.sha }}', 'persist-credentials': False}})
        self.assertEqual(probe['steps'][1]['env'], {'TEST_API_ADMIN_SSH_KEY': '${{ secrets.TEST_API_ADMIN_SSH_KEY }}',
            'TEST_API_KNOWN_HOSTS': '${{ vars.TEST_API_KNOWN_HOSTS }}'})
        self.assertEqual(probe['steps'][1]['run'], 'python3 -I -B scripts/test_api_readonly_access.py')
        self.assertEqual(workflow['jobs']['offline']['steps'][-1]['run'], "python3 -B -m unittest discover -s tests -p 'test_*.py'")


if __name__ == '__main__': unittest.main()
