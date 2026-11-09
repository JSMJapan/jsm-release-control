import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/apache_admin_readonly_probe.py'
KNOWN = '[187.77.118.50]:17177 ssh-ed25519 AAAA\n[187.77.118.50]:17177 ecdsa-sha2-nistp256 AAAA\n[187.77.118.50]:17177 ssh-rsa AAAA\n'


class AdminProbeTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'Missing bounded admin RO probe')
        spec = importlib.util.spec_from_file_location('apache_admin_readonly_probe', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def context(self):
        return dict(GITHUB_REPOSITORY='JSMJapan/jsm-release-control', GITHUB_ACTOR='JSMJapan',
                    GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
                    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_RUN_ID='123456789',
                    GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/apache-admin-readonly-probe.yml@refs/heads/main',
                    APACHE_BOOTSTRAP_ADMIN_SSH_KEY='short-dummy-admin-key', APACHE_BOOTSTRAP_KNOWN_HOSTS=KNOWN)

    def api(self, protected=True):
        calls = []
        reviewer = dict(type='required_reviewers', prevent_self_review=False,
                        reviewers=[dict(type='User', reviewer=dict(login='JSMJapan'))])
        fixtures = [dict(full_name='JSMJapan/jsm-release-control', private=False),
                    dict(can_admins_bypass=False, protection_rules=[reviewer] if protected else [],
                         deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True)),
                    dict(total_count=1, branch_policies=[dict(name='main', type='branch')])]
        class Api:
            def get_json(inner, host, path, token=None):
                calls.append((host, path, token)); return fixtures[len(calls)-1]
        return Api(), calls

    def payload(self, nonce='b' * 32):
        item = dict(present=True, regular=True, root_owned=True, mode=0o755)
        return dict(version='jsm-apache-admin-ro-v1', nonce=nonce, euid=0,
                    apache_binary=item, apache_config=dict(item, mode=0o644), writes_performed=False)

    def test_fixed_ssh_command_private_temp_modes_cleanup_and_safe_receipt(self):
        api, calls = self.api(); paths = []
        def transport(command, program):
            self.assertEqual(command[-5:], ['root@187.77.118.50', '/usr/bin/python3', '-I', '-B', '-'])
            self.assertIn('StrictHostKeyChecking=yes', command)
            self.assertIn('BatchMode=yes', command)
            self.assertIn('IdentitiesOnly=yes', command)
            identity = pathlib.Path(command[command.index('-i')+1]); paths.append(identity.parent)
            known = pathlib.Path(next(arg.split('=',1)[1] for arg in command if arg.startswith('UserKnownHostsFile=')))
            self.assertEqual(identity.read_text(), 'short-dummy-admin-key\n')
            self.assertEqual(known.read_text(), KNOWN)
            self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
            self.assertEqual(known.stat().st_mode & 0o777, 0o600)
            self.assertEqual(identity.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn(('b' * 32).encode(), program)
            return json.dumps(self.payload()).encode()
        with patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                patch.object(self.module.secrets, 'token_hex', return_value='b' * 32), \
                patch.object(self.module, 'bounded_ssh', side_effect=transport):
            result = self.module.collect(api, self.context())
        self.assertEqual(result['status'], 'ADMIN_READ_ONLY_PROBE_COMPLETE')
        self.assertTrue(result['root_identity'])
        self.assertEqual(result['apache_channel'], 'NOT_ACTIVATED')
        self.assertEqual(result['writes_performed'], False)
        self.assertNotIn('dummy', json.dumps(result))
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertTrue(all(host == 'api.github.com' and token is None for host, path, token in calls))

    def test_context_policy_missing_key_or_changed_host_pin_refuse_before_ssh(self):
        for case in ('old_workflow', 'wrong_actor', 'unprotected', 'missing_key', 'changed_pin'):
            env = self.context(); api, calls = self.api(protected=case != 'unprotected')
            if case == 'old_workflow': env['GITHUB_WORKFLOW_REF'] = env['GITHUB_WORKFLOW_REF'].replace('apache-admin-readonly-probe', 'hostinger-readonly-preflight')
            if case == 'wrong_actor': env['GITHUB_ACTOR'] = 'other'
            if case == 'missing_key': env.pop('APACHE_BOOTSTRAP_ADMIN_SSH_KEY')
            if case == 'changed_pin': env['APACHE_BOOTSTRAP_KNOWN_HOSTS'] += 'changed'
            with patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                    patch.object(self.module, 'bounded_ssh') as transport:
                with self.assertRaises(self.module.Refused): self.module.collect(api, env)
                transport.assert_not_called()

    def test_actual_remote_program_only_stats_two_fixed_paths_and_reports_root(self):
        output = io.StringIO(); calls = []
        def metadata(path):
            calls.append(path)
            return types.SimpleNamespace(st_mode=stat.S_IFREG | (0o755 if path.endswith('apache2') else 0o644), st_uid=0)
        with patch.object(os, 'lstat', side_effect=metadata), patch.object(os, 'geteuid', return_value=0), contextlib.redirect_stdout(output):
            exec(compile(self.module.remote_program('b' * 32), '<fixed-remote>', 'exec'), {})
        self.assertEqual(calls, ['/usr/sbin/apache2', '/etc/apache2/apache2.conf'])
        self.assertEqual(json.loads(output.getvalue()), self.payload())

    def test_nonce_closed_schema_root_and_metadata_types_reject_unsafe_output(self):
        for case in ('nonce', 'extra', 'uid', 'boolean_mode', 'raw_banner', 'oversize'):
            value = self.payload()
            if case == 'nonce': value['nonce'] = 'c' * 32
            if case == 'extra': value['PRIVATE_CONFIG'] = 'PRIVATE_BODY'
            if case == 'uid': value['euid'] = 1000
            if case == 'boolean_mode': value['apache_config']['mode'] = True
            raw = b'PRIVATE_BANNER' if case == 'raw_banner' else b'x' * 5000 if case == 'oversize' else json.dumps(value).encode()
            with self.assertRaises(self.module.Refused) as failed: self.module.project_remote(raw, 'b' * 32)
            self.assertNotIn('PRIVATE', str(failed.exception))

    def test_hard_stdout_cap_and_deadline_without_ssh_or_network(self):
        with self.assertRaisesRegex(self.module.Refused, 'REMOTE_OUTPUT_BOUND'):
            self.module.bounded_ssh([sys.executable, '-c', 'import sys; sys.stdout.write("x"*5000)'], b'')
        with patch.object(self.module, 'SSH_SECONDS', 0.05):
            with self.assertRaisesRegex(self.module.Refused, 'SSH_DEADLINE'):
                self.module.bounded_ssh([sys.executable, '-c', 'import time; time.sleep(1)'], b'')

    def test_main_never_emits_raw_ssh_error_or_key(self):
        output = io.StringIO()
        with patch.object(self.module, 'collect', side_effect=RuntimeError('PRIVATE_KEY PRIVATE_STDERR')), \
                patch.object(self.module.signal, 'signal'), patch.object(self.module.signal, 'setitimer'), \
                patch.object(self.module.sys, 'argv', ['probe.py']), contextlib.redirect_stdout(output):
            self.assertEqual(self.module.main(), 1)
        self.assertNotIn('PRIVATE', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'], 'BLOCKED')

    def test_owned_private_files_are_removed_after_transport_or_remote_schema_failure(self):
        for case in ('ssh_failure', 'bad_nonce'):
            api, calls = self.api(); folders = []
            def transport(command, program):
                folder = pathlib.Path(command[command.index('-i')+1]).parent
                folders.append(folder)
                self.assertTrue((folder / 'identity').exists())
                if case == 'ssh_failure': raise self.module.Refused('SSH_KEY_LOAD_OR_AUTH_OR_COMMAND_FAILED')
                return json.dumps(self.payload('c' * 32)).encode()
            with patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                    patch.object(self.module.secrets, 'token_hex', return_value='b' * 32), \
                    patch.object(self.module, 'bounded_ssh', side_effect=transport):
                with self.assertRaises(self.module.Refused): self.module.collect(api, self.context())
            self.assertTrue(folders)
            self.assertTrue(all(not folder.exists() for folder in folders))

    def test_identity_transport_normalizes_only_crlf_and_final_lf_preserving_body_and_pin(self):
        for pasted, expected in (
            ('dummy-key-without-final-lf', 'dummy-key-without-final-lf\n'),
            ('dummy-key-with-final-lf\n', 'dummy-key-with-final-lf\n'),
            ('  dummy body line  \r\nsecond line  \r\n\r\n', '  dummy body line  \nsecond line  \n'),
        ):
            with self.subTest(pasted=pasted):
                api, calls = self.api(); env = self.context(); env['APACHE_BOOTSTRAP_ADMIN_SSH_KEY'] = pasted
                folders = []
                def transport(command, program):
                    identity = pathlib.Path(command[command.index('-i')+1]); folders.append(identity.parent)
                    self.assertEqual(identity.read_bytes(), expected.encode())
                    self.assertEqual((identity.parent / 'known_hosts').read_bytes(), KNOWN.encode())
                    self.assertEqual(env['APACHE_BOOTSTRAP_ADMIN_SSH_KEY'], pasted)
                    return json.dumps(self.payload()).encode()
                with patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                        patch.object(self.module.secrets, 'token_hex', return_value='b' * 32), \
                        patch.object(self.module, 'bounded_ssh', side_effect=transport):
                    result = self.module.collect(api, env)
                self.assertEqual(result['status'], 'ADMIN_READ_ONLY_PROBE_COMPLETE')
                self.assertTrue(folders)
                self.assertTrue(all(not folder.exists() for folder in folders))


if __name__ == '__main__': unittest.main()
