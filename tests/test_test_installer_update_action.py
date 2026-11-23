"""Offline tests of the installer transform and protected GitHub caller."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import test_installer_update_action as action
import test_installer_update_package as package

SOURCE = b'#!/bin/bash\nset -e\nprintf "ready\\n"\ntrap - EXIT\nprintf "done\\n"\n'
SHA = 'a' * 40


def digest(data):
    return hashlib.sha256(data).hexdigest()


def response(status):
    return (json.dumps({'version': package.PROTOCOL, 'status': status},
                       sort_keys=True, separators=(',', ':')) + '\n').encode()


def verified_context():
    return dict(GITHUB_REPOSITORY=action.REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
        GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com', GITHUB_SHA=SHA,
        GITHUB_WORKFLOW_SHA=SHA, GITHUB_RUN_ID='12345', APPROVED_WORKFLOW_SHA=SHA, INSTALLER_OPERATION='APPLY',
        GITHUB_WORKFLOW_REF=action.REPO + '/.github/workflows/' + action.WORKFLOW + '@refs/heads/main')


class TransformTests(unittest.TestCase):
    def configure(self, source):
        replaced = source.replace(package.ANCHOR, package.HOOK + package.ANCHOR, 1)
        settings = patch.multiple(package, ORIGINAL_SIZE=len(source), ORIGINAL_SHA256=digest(source),
                                  UPDATED_SIZE=len(replaced), UPDATED_SHA256=digest(replaced))
        self.addCleanup(settings.stop)
        settings.start()
        return replaced

    def test_exact_full_round_trip_and_idempotent_states(self):
        expected = self.configure(SOURCE)
        self.assertEqual(package.transform(SOURCE, 'CHECK'), ('READY', None))
        self.assertEqual(package.transform(SOURCE, 'APPLY'), ('READY', expected))
        self.assertEqual(package.transform(expected, 'APPLY'), ('ALREADY_APPLIED', None))
        self.assertEqual(package.transform(expected, 'ROLLBACK'), ('READY', SOURCE))
        self.assertEqual(package.transform(SOURCE, 'ROLLBACK'), ('ALREADY_ORIGINAL', None))
        self.assertEqual(package.transform(SOURCE, 'OTHER'), ('REQUEST_REFUSED', None))
        self.assertEqual(package.transform(SOURCE.replace(b'done', b'new!'), 'APPLY'), ('PREIMAGE_REFUSED', None))
        self.assertEqual(package.transform(expected + b'\n', 'ROLLBACK'), ('PREIMAGE_REFUSED', None))

    def test_duplicate_anchor_blocks_even_with_matching_preimage_pin(self):
        source = package.ANCHOR + SOURCE
        self.configure(source)
        self.assertEqual(package.transform(source, 'APPLY'), ('PREIMAGE_REFUSED', None))

    def test_hook_preserves_exit_and_printing_if_reporter_fails(self):
        expected = self.configure(SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report'
            marker = Path(directory) / 'marker'
            path.write_text('#!/bin/sh\nprintf "%s\\n" called > ' + str(marker) + '\n'
                            'printf "%s\\n" hidden >&2\nexit 7\n')
            path.chmod(0o700)
            # Only this synthetic executable replaces the code-owned VM target.
            script = expected.replace(package.REPORTER.encode(), str(path).encode())
            if not Path('/usr/bin/timeout').is_file():
                wrapper = Path(directory) / 'synthetic-timeout'
                wrapper.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')
                wrapper.chmod(0o700)
                script = script.replace(b'/usr/bin/timeout', str(wrapper).encode())
            proc = subprocess.run(['/bin/bash','--noprofile','--norc'], input=script,
                                  env={'PATH':'/usr/bin:/bin','LANG':'C'}, capture_output=True,
                                  timeout=6, check=True)
            self.assertEqual(proc.stdout, b'ready\ndone\n')
            self.assertEqual(proc.stderr, b'')
            self.assertEqual(marker.read_text(), 'called\n')


class ActionTests(unittest.TestCase):
    def test_manual_protected_workflow_uses_only_new_writer_credentials(self):
        workflow = json.loads((ROOT / '.github' / 'workflows' / action.WORKFLOW).read_text())
        self.assertEqual(set(workflow['on']), {'workflow_dispatch'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        job = workflow['jobs']['update']
        self.assertEqual(job['needs'], 'offline')
        self.assertTrue("github.run_attempt == 1" in job['if'] and "inputs.approved_sha == github.sha" in job['if'])
        self.assertEqual(job['environment'], action.ENVIRONMENT)
        self.assertEqual(set(job['steps'][-1]['env']), {'APPROVED_WORKFLOW_SHA','INSTALLER_OPERATION',
            'TEST_INSTALLER_WRITE_SSH_KEY','TEST_INSTALLER_WRITE_KNOWN_HOSTS'})
        self.assertEqual(job['steps'][-1]['run'], 'python3 -I -B scripts/test_installer_update_action.py')

    def test_invalid_context_never_gets_policy_or_transport(self):
        good = verified_context()
        self.assertEqual(action.context(good),'APPLY')
        for key, value in (('GITHUB_TRIGGERING_ACTOR','other'),('GITHUB_RUN_ATTEMPT','2'),
                           ('INSTALLER_OPERATION','arbitrary'),('APPROVED_WORKFLOW_SHA','b'*40)):
            with self.subTest(key=key), patch.object(action,'require_protected_writer') as policy, \
                    patch.object(action,'run_writer') as transport:
                with self.assertRaises(action.Refused):
                    action.collect(None,dict(good,**{key:value}))
                policy.assert_not_called()
                transport.assert_not_called()

    def test_policy_refusal_and_missing_dedicated_key_do_not_use_prior_key(self):
        with patch.object(action,'require_protected_writer',side_effect=action.Refused('POLICY_TEST')), \
                patch.object(action,'run_writer') as transport:
            with self.assertRaisesRegex(action.Refused,'POLICY_TEST'):
                action.collect(None,verified_context())
            transport.assert_not_called()
        with patch.object(action,'_bounded') as bounded:
            with self.assertRaisesRegex(action.Refused,'DEDICATED_WRITER_NOT_PROVISIONED'):
                action.run_writer(dict(TEST_API_ADMIN_SSH_KEY='not-for-the-writer'),'CHECK')
            bounded.assert_not_called()

    def test_exact_remote_command_and_pin_before_transport(self):
        known = 'synthetic host key context'
        env = dict(TEST_INSTALLER_WRITE_SSH_KEY='synthetic scoped writer key',
                   TEST_INSTALLER_WRITE_KNOWN_HOSTS=known)
        with patch.object(action,'_bounded',return_value=(0,response('APPLIED'))) as bounded, \
                patch.object(action,'PIN_SHA256',digest(known.encode())):
            self.assertEqual(action.run_writer(env,'APPLY'),'APPLIED')
            (command,), options = bounded.call_args
            self.assertEqual(command[-2:], ['jsmtestinstall@34.104.157.63',package.PROTOCOL])
            self.assertIn('ClearAllForwardings=yes',command)
            self.assertIn('StrictHostKeyChecking=yes',command)
            self.assertEqual(options['data'],b'{"operation":"APPLY","version":"jsm-test-installer-update-v1"}\n')
            self.assertEqual(options['limit'],512)

    def test_receipt_cannot_substitute_success_or_embed_data(self):
        self.assertEqual(action.parse_receipt(0,response('APPLIED'),'APPLY'),'APPLIED')
        self.assertEqual(action.parse_receipt(1,response('REPORTER_UNAVAILABLE'),'CHECK'),'REPORTER_UNAVAILABLE')
        for code, raw in ((1,response('APPLIED')), (0,response('READY')), (0,b'{"status":"APPLIED","data":"private"}')):
            with self.subTest(code=code), self.assertRaisesRegex(action.Refused,'WRITER_RECEIPT_REFUSED'):
                action.parse_receipt(code,raw,'APPLY')
