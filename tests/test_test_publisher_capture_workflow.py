"""Offline verification of the publisher workflow and its ciphertext-only runner."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_test_installer_capture as deployer_tests
import test_installer_capture_encrypted as shared
import test_publisher_capture_encrypted as publisher
from test_publisher_capture_capsule import STATUSES, VERSION, WRAPPER_SIZE

ROOT = Path(__file__).resolve().parents[1]
NONCE = deployer_tests.NONCE


def owner_context():
    env = deployer_tests.owner_context()
    env.update(
        GITHUB_WORKFLOW_REF=shared.REPO + '/.github/workflows/' + publisher.WORKFLOW + '@refs/heads/main',
        APPROVED_RECIPIENT_SHA256=publisher.RECIPIENT_SHA256,
    )
    return env


def wire(status, ciphertext=None, *, version=VERSION):
    row = deployer_tests.child(status, ciphertext)
    row['version'] = version
    return deployer_tests.wire(row)


class WorkflowTests(unittest.TestCase):
    def test_wrapper_workflow_is_manual_and_separate_from_deployer(self):
        workflows = ROOT / '.github' / 'workflows'
        wrapper = json.loads((workflows / publisher.WORKFLOW).read_text())
        deployer = json.loads((workflows / shared.WORKFLOW).read_text())
        self.assertEqual(wrapper['on'], deployer['on'])
        self.assertEqual(wrapper['permissions'], {'contents': 'read'})
        self.assertNotEqual(wrapper['concurrency']['group'], deployer['concurrency']['group'])
        capture = wrapper['jobs']['capture']
        before = deployer['jobs']['capture']
        self.assertEqual(capture['if'], before['if'])
        self.assertEqual(capture['environment'], before['environment'])
        self.assertEqual(capture['needs'], 'offline')
        self.assertNotIn('environment', wrapper['jobs']['offline'])
        self.assertEqual(capture['steps'][1]['env'], before['steps'][1]['env'])
        self.assertEqual(capture['steps'][1]['run'], 'python3 -I -B scripts/test_publisher_capture_encrypted.py')
        self.assertEqual(capture['steps'][2]['uses'], before['steps'][2]['uses'])
        self.assertNotIn('if', capture['steps'][2])
        self.assertEqual(capture['steps'][2]['with'], {
            'name': 'test-publisher-2760-cms-${{ github.run_id }}',
            'path': '${{ runner.temp }}/' + publisher.FILENAME,
            'retention-days': 1, 'compression-level': 0, 'if-no-files-found': 'error',
        })

    def test_contexts_cannot_be_interchanged(self):
        env = owner_context()
        publisher.context_ready(env)
        with self.assertRaises(shared.Refused):
            shared.context_ready(env)
        with self.assertRaises(shared.Refused):
            publisher.context_ready(deployer_tests.owner_context())
        for setting, value in (
            ('GITHUB_TRIGGERING_ACTOR', 'other'),
            ('GITHUB_RUN_ATTEMPT', '2'),
            ('GITHUB_REF', 'refs/heads/branch'),
            ('APPROVED_RECIPIENT_SHA256', shared.RECIPIENT_SHA256),
        ):
            with self.subTest(setting=setting), patch.object(shared, 'verify_policy') as policy, \
                    patch.object(shared, '_receive') as transport:
                with self.assertRaises(shared.Refused):
                    publisher.collect(None, dict(env, **{setting: value}))
                policy.assert_not_called()
                transport.assert_not_called()

    def test_checks_policy_before_reading_any_runner_credential(self):
        class GuardedContext(dict):
            def get(self, key, default=None):
                if key in ('TEST_API_ADMIN_SSH_KEY', 'TEST_API_KNOWN_HOSTS'):
                    raise AssertionError('unexpected credential access')
                return super().get(key, default)
        with patch.object(shared, 'verify_policy', side_effect=shared.Refused('PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED')), \
                patch.object(shared, 'recipient') as recipient:
            with self.assertRaisesRegex(shared.Refused, 'PROTECTED_TEST_OWNER_MAIN'):
                publisher.collect(None, GuardedContext(owner_context()))
            recipient.assert_not_called()

    def test_closed_failures_do_not_accept_extra_payload_or_old_profile(self):
        pem = publisher.CERTIFICATE.read_bytes()
        for status in STATUSES[1:]:
            self.assertEqual(publisher.project_remote(wire(status), NONCE, pem), (status, None))
            with self.assertRaisesRegex(shared.Refused, '^CAPTURE_RECEIPT_REJECTED$'):
                publisher.project_remote(wire(status, 'AA=='), NONCE, pem)
        for data in (
            wire('HISTORICAL_DIGEST_MISMATCH', version='jsm-test-installer-cms-v1'),
            wire('CAPTURED', base64.b64encode(b'plaintext canary').decode('ascii')),
        ):
            with self.assertRaisesRegex(shared.Refused, '^CAPTURE_RECEIPT_REJECTED$'):
                publisher.project_remote(data, NONCE, pem)


class CiphertextRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = os.environ.get('JSM_TEST_OPENSSL3', '/usr/bin/openssl')
        tool_version = subprocess.run([cls.openssl, 'version'], stdout=subprocess.PIPE,
                                      env=deployer_tests.CRYPTO_ENV, check=True, timeout=5).stdout
        if not tool_version.startswith(b'OpenSSL 3.'):
            if sys.platform.startswith('linux'):
                raise AssertionError('Linux CI requires OpenSSL 3 for ciphertext tests')
            raise unittest.SkipTest('Local OpenSSL 3 executable is not configured')

    def cms(self, count, recipient=None):
        process = subprocess.run([self.openssl, 'cms', '-encrypt', '-binary', '-outform', 'DER', '-aes-256-gcm',
                                  '-provider', 'default', '-recip', recipient or publisher.CERTIFICATE,
                                  '-keyopt', 'rsa_padding_mode:oaep', '-keyopt', 'rsa_oaep_md:sha256',
                                  '-keyopt', 'rsa_mgf1_md:sha256'],
                                 input=b'x' * count, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 env=deployer_tests.CRYPTO_ENV, timeout=4, check=True)
        return process.stdout

    def exercise_main(self, directory, raw):
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err, \
                patch.object(shared.os, 'environ', dict(owner_context(), RUNNER_TEMP=directory)), \
                patch.object(shared.sys, 'argv', ['publisher']), patch.object(shared, 'TestPolicyApi'), \
                patch.object(shared, 'verify_policy'), patch.object(shared, '_receive', return_value=(raw, NONCE)):
            status = publisher.main()
        self.assertEqual(err.getvalue(), '')
        return status, json.loads(out.getvalue())

    def test_runner_stages_exact_ciphertext_and_its_validated_digest(self):
        der = self.cms(WRAPPER_SIZE)
        encoded = base64.b64encode(der).decode('ascii')
        with tempfile.TemporaryDirectory() as directory:
            code, receipt = self.exercise_main(directory, wire('CAPTURED', encoded))
            destination = Path(directory) / publisher.FILENAME
            self.assertEqual(code, 0)
            self.assertEqual(receipt['status'], 'ENCRYPTED_ARTIFACT_STAGED')
            self.assertEqual(receipt['ciphertext_sha256'], hashlib.sha256(der).hexdigest())
            self.assertEqual(receipt['db_isolation'], 'NOT_ESTABLISHED')
            self.assertNotIn(encoded, json.dumps(receipt))
            self.assertEqual(list(Path(directory).iterdir()), [destination])
            self.assertEqual(destination.read_bytes(), der)

    def test_real_cms_wrong_size_or_recipient_never_stages_an_artifact(self):
        for der in (self.cms(8033), self.cms(WRAPPER_SIZE, shared.CERTIFICATE)):
            with self.subTest(size=len(der)), tempfile.TemporaryDirectory() as directory:
                code, receipt = self.exercise_main(directory, wire('CAPTURED', base64.b64encode(der).decode('ascii')))
                self.assertEqual(code, 1)
                self.assertEqual(receipt['reason'], 'CAPTURE_RECEIPT_REJECTED')
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_wrong_historical_digest_is_a_closed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            code, receipt = self.exercise_main(directory, wire('HISTORICAL_DIGEST_MISMATCH'))
            self.assertEqual(code, 1)
            self.assertEqual(receipt['reason'], 'HISTORICAL_DIGEST_MISMATCH')
            self.assertNotIn('ciphertext_sha256', receipt)
            self.assertEqual(list(Path(directory).iterdir()), [])
