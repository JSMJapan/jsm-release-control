"""Offline only. No transport to TEST and no production or installer fixtures."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import test_installer_capture_capsule as capsule
import test_installer_capture_encrypted as capture

NONCE = 'a' * 32
SHA = 'b' * 40
CRYPTO_ENV = dict(PATH='/usr/bin:/bin', LANG='C', OPENSSL_CONF='/dev/null')


def owner_context():
    return dict(
        GITHUB_REPOSITORY=capture.REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
        GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com', GITHUB_SHA=SHA,
        GITHUB_WORKFLOW_SHA=SHA, GITHUB_RUN_ID='12345', APPROVED_CAPTURE_SHA=SHA,
        APPROVED_RECIPIENT_SHA256=capture.RECIPIENT_SHA256,
        GITHUB_WORKFLOW_REF=capture.REPO + '/.github/workflows/' + capture.WORKFLOW + '@refs/heads/main',
    )


def child(status='CAPTURED', ciphertext=None):
    return dict(version='jsm-test-installer-cms-v1', nonce=NONCE, euid=0, status=status, ciphertext=ciphertext)


def wire(diagnostic):
    return json.dumps(dict(version='jsm-test-installed-route-outer-v2', nonce=NONCE, principal='marinagurina',
                           euid=1000, root_diagnostic=diagnostic), separators=(',', ':')).encode()


class BoundaryTests(unittest.TestCase):
    def test_workflow_uses_only_protected_manual_capture_and_fixed_artifact(self):
        value = json.loads((ROOT / '.github/workflows' / capture.WORKFLOW).read_text())
        self.assertEqual(set(value['on']), {'workflow_dispatch'})
        inputs = value['on']['workflow_dispatch']['inputs']
        self.assertEqual(set(inputs), {'approved_sha', 'recipient_sha256'})
        self.assertTrue(all(row['required'] and row['type'] == 'string' for row in inputs.values()))
        self.assertEqual(value['permissions'], {'contents': 'read'})
        jobs = value['jobs']
        self.assertNotIn('environment', jobs['offline'])
        protected = jobs['capture']
        self.assertEqual(protected['needs'], 'offline')
        self.assertEqual(protected['environment'], capture.ENVIRONMENT)
        for exact in ("workflow_dispatch", "github.event.repository.private == false",
                      "github.actor == 'JSMJapan'", "github.triggering_actor == 'JSMJapan'",
                      "refs/heads/main", "github.run_attempt == 1", "inputs.approved_sha == github.sha"):
            self.assertIn(exact, protected['if'])
        self.assertEqual(protected['steps'][1]['run'], 'python3 -I -B scripts/test_installer_capture_encrypted.py')
        upload = protected['steps'][2]
        self.assertRegex(upload['uses'], r'\Aactions/upload-artifact@[0-9a-f]{40}\Z')
        self.assertNotIn('if', upload)
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/' + capture.FILENAME)
        self.assertEqual(upload['with']['retention-days'], 1)
        self.assertEqual(upload['with']['if-no-files-found'], 'error')

    def test_context_refuses_before_network_or_transport(self):
        initial = owner_context()
        blocked = {'GITHUB_REPOSITORY': 'owner/other', 'GITHUB_ACTOR': 'OTHER',
                   'GITHUB_TRIGGERING_ACTOR': 'OTHER', 'GITHUB_REF': 'refs/heads/branch',
                   'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_WORKFLOW_REF': 'OTHER',
                   'GITHUB_WORKFLOW_SHA': 'c' * 40, 'APPROVED_CAPTURE_SHA': 'c' * 40,
                   'APPROVED_RECIPIENT_SHA256': '0' * 64}
        capture.context_ready(initial)
        for name, wrong in blocked.items():
            with self.subTest(name=name):
                with self.assertRaises(capture.Refused):
                    capture.collect(None, dict(initial, **{name: wrong}))

    def test_changed_public_policy_blocks_recipient_and_transport(self):
        repo = dict(full_name=capture.REPO, private=False)
        env = dict(name=capture.ENVIRONMENT, can_admins_bypass=False,
                   deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True),
                   protection_rules=[dict(type='required_reviewers', prevent_self_review=False,
                                          reviewers=[dict(type='User', reviewer=dict(login='JSMJapan', id=327623967))])])
        branches = dict(total_count=1, branch_policies=[dict(name='main', type='branch')])
        rows = {capture.GH_REPO: repo, capture.GH_ENV: env,
                capture.GH_ENV + '/deployment-branch-policies': branches}

        class Api:
            def get_json(self, path):
                return rows[path]

        capture.verify_policy(Api())
        with patch.object(capture, 'recipient', side_effect=AssertionError('recipient called')), \
                patch.object(capture, '_bounded', side_effect=AssertionError('transport called')):
            for row, field, invalid in (
                (repo, 'private', True), (env, 'can_admins_bypass', True),
                (env['protection_rules'][0]['reviewers'][0]['reviewer'], 'id', 1),
                (branches['branch_policies'][0], 'name', '*'),
            ):
                previous = row[field]
                row[field] = invalid
                with self.subTest(field=field), self.assertRaisesRegex(capture.Refused, 'PROTECTED_TEST_OWNER_MAIN'):
                    capture.collect(Api(), owner_context())
                row[field] = previous

    def test_missing_key_and_host_mismatch_do_not_invoke_transport(self):
        with patch.object(capture, 'verify_policy'), patch.object(capture, '_bounded') as transport:
            with self.assertRaisesRegex(capture.Refused, 'TEST_SSH_KEY_NOT_CONFIGURED'):
                capture.collect(None, owner_context())
            env = dict(owner_context(), TEST_API_ADMIN_SSH_KEY='synthetic fixture', TEST_API_KNOWN_HOSTS='wrong')
            with self.assertRaisesRegex(capture.Refused, 'EXACT_TEST_HOST_PIN_REQUIRED'):
                capture.collect(None, env)
            transport.assert_not_called()

    def test_malformed_receipts_and_unencrypted_payload_are_rejected(self):
        pem = capture.recipient()
        sentinel = base64.b64encode(b'private-plaintext-canary').decode()
        for result in (
            wire(child(ciphertext=sentinel)), wire(child('PATH_REFUSED', sentinel)), wire(child('OTHER')),
            wire(dict(child(), euid=True)), wire(None), wire(dict(child('PATH_REFUSED'), unexpected='secret')),
            wire(dict(child('PATH_REFUSED'), nonce='f' * 32)), wire(child(ciphertext=' ' * 13000)),
            wire(child('PATH_REFUSED')).replace(b'"euid":0', b'"euid":0,"euid":0'),
        ):
            with self.subTest(size=len(result)), self.assertRaisesRegex(capture.Refused, '^CAPTURE_RECEIPT_REJECTED$'):
                capture.project_remote(result, NONCE, pem)
        for refusal in capsule.STATUSES[1:]:
            self.assertEqual(capture.project_remote(wire(child(refusal)), NONCE, pem), (refusal, None))

    def test_failed_collection_writes_no_artifact_or_private_error(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()) as out, \
                redirect_stderr(io.StringIO()) as err, patch.object(capture.os, 'environ', dict(owner_context(), RUNNER_TEMP=folder)), \
                patch.object(capture.sys, 'argv', ['runner']), patch.object(capture, 'TestPolicyApi'), \
                patch.object(capture, 'collect', side_effect=RuntimeError('SYNTHETIC_SECRET_ERROR')):
            self.assertEqual(capture.main(), 1)
            self.assertEqual(list(Path(folder).iterdir()), [])
            self.assertEqual(json.loads(out.getvalue())['reason'], 'CAPTURE_REFUSED')
            self.assertNotIn('SYNTHETIC', out.getvalue())
            self.assertEqual(err.getvalue(), '')

    def test_capture_preflight_failure_does_not_touch_source_path(self):
        namespace = {}
        exec(capsule._VALIDATION + capsule._ROOT, namespace)
        with patch.dict(namespace, _preflight=lambda *_: (_ for _ in ()).throw(ValueError()),
                        _parents=lambda *_: self.fail('Source path accessed after failed preflight')):
            self.assertEqual(namespace['_capture'](b'invalid', 'invalid', 0), ('PREFLIGHT_REFUSED', None))

    def test_recipient_is_bound_before_render_and_immutable(self):
        pem = capture.recipient()
        self.assertEqual(capture.RECIPIENT_SHA256, hashlib.sha256(pem).hexdigest())
        with self.assertRaises(ValueError):
            capsule.render(NONCE, pem + b'extra', capture.RECIPIENT_SHA256)
        with self.assertRaises(ValueError):
            capsule.render('invalid', pem, capture.RECIPIENT_SHA256)
        code = capsule.render(NONCE, pem, capture.RECIPIENT_SHA256)
        compile(code, '<offline synthetic compilation>', 'exec')
        self.assertTrue(code.isascii())


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = os.environ.get('JSM_TEST_OPENSSL3', '/usr/bin/openssl')
        version = subprocess.run([cls.openssl, 'version'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 env=CRYPTO_ENV, check=True, timeout=5).stdout
        if not version.startswith(b'OpenSSL 3.'):
            if sys.platform.startswith('linux'):
                raise AssertionError('Linux offline CI requires OpenSSL 3 for the CMS roundtrip')
            raise unittest.SkipTest('Set JSM_TEST_OPENSSL3 to an OpenSSL 3 executable for local CMS tests')
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        cls.folder = Path(folder.name)
        cls.first = cls.new_recipient('fixture-a')
        cls.second = cls.new_recipient('fixture-b')
        namespace = {}
        exec(capsule._VALIDATION + capsule._ROOT, namespace)
        cls.namespace = namespace

    @classmethod
    def command(cls, *argv, data=b''):
        return subprocess.run([cls.openssl, *argv], input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=CRYPTO_ENV, timeout=10, check=False)

    @classmethod
    def new_recipient(cls, name):
        cert, key = cls.folder / (name + '.pem'), cls.folder / (name + '.key')
        result = cls.command('req', '-config', '/dev/null', '-newkey', 'rsa:3072', '-nodes', '-x509',
                             '-days', '1', '-sha256', '-subj', '/CN=' + name, '-out', cert, '-keyout', key)
        if result.returncode:
            raise AssertionError('synthetic certificate generation failed')
        return cert, key

    def encrypt(self, data, cert):
        def run(argv, supplied, limit, _deadline, *, recipient_fd):
            argv = [str(cert) if part == '/proc/self/fd/' + str(recipient_fd) else part for part in argv]
            result = self.command(*argv, data=supplied)
            self.assertEqual(result.returncode, 0)
            self.assertLessEqual(len(result.stdout), limit)
            return result.stdout
        with patch.dict(self.namespace, _bounded_crypto=run):
            return self.namespace['_cms'](data, 5, time.monotonic() + 5)

    def decrypt(self, ciphertext, recipient):
        cert, key = recipient
        return self.command('cms', '-decrypt', '-binary', '-inform', 'DER', '-recip', cert, '-inkey', key,
                            data=ciphertext)

    def test_binary_roundtrip_at_maximum_and_original_wrapper_bounds(self):
        marker = b'\x00JSMSyntheticSecretMarker\r\n\xff'
        source = (marker * 350)[:8192]
        self.assertEqual(len(source), 8192)
        ciphertext = self.encrypt(source, self.first[0])
        self.assertNotIn(marker, ciphertext)
        encrypted = self.decrypt(ciphertext, self.first)
        self.assertEqual(encrypted.returncode, 0)
        self.assertEqual(encrypted.stdout, source)
        text_cipher = base64.b64encode(ciphertext).decode('ascii')
        diagnostic = child(ciphertext=text_cipher)
        self.assertLessEqual(len(json.dumps(diagnostic, separators=(',', ':')).encode()), 12288)
        self.assertLessEqual(len(wire(diagnostic)), 16384)
        self.assertEqual(capture.project_remote(wire(diagnostic), NONCE, self.first[0].read_bytes()),
                         ('CAPTURED', ciphertext))

    def test_wrong_recipient_tampering_and_truncation(self):
        ciphertext = self.encrypt(b'synthetic data', self.first[0])
        self.assertTrue(capsule.validate_envelope(ciphertext, self.first[0].read_bytes()))
        self.assertFalse(capsule.validate_envelope(ciphertext, self.second[0].read_bytes()))
        self.assertNotEqual(self.decrypt(ciphertext, self.second).returncode, 0)
        self.assertFalse(capsule.validate_envelope(ciphertext[:-1], self.first[0].read_bytes()))
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        self.assertNotEqual(self.decrypt(tampered, self.first).returncode, 0)
        for value in (ciphertext + b'\x00', ciphertext[:-16], b'synthetic data'):
            self.assertFalse(capsule.validate_envelope(value))

    def test_success_stages_only_ciphertext_and_public_receipt(self):
        ciphertext = self.encrypt(b'private source marker', self.first[0])
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()) as stdout, \
                redirect_stderr(io.StringIO()) as stderr, patch.object(capture.os, 'environ', dict(owner_context(), RUNNER_TEMP=folder)), \
                patch.object(capture.sys, 'argv', ['runner']), patch.object(capture, 'TestPolicyApi'), \
                patch.object(capture, 'collect', return_value=ciphertext):
            self.assertEqual(capture.main(), 0)
            output = Path(folder) / capture.FILENAME
            self.assertEqual(list(Path(folder).iterdir()), [output])
            self.assertEqual(output.read_bytes(), ciphertext)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result['status'], 'ENCRYPTED_ARTIFACT_STAGED')
            self.assertEqual(result['ciphertext_sha256'], hashlib.sha256(ciphertext).hexdigest())
            self.assertEqual(result['db_isolation'], 'NOT_ESTABLISHED')
            self.assertNotIn(base64.b64encode(ciphertext).decode(), stdout.getvalue())
            self.assertNotIn('private source marker', stdout.getvalue())
            self.assertEqual(stderr.getvalue(), '')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'linux memfd and no-atime source descriptor')
    def test_linux_capsule_preflight_and_fixed_regular_source(self):
        pem = self.first[0].read_bytes()
        digest = hashlib.sha256(pem).hexdigest()
        namespace = self.namespace

        with patch.object(namespace['os'], 'geteuid', return_value=0), \
                patch.object(namespace['resource'], 'setrlimit'):
            recipient_fd, witness = namespace['_preflight'](pem, digest, time.monotonic() + 3)
            os.close(recipient_fd)
        self.assertEqual(witness[3], len(namespace['_CANARY']))

        root = self.folder / 'synthetic-root'
        root.mkdir(mode=0o700)
        leaf = root / 'jsm-sandbox-deploy'
        data = b'public synthetic source fixture\x00\r\n' * 23
        leaf.write_bytes(data)
        original_bytes = leaf.stat().st_atime_ns

        def synthetic_parent(_deadline):
            return [os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]

        namespace['_OPENSSL'] = self.openssl
        with patch.dict(namespace, _safe_mode=lambda info: info.st_uid in (0, os.getuid()) and info.st_mode & 0o022 == 0,
                        _parents=synthetic_parent), patch.object(os, 'geteuid', return_value=0), \
                patch.object(namespace['resource'], 'setrlimit'):
            status, encoded = namespace['_capture'](pem, digest, time.monotonic() + 3)
            self.assertEqual(status, 'CAPTURED')
            self.assertEqual(leaf.stat().st_atime_ns, original_bytes)
            result = self.decrypt(base64.b64decode(encoded, validate=True), self.first)
            self.assertEqual((result.returncode, result.stdout), (0, data))

            hardlink = root / 'another-entry'
            os.link(leaf, hardlink)
            self.assertEqual(namespace['_capture'](pem, digest, time.monotonic() + 3), ('PATH_REFUSED', None))
            os.unlink(hardlink)
            leaf.chmod(0o666)
            self.assertEqual(namespace['_capture'](pem, digest, time.monotonic() + 3), ('PATH_REFUSED', None))
            leaf.chmod(0o600)
            leaf.write_bytes(b'x' * 8193)
            self.assertEqual(namespace['_capture'](pem, digest, time.monotonic() + 3), ('PATH_REFUSED', None))
            leaf.write_bytes(data)

            original_cms = namespace['_cms']

            def mutate_after_encryption(source, fd, deadline):
                ciphertext = original_cms(source, fd, deadline)
                if source == data:
                    leaf.write_bytes(b'substitute')
                return ciphertext

            with patch.dict(namespace, _cms=mutate_after_encryption):
                self.assertEqual(namespace['_capture'](pem, digest, time.monotonic() + 3), ('SOURCE_CHANGED', None))
            leaf.unlink()
            leaf.symlink_to(self.first[0])
            self.assertEqual(namespace['_capture'](pem, digest, time.monotonic() + 3), ('PATH_REFUSED', None))
