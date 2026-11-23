"""Offline fixtures for the exact TEST bootstrap and its guarded runner."""
from pathlib import Path
import io
import json
import os
from contextlib import redirect_stdout
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import test_installer_receiver_bootstrap as bootstrap

NONCE = 'c' * 32
SHA = 'a' * 40


def approved():
    return dict(GITHUB_REPOSITORY=bootstrap.REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
        GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
        GITHUB_SHA=SHA, GITHUB_WORKFLOW_SHA=SHA, GITHUB_RUN_ID='123456',
        GITHUB_WORKFLOW_REF=bootstrap.REPO + '/.github/workflows/' + bootstrap.WORKFLOW + '@refs/heads/main',
        APPROVED_BOOTSTRAP_SHA=SHA, APPROVED_PUBLIC_KEY_SHA256=bootstrap.PUBLIC_SHA256,
        APPROVED_BOOTSTRAP_SCOPE=bootstrap.SCOPE)


def response(status='BOOTSTRAPPED'):
    return dict(version='jsm-test-installed-route-outer-v2', nonce=NONCE, principal='marinagurina',
        euid=1001, root_diagnostic=dict(version=bootstrap.VERSION, nonce=NONCE, euid=0, status=status))


class GitHubBoundaryTests(unittest.TestCase):
    def test_workflow_is_manual_and_has_a_single_bootstrap_write_scope(self):
        path = ROOT / '.github/workflows' / bootstrap.WORKFLOW
        value = json.loads(path.read_text())
        self.assertEqual(set(value['on']), {'workflow_dispatch'})
        inputs = value['on']['workflow_dispatch']['inputs']
        self.assertEqual(inputs['scope']['options'], [bootstrap.SCOPE])
        self.assertEqual(set(inputs), {'scope', 'approved_sha', 'writer_public_key_sha256'})
        job = value['jobs']['bootstrap']
        self.assertEqual(job['needs'], 'offline')
        self.assertEqual(job['environment'], 'test-api-readonly-access')
        self.assertIn('inputs.approved_sha == github.sha', job['if'])
        self.assertIn('github.run_attempt == 1', job['if'])
        self.assertEqual(value['permissions'], {'contents': 'read'})

    def test_wrong_scope_fails_before_policy_package_or_transport(self):
        self.assertEqual(bootstrap.context(approved()), SHA)
        for key, value in (('APPROVED_BOOTSTRAP_SCOPE', 'OTHER'),
                           ('APPROVED_PUBLIC_KEY_SHA256', 'd' * 64),
                           ('APPROVED_BOOTSTRAP_SHA', 'b' * 40),
                           ('GITHUB_RUN_ATTEMPT', '2')):
            with self.subTest(key=key), patch.object(bootstrap, 'verify_policy') as policy, \
                    patch.object(bootstrap, '_receive') as transport:
                with self.assertRaises(bootstrap.Refused):
                    bootstrap.collect(None, dict(approved(), **{key: value}))
                policy.assert_not_called()
                transport.assert_not_called()

    def test_both_protected_environments_are_checked_before_transport(self):
        with patch.object(bootstrap, 'verify_policy') as observer_policy, \
                patch.object(bootstrap, 'require_protected_writer', side_effect=bootstrap.Refused('WRITER')) as writer_policy, \
                patch.object(bootstrap, 'package') as package, patch.object(bootstrap, '_receive') as transport:
            with self.assertRaisesRegex(bootstrap.Refused, 'WRITER'):
                bootstrap.collect(None, approved())
            observer_policy.assert_called_once_with(None)
            writer_policy.assert_called_once_with(None, SHA)
            package.assert_not_called()
            transport.assert_not_called()

    def test_receipt_refuses_bad_nonce_scope_and_extra_payload(self):
        self.assertEqual(bootstrap.project(json.dumps(response()).encode(), NONCE), 'BOOTSTRAPPED')
        for change in ({'nonce': 'b' * 32}, {'euid': True}, {'contents': 'synthetic disallowed payload'}):
            sample = response()
            sample['root_diagnostic'].update(change)
            with self.assertRaisesRegex(bootstrap.Refused, 'BOOTSTRAP_RECEIPT_REFUSED'):
                bootstrap.project(json.dumps(sample).encode(), NONCE)


class FixtureOs:
    def __init__(self, prefix):
        self.prefix = prefix

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, name, flags, *args, **kwargs):
        if name == '/':
            name = self.prefix
        return os.open(name, flags, *args, **kwargs)

    @staticmethod
    def root_group(record):
        class FixtureStat:
            st_gid = 0

            def __getattr__(self, name):
                return getattr(record, name)
        return FixtureStat()

    def stat(self, *args, **kwargs):
        return self.root_group(os.stat(*args, **kwargs))

    def fstat(self, *args, **kwargs):
        return self.root_group(os.fstat(*args, **kwargs))

    @staticmethod
    def fchown(_fd, uid, gid):
        if (uid, gid) != (0, 0):
            raise AssertionError('expected only the root-owned package')


class HostFixtureTests(unittest.TestCase):
    def setUp(self):
        self.public, self.files = bootstrap.package()
        source = bootstrap.child_program(NONCE, self.public, self.files)
        definitions, call = source.rsplit('\n_boot_main()', 1)
        self.assertFalse(call.strip())
        self.ns = {}
        exec(compile(definitions, '<offline TEST bootstrap>', 'exec'), self.ns)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        for dirname in ('usr/local', 'var/lib', 'etc/sudoers.d'):
            (self.root / dirname).mkdir(parents=True)
        self.writer = self.root / 'usr/local/libexec/jsm-test-installer-writer'
        self.home = self.root / 'var/lib/jsm-test-installer-writer-home'
        self.sudo = self.root / 'etc/sudoers.d/jsm-test-installer-writer'
        self.useradd = []
        self.ns.update(os=FixtureOs(self.root), _boot_host_matches=lambda _: True,
            _boot_account_absent=lambda: True, _boot_visudo=lambda _: None,
            _boot_safe=lambda record: record.st_uid == os.getuid() and not record.st_mode & 0o022,
            _boot_tool=lambda _: None, _boot_useradd=lambda _: self.useradd.append(True))

    def apply(self, files=None):
        return self.ns['_boot_apply'](self.files if files is None else files, self.public, time.monotonic() + 3)

    def test_exact_pinned_files_bootstrap_without_touching_installer_or_old_account(self):
        target = self.root / 'usr/local/sbin/jsm-sandbox-deploy'
        target.parent.mkdir()
        target.write_bytes(b'synthetic existing installer')
        self.assertEqual(self.apply(), 'BOOTSTRAPPED')
        self.assertEqual(self.useradd, [True])
        self.assertEqual(target.read_bytes(), b'synthetic existing installer')
        self.assertEqual(stat.S_IMODE(self.writer.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.writer / 'state').stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.sudo.stat().st_mode), 0o440)
        self.assertIn(b'NOSETENV: /usr/bin/python3 -I -B -S ', self.sudo.read_bytes())
        line = (self.home / '.ssh/authorized_keys').read_bytes()
        self.assertTrue(line.startswith(b'restrict,command="'))
        self.assertTrue(line.endswith(self.public))
        for source, (dest, mode, _, _) in self.ns['_BOOT_MEMBERS'].items():
            self.assertEqual((self.writer / dest).read_bytes(), self.files[source])
            self.assertEqual(stat.S_IMODE((self.writer / dest).stat().st_mode), mode)
        self.assertEqual(self.apply(), 'PREEXISTING_REFUSED')
        self.assertEqual(len(self.useradd), 1)

    def test_changed_package_and_wrong_host_perform_no_writes(self):
        self.assertEqual(self.apply(dict(self.files, **{'package.py':b'substitute'})), 'INPUT_REFUSED')
        self.ns['_boot_host_matches'] = lambda _: False
        self.assertEqual(self.apply(), 'TARGET_REFUSED')
        self.assertFalse(self.writer.exists())
        self.assertFalse(self.home.exists())
        self.assertEqual(self.useradd, [])

    def test_pre_account_failure_rolls_back_only_owned_files(self):
        original = self.ns['_boot_file']

        def fail_late(*args):
            if args[3] == 'authorized_keys':
                raise OSError('synthetic private failure')
            return original(*args)

        self.ns['_boot_file'] = fail_late
        self.assertEqual(self.apply(), 'BOOTSTRAP_FAILED')
        self.assertFalse(self.writer.exists())
        self.assertFalse(self.home.exists())
        self.assertFalse(self.sudo.exists())
        self.assertTrue((self.root / 'var/lib').is_dir())

    def test_uncertain_account_creation_removes_its_key_and_privilege_without_repeating(self):
        def uncertain(_):
            self.ns['_boot_account_absent'] = lambda: False
            raise self.ns['_BootUncertain']()

        self.ns['_boot_useradd'] = uncertain
        self.assertEqual(self.apply(), 'STATE_UNCERTAIN')
        self.assertFalse((self.writer / 'forced-command').exists())
        self.assertFalse((self.home / '.ssh/authorized_keys').exists())
        self.assertFalse(self.sudo.exists())
        self.assertEqual(self.apply(), 'PREEXISTING_REFUSED')
