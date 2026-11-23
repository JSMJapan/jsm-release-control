import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from apache_parity_bridge import Refused
import test_php_manifest_readonly as profile


NONCE = 'a' * 32


def payload(child):
    return json.dumps(dict(
        version='jsm-test-installed-route-outer-v2', nonce=NONCE,
        euid=1000, principal='marinagurina', root_diagnostic=child,
    )).encode('ascii')


def child(status='MATCH'):
    return dict(
        nonce=NONCE, euid=0, version=profile.VERSION, fpm_root='STABLE',
        files={file_id: status for file_id in profile.MANIFEST},
        php_loopback_3306='UNKNOWN',
    )


class ManifestRunnerTests(unittest.TestCase):
    def test_a_disk_match_does_not_admit_sql_or_database(self):
        result = profile.project_remote(payload(child()), NONCE)
        self.assertEqual(result['manifest'], 'MATCH')
        self.assertEqual(result['active_api_binding'], 'NOT_ESTABLISHED')
        self.assertEqual(result['db_isolation'], 'NOT_ESTABLISHED')
        self.assertEqual(result['sql'], 'NOT_ATTEMPTED')

    def test_untrusted_fields_and_cross_run_nonce_are_rejected(self):
        candidate = child()
        candidate['files']['api_entry'] = dict(sha256='b' * 64)
        with self.assertRaises(Refused):
            profile.project_remote(payload(candidate), NONCE)
        candidate = child()
        candidate['nonce'] = 'b' * 32
        with self.assertRaises(Refused):
            profile.project_remote(payload(candidate), NONCE)
        candidate = child()
        candidate['unexpected'] = 'not for logs'
        with self.assertRaises(Refused):
            profile.project_remote(payload(candidate), NONCE)

    def test_unstable_fpm_root_cannot_report_positive_evidence(self):
        candidate = child()
        candidate['fpm_root'] = 'UNKNOWN'
        with self.assertRaises(Refused):
            profile.project_remote(payload(candidate), NONCE)
        candidate['files'] = {key: 'UNKNOWN' for key in profile.MANIFEST}
        self.assertEqual(profile.project_remote(payload(candidate), NONCE)['manifest'], 'UNKNOWN')

    def test_different_sha_or_workflow_stops_before_access(self):
        env = dict(profile.CONTEXT, GITHUB_SHA='1' * 40, GITHUB_WORKFLOW_SHA='1' * 40,
                   GITHUB_RUN_ID='1234', APPROVED_SHA='2' * 40)
        with patch.object(profile, '_receive') as remote, patch.object(profile, 'verify_policy') as policy:
            with self.assertRaises(Refused):
                profile.collect(None, env)
            policy.assert_not_called()
            remote.assert_not_called()

    def test_fixed_scope_and_root_capsule(self):
        self.assertEqual(len(profile.MANIFEST), 8)
        for relative, size, fingerprint in profile.MANIFEST.values():
            self.assertNotIn('.env', relative)
            self.assertNotIn('-local.php', relative)
            self.assertLessEqual(size, 32768)
            self.assertRegex(fingerprint, r'^[0-9a-f]{64}$')
        program = profile.root_program(NONCE)
        compile(program, '<fixed root observer>', 'exec')
        for forbidden in ('/srv/jsm/app/backend/.env', 'getDsn(', 'SELECT DATABASE'):
            self.assertNotIn(forbidden, program)


class CapsuleFixtureTests(unittest.TestCase):
    def setUp(self):
        self.ns = {}
        exec(profile.root_library(), self.ns)

    def use_lock_fixture(self, fd):
        self.ns['_manifest_lock'] = lambda *_: os.dup(fd)
        self.ns['_manifest_lock_path'] = lambda *_: ((), self.ns['_manifest_stamp'](os.fstat(fd)))

    def test_changed_generation_invalidates_every_observation(self):
        first = child()['files']
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY)
            self.ns['_manifest_root'] = lambda *_: os.dup(fd)
            self.ns['_observe_php_endpoint'] = lambda *_: {'state': 'UNKNOWN'}
            self.ns['_manifest_read_files'] = lambda *_: first
            self.use_lock_fixture(fd)
            calls = iter([('first', 123), ('second', 124)])
            self.ns['_manifest_snapshot'] = lambda _until: next(calls)
            self.ns['os_geteuid'] = lambda: 0
            try:
                data = self.ns['_read_php_manifest'](NONCE)
            finally:
                os.close(fd)
        self.assertEqual(data['fpm_root'], 'UNKNOWN')
        self.assertEqual(set(data['files'].values()), {'UNKNOWN'})

    def test_stable_projection_passes_only_closed_file_statuses(self):
        available = {role: ('MATCH', ('private identity',), ()) for role in profile.MANIFEST}
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY)
            self.use_lock_fixture(fd)
            self.ns['_manifest_root'] = lambda *_: os.dup(fd)
            self.ns['_manifest_snapshot'] = lambda *_: ('unchanged', 123)
            self.ns['_observe_php_endpoint'] = lambda *_: {'state': 'OBSERVED'}
            self.ns['_manifest_read_files'] = lambda *_: available
            self.ns['os_geteuid'] = lambda: 0
            try:
                data = self.ns['_read_php_manifest'](NONCE)
            finally:
                os.close(fd)
        result = profile.project_remote(payload(data), NONCE)
        self.assertEqual(result['manifest'], 'MATCH')
        self.assertEqual(result['php_loopback_3306'], 'OBSERVED')
        self.assertNotIn('private identity', json.dumps(result))

    @unittest.skipUnless(hasattr(os, 'O_PATH') and hasattr(os, 'O_NOATIME'), 'Linux path anchors')
    def test_regular_file_match_and_refusal_of_links(self):
        example = b'<?php\n'
        row = ('entry.php', len(example), hashlib.sha256(example).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'entry.php').write_bytes(example)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                read = self.ns['_manifest_probe']
                after = time.monotonic() + 2
                self.ns['_MANIFEST_TRUSTED_UID'] = os.getuid() + 1
                with self.assertRaises(ValueError):
                    read(fd, row, after)
                self.ns['_MANIFEST_TRUSTED_UID'] = os.getuid()
                self.assertEqual(read(fd, row, after)[0], 'MATCH')
                (path / 'entry.php').write_bytes(b'q' * len(example))
                self.assertEqual(read(fd, row, after)[0], 'MISMATCH')
                (path / 'entry.php').rename(path / 'outside.php')
                (path / 'entry.php').symlink_to('outside.php')
                with self.assertRaises(ValueError):
                    read(fd, row, after)
                (path / 'entry.php').unlink()
                os.link(path / 'outside.php', path / 'entry.php')
                with self.assertRaises(ValueError):
                    read(fd, row, after)
            finally:
                os.close(fd)
