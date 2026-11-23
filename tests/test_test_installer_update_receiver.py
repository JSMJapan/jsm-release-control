"""Exercise the TEST installer receiver against an isolated synthetic tree."""

from contextlib import ExitStack, redirect_stdout
import fcntl
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import test_installer_update_receiver as receiver


ORIGINAL = b'#!/bin/sh\nprintf "synthetic original\\n"\n'
UPDATED = b'#!/bin/sh\nprintf "synthetic updated\\n"\n'
REPORTER = b'#!/bin/sh\nprintf "synthetic reporter\\n"\n'


def request(operation):
    return (json.dumps(dict(version=receiver.PROTOCOL, operation=operation), sort_keys=True,
                       separators=(',', ':')) + '\n').encode('ascii')


class FixtureOs:
    """Exercise real file operations, with a Mac stand-in for Linux-only flags."""

    O_PATH = getattr(os, 'O_PATH', 1 << 29)
    O_NOATIME = getattr(os, 'O_NOATIME', 1 << 30)

    def __init__(self):
        self.read_anchors = []

    def __getattr__(self, name):
        return getattr(os, name)

    def listxattr(self, fd):
        if hasattr(os, 'listxattr'):
            return os.listxattr(fd)
        return []

    def open(self, path, flags, *args, **kwargs):
        if path.startswith('/proc/self/fd/'):
            anchor = int(path.rsplit('/', 1)[-1])
            self.read_anchors.append(os.fstat(anchor))
            if not hasattr(os, 'O_PATH'):
                return os.dup(anchor)
        if not hasattr(os, 'O_PATH') and flags & self.O_PATH:
            flags = (flags & ~self.O_PATH) | os.O_NONBLOCK
        return os.open(path, flags, *args, **kwargs)


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        for chain in (receiver._TARGET_CHAIN, receiver._REPORTER_CHAIN, receiver._LOCK_CHAIN, receiver._STATE_CHAIN):
            self.root.joinpath(*chain).mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state = self.root.joinpath(*receiver._STATE_CHAIN)
        self.previous = self.state / receiver._PREVIOUS
        self.candidate = self.state / receiver._CANDIDATE
        self.target = self.root.joinpath(*receiver._TARGET_CHAIN, receiver._TARGET)
        self.lock = self.root.joinpath(*receiver._LOCK_CHAIN, receiver._LOCK)
        self.reporter = self.root.joinpath(*receiver._REPORTER_CHAIN, receiver._REPORTER)
        self.pin = self.root.joinpath(*receiver._REPORTER_CHAIN, receiver._REPORTER_PIN)
        self.target.write_bytes(ORIGINAL)
        self.target.chmod(0o750)
        self.lock.write_bytes(b'')
        self.reporter.write_bytes(REPORTER)
        self.reporter.chmod(0o700)
        self.pin.write_text(sha256(REPORTER).hexdigest() + '\n', encoding='ascii')

        self.fixture_os = FixtureOs()
        stack.enter_context(patch.object(receiver, 'os', self.fixture_os))
        stack.enter_context(patch.object(receiver, '_host_matches', return_value=True))
        stack.enter_context(patch.object(receiver, '_open_chain', side_effect=self.open_chain))
        stack.enter_context(patch.object(receiver, '_safe_mode', side_effect=self.safe_fixture_mode))
        stack.enter_context(patch.object(receiver, 'ORIGINAL_SHA256', sha256(ORIGINAL).hexdigest()))
        stack.enter_context(patch.object(receiver, 'UPDATED_SHA256', sha256(UPDATED).hexdigest()))
        self.transform = stack.enter_context(patch.object(receiver, 'transform', side_effect=self.transform_fixture))

    @staticmethod
    def safe_fixture_mode(info):
        return info.st_uid == os.getuid() and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)

    def open_chain(self, parts):
        self.assertIn(parts, (receiver._TARGET_CHAIN, receiver._REPORTER_CHAIN, receiver._LOCK_CHAIN, receiver._STATE_CHAIN))
        descriptors = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            descriptors.append(os.open(self.root, flags))
            for part in parts:
                descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
            return descriptors
        except BaseException:
            for fd in reversed(descriptors):
                os.close(fd)
            raise

    @staticmethod
    def transform_fixture(data, operation):
        if data == ORIGINAL:
            return ('ALREADY_ORIGINAL', None) if operation == 'ROLLBACK' else (
                'READY', UPDATED if operation == 'APPLY' else None)
        if data == UPDATED:
            return ('READY', ORIGINAL) if operation == 'ROLLBACK' else ('ALREADY_APPLIED', None)
        return 'PREIMAGE_REFUSED', None

    def assert_target(self, data):
        self.assertEqual(self.target.read_bytes(), data)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o750)
        self.assertEqual(list(self.target.parent.iterdir()), [self.target])

    def test_reject_command_extras_noncanonical_encodings_and_unknown_operations_before_host(self):
        valid = request('APPLY')
        for raw in (b'', bytearray(valid), valid.rstrip(), b' ' + valid, b'\xff',
                    request('REMOVE'), valid.replace(b'{', b'{"operation":"ROLLBACK",', 1),
                    valid.replace(b'{', b'{"path":"/arbitrary",', 1), valid + b'\x00' * 128):
            with self.subTest(raw=raw), patch.object(receiver, '_host_matches') as host:
                self.assertEqual(receiver.handle(raw), 'REQUEST_REFUSED')
                host.assert_not_called()
        self.transform.assert_not_called()
        self.assert_target(ORIGINAL)

    def test_wrong_host_or_failed_attestation_refuses_before_any_paths(self):
        for result in (False, TimeoutError('synthetic private failure')):
            with self.subTest(result=result):
                with patch.object(receiver, '_host_matches', side_effect=[result]), \
                        patch.object(receiver, '_open_chain') as paths:
                    self.assertEqual(receiver.handle(request('APPLY')), 'TARGET_REFUSED')
                    paths.assert_not_called()
        self.transform.assert_not_called()
        self.assert_target(ORIGINAL)

    def test_missing_or_tampered_reporter_prevents_apply(self):
        self.pin.unlink()
        self.assertEqual(receiver.handle(request('APPLY')), 'REPORTER_UNAVAILABLE')
        self.assert_target(ORIGINAL)
        self.pin.write_text('0' * 64 + '\n', encoding='ascii')
        self.assertEqual(receiver.handle(request('APPLY')), 'REPORTER_UNAVAILABLE')
        self.assert_target(ORIGINAL)

    def test_check_apply_idempotence_and_rollback_without_reporter(self):
        original_inode = self.target.stat().st_ino
        self.assertEqual(receiver.handle(request('CHECK')), 'READY')
        self.assertEqual(self.target.stat().st_ino, original_inode)
        self.assert_target(ORIGINAL)

        self.assertEqual(receiver.handle(request('APPLY')), 'APPLIED')
        updated_inode = self.target.stat().st_ino
        self.assertNotEqual(updated_inode, original_inode)
        self.assert_target(UPDATED)
        self.assertEqual(receiver.handle(request('APPLY')), 'ALREADY_APPLIED')
        self.assertEqual(self.target.stat().st_ino, updated_inode)

        self.reporter.unlink()
        self.pin.unlink()
        self.assertEqual(receiver.handle(request('ROLLBACK')), 'ROLLED_BACK')
        self.assert_target(ORIGINAL)
        self.assertEqual(receiver.handle(request('ROLLBACK')), 'ALREADY_ORIGINAL')

    def test_check_can_close_uncertainty_even_when_reporter_is_missing(self):
        self.reporter.unlink()
        self.assertEqual(receiver.handle(request('CHECK')), 'ORIGINAL_NO_REPORTER')
        self.assert_target(ORIGINAL)
        self.target.write_bytes(UPDATED)
        self.assertEqual(receiver.handle(request('CHECK')), 'UPDATED_NO_REPORTER')
        self.assert_target(UPDATED)

    def test_exact_preimage_and_replacement_digests_are_required(self):
        tampered = ORIGINAL[:-1] + b'!'
        self.target.write_bytes(tampered)
        self.assertEqual(receiver.handle(request('APPLY')), 'PREIMAGE_REFUSED')
        self.assert_target(tampered)

        self.target.write_bytes(ORIGINAL)
        self.transform.side_effect = None
        self.transform.return_value = ('READY', b'unpinned replacement')
        self.assertEqual(receiver.handle(request('APPLY')), 'PREIMAGE_REFUSED')
        self.assert_target(ORIGINAL)

    def test_unmanaged_extended_attributes_refuse_replacement(self):
        with patch.object(self.fixture_os, 'listxattr', return_value=['system.posix_acl_access']):
            self.assertEqual(receiver.handle(request('APPLY')), 'TARGET_REFUSED')
        self.transform.assert_not_called()
        self.assert_target(ORIGINAL)

    def test_lock_contention_blocks_without_touching_target(self):
        with self.lock.open('rb') as locked:
            fcntl.flock(locked.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(receiver.handle(request('APPLY')), 'LOCK_REFUSED')
        self.transform.assert_not_called()
        self.assert_target(ORIGINAL)

    def test_target_symlink_hardlink_and_untrusted_parent_are_refused(self):
        other = self.root / 'unrelated'
        self.target.rename(other)
        self.target.symlink_to(other)
        self.assertEqual(receiver.handle(request('APPLY')), 'TARGET_REFUSED')
        self.target.unlink()
        os.link(other, self.target)
        self.assertEqual(receiver.handle(request('APPLY')), 'TARGET_REFUSED')
        self.target.unlink()
        other.rename(self.target)
        self.target.parent.chmod(0o770)
        self.assertEqual(receiver.handle(request('APPLY')), 'TARGET_REFUSED')
        self.assert_target(ORIGINAL)

    def test_special_file_substituted_before_anchor_is_never_opened_for_reading(self):
        real_open = self.fixture_os.open

        def substitute_fifo(path, flags, *args, **kwargs):
            if path == receiver._TARGET and flags & self.fixture_os.O_PATH:
                self.target.unlink()
                os.mkfifo(self.target)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(self.fixture_os, 'open', side_effect=substitute_fifo):
            self.assertEqual(receiver.handle(request('APPLY')), 'TARGET_REFUSED')
        self.assertTrue(stat.S_ISFIFO(self.target.lstat().st_mode))
        self.assertEqual(len(self.fixture_os.read_anchors), 1)
        self.assertEqual(self.fixture_os.read_anchors[0].st_ino, self.lock.stat().st_ino)
        self.transform.assert_not_called()

    def test_changed_target_after_staging_is_not_overwritten(self):
        stage = receiver._stage
        intervening = b'independent concurrent replacement'

        def change_after_stage(*args, **kwargs):
            staged = stage(*args, **kwargs)
            if staged.name != receiver._STAGED:
                return staged
            sibling = self.root / 'intervening'
            sibling.write_bytes(intervening)
            sibling.chmod(0o750)
            sibling.replace(self.target)
            return staged

        with patch.object(receiver, '_stage', side_effect=change_after_stage):
            self.assertEqual(receiver.handle(request('APPLY')), 'WRITE_REFUSED')
        self.assert_target(intervening)

    def test_postcommit_readback_failure_reports_uncertainty_and_retains_new_inode(self):
        with patch.object(receiver, '_readback', side_effect=ValueError('private detail')):
            self.assertEqual(receiver.handle(request('APPLY')), 'READBACK_UNCERTAIN')
        self.assert_target(UPDATED)

    def test_previous_and_candidate_are_present_and_synced_before_install_replace(self):
        synced = set()

        def record_sync(fd):
            info = os.fstat(fd)
            synced.add((info.st_dev, info.st_ino))
            os.fsync(fd)

        def verify_pins_before_replace(source, destination, **kwargs):
            if destination != receiver._TARGET:
                os.replace(source, destination, **kwargs)
                return
            self.assertEqual(self.previous.read_bytes(), ORIGINAL)
            for path in (self.previous, self.candidate, self.state):
                info = path.stat()
                self.assertIn((info.st_dev, info.st_ino), synced)
            self.assertEqual(self.candidate.stat().st_nlink, 2)
            os.replace(source, destination, **kwargs)

        with patch.object(self.fixture_os, 'fsync', side_effect=record_sync), \
                patch.object(self.fixture_os, 'replace', side_effect=verify_pins_before_replace):
            self.assertEqual(receiver.handle(request('APPLY')), 'APPLIED')
        self.assertEqual(self.candidate.stat().st_ino, self.target.stat().st_ino)

    def test_recover_uncertain_candidate_even_if_its_bytes_were_corrupted(self):
        with patch.object(receiver, '_readback', side_effect=ValueError()):
            self.assertEqual(receiver.handle(request('APPLY')), 'READBACK_UNCERTAIN')
        self.assertEqual(self.previous.read_bytes(), ORIGINAL)
        self.assertEqual(stat.S_IMODE(self.previous.stat().st_mode), 0o600)
        self.assertEqual(self.candidate.stat().st_ino, self.target.stat().st_ino)
        self.target.write_bytes(b'corrupted bytes on exact installed inode')
        self.assertEqual(receiver.handle(request('ROLLBACK')), 'PREIMAGE_REFUSED')
        self.assertEqual(receiver.handle(request('RECOVER')), 'RECOVERED')
        self.assert_target(ORIGINAL)
        self.assertFalse(self.candidate.exists())

    def test_recover_never_overwrites_third_inode_or_accepts_tampered_backup(self):
        self.assertEqual(receiver.handle(request('APPLY')), 'APPLIED')
        self.previous.write_bytes(b'bad previous')
        self.assertEqual(receiver.handle(request('RECOVER')), 'RECOVERY_REFUSED')
        self.assert_target(UPDATED)
        self.previous.write_bytes(ORIGINAL)
        self.target.unlink()
        self.target.write_bytes(UPDATED)
        self.target.chmod(0o750)
        third = self.target.stat().st_ino
        self.assertEqual(receiver.handle(request('RECOVER')), 'RECOVERY_REFUSED')
        self.assertEqual(self.target.stat().st_ino, third)
        self.assert_target(UPDATED)

    def test_retry_after_interruption_between_durable_pin_and_replace(self):
        staged = self.state / receiver._STAGED
        staged.write_bytes(UPDATED)
        staged.chmod(0o750)
        os.link(staged, self.candidate)
        old_candidate = os.open(self.candidate, os.O_RDONLY)
        self.addCleanup(os.close, old_candidate)

        self.assertEqual(receiver.handle(request('APPLY')), 'APPLIED')
        self.assert_target(UPDATED)
        self.assertFalse(staged.exists())
        self.assertNotEqual(self.candidate.stat().st_ino, os.fstat(old_candidate).st_ino)
        self.assertEqual(self.candidate.stat().st_ino, self.target.stat().st_ino)

    def test_retry_after_restore_commits_before_pin_retirement(self):
        self.assertEqual(receiver.handle(request('APPLY')), 'APPLIED')
        with patch.object(receiver, '_retire_candidate', side_effect=OSError()):
            self.assertEqual(receiver.handle(request('ROLLBACK')), 'READBACK_UNCERTAIN')
        self.assert_target(ORIGINAL)
        self.assertEqual(self.candidate.stat().st_nlink, 1)

        self.assertEqual(receiver.handle(request('APPLY')), 'APPLIED')
        self.assert_target(UPDATED)
        self.assertEqual(self.candidate.stat().st_ino, self.target.stat().st_ino)

    def test_conflicting_transaction_entries_preserve_current_original(self):
        staged = self.state / receiver._STAGED
        staged.write_bytes(UPDATED)
        self.candidate.write_bytes(UPDATED)
        self.assertEqual(receiver.handle(request('APPLY')), 'RECOVERY_REFUSED')
        self.assert_target(ORIGINAL)
        self.assertEqual(staged.read_bytes(), UPDATED)
        self.assertEqual(self.candidate.read_bytes(), UPDATED)

    def test_nonprivate_recovery_directory_blocks_apply_before_target_change(self):
        self.state.chmod(0o750)
        self.assertEqual(receiver.handle(request('APPLY')), 'RECOVERY_REFUSED')
        self.assert_target(ORIGINAL)
        self.assertFalse(self.previous.exists())

    def test_main_returns_only_closed_json(self):
        output = io.StringIO()
        with patch.object(receiver, '_read_request', return_value=request('CHECK')), redirect_stdout(output):
            self.assertEqual(receiver.main([receiver.PROTOCOL]), 0)
        self.assertEqual(json.loads(output.getvalue()), {'version': receiver.PROTOCOL, 'status': 'READY'})


if __name__ == '__main__':
    unittest.main()
