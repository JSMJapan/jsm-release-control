"""Exercise disposable staging using only synthetic local PHP source bytes."""

from hashlib import sha256
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import test_db_control_staging as staging


NONCE = 'c0' * 16
SOURCES = {name: b'<?php /* synthetic */' + name.encode('ascii') for name in staging._STAGING_NAMES}


class StagingTests(unittest.TestCase):
    def setUp(self):
        location = tempfile.TemporaryDirectory()
        self.addCleanup(location.cleanup)
        self.root = Path(location.name)
        self.path = self.root / ('jsm-db-2760-' + NONCE)

    def stage(self):
        return staging.staged_php(str(self.root), NONCE, SOURCES)

    def test_pinned_contents_modes_and_normal_cleanup(self):
        with self.stage() as result:
            self.assertEqual(Path(result['path']), self.path)
            info = self.path.stat()
            self.assertEqual((result['device'], result['inode']), (info.st_dev, info.st_ino))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o711)
            self.assertEqual(set(result['files']), set(SOURCES))
            for name, raw in SOURCES.items():
                file = self.path / name
                self.assertEqual(file.read_bytes(), raw)
                info = file.stat()
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
                self.assertEqual(result['files'][name], dict(device=info.st_dev, inode=info.st_ino,
                                                             size=len(raw), sha256=sha256(raw).hexdigest()))
        self.assertFalse(self.path.exists())

    def test_setup_failure_after_partial_write_cleans_exact_files(self):
        original = os.write
        attempts = 0

        def interrupted(fd, data):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise OSError('synthetic detail')
            return original(fd, data[:5])

        with patch.object(staging.os, 'write', side_effect=interrupted):
            with self.assertRaises(staging.StagingRefused):
                with self.stage():
                    self.fail('unexpected ready state')
        self.assertFalse(self.path.exists())

    def test_failure_in_body_preserves_error_and_cleans(self):
        with self.assertRaisesRegex(RuntimeError, 'test failure'):
            with self.stage():
                raise RuntimeError('test failure')
        self.assertFalse(self.path.exists())

    def test_unconfirmed_request_is_sealed_and_kept_for_recovery(self):
        with self.assertRaises(staging.CleanupUnconfirmed):
            with self.stage():
                raise staging.DeferCleanup()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
        self.assertEqual({file.name: file.read_bytes() for file in self.path.iterdir()}, SOURCES)

    def test_replaced_leaf_is_preserved(self):
        name = next(iter(SOURCES))
        with self.assertRaises(staging.CleanupUnconfirmed):
            with self.stage():
                file = self.path / name
                file.unlink()
                file.write_bytes(b'independent file')
        self.assertEqual((self.path / name).read_bytes(), b'independent file')
        self.assertEqual(set(self.path.iterdir()), {self.path / name})

    def test_replaced_directory_is_preserved(self):
        renamed = self.root / 'independent-location'
        with self.assertRaises(staging.CleanupUnconfirmed):
            with self.stage():
                self.path.rename(renamed)
                self.path.mkdir()
                (self.path / 'unrelated').write_bytes(b'independent file')
        self.assertEqual((self.path / 'unrelated').read_bytes(), b'independent file')
        self.assertEqual(set(item.name for item in renamed.iterdir()), set(SOURCES))

    def test_remains_if_an_unknown_file_appears(self):
        name = 'unexpected'
        with self.assertRaises(staging.CleanupUnconfirmed):
            with self.stage():
                (self.path / name).write_bytes(b'independent file')
        self.assertEqual(set(self.path.iterdir()), {self.path / name})

    def test_bad_sources_nonce_symlink_and_existing_directory_refuse(self):
        with self.assertRaises(staging.StagingRefused):
            with staging.staged_php(str(self.root), NONCE, dict(SOURCES, unrelated=b'invalid')):
                self.fail()
        with self.assertRaises(staging.StagingRefused):
            with staging.staged_php(str(self.root), '../not-a-nonce', SOURCES):
                self.fail()
        link = self.root / 'root-link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(staging.StagingRefused):
            with staging.staged_php(str(link), NONCE, SOURCES):
                self.fail()
        self.path.mkdir()
        with self.assertRaises(staging.StagingRefused):
            with self.stage():
                self.fail()
        self.assertTrue(self.path.is_dir())


if __name__ == '__main__':
    unittest.main()
