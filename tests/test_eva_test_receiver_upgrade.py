import fcntl
from hashlib import sha256
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from article_test_state import canonical
import eva_test_bootstrap as bootstrap
import eva_test_receiver_upgrade_host as host

NATIVE_EXCHANGE = host._exchange


class ReceiverUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.libexec = Path(self.folder.name)
        self.old = {
            'forced-command': b'fixed command\n',
            'login-shell': b'fixed shell\n',
            'control.sha': b'old revision\n',
            'eva_test_host.py': b'old module\n',
            'eva_test_live_policy.json': b'old policy\n',
        }
        self.replacement = {
            'control.sha': b'new revision\n',
            'eva_test_host.py': b'fixed module\n',
            'eva_test_live_policy.json': b'fresh policy\n',
        }
        self.new = {**self.old, **self.replacement}
        self.manifest = {name: sha256(data).hexdigest() for name, data in self.old.items()}
        self.install = self.libexec / host.ACTIVE
        self.staging = self.libexec / host.STAGED
        self.write_package(self.install, self.old)
        self.parent = os.open(self.libexec, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.parent)
        for setup in (
            patch.object(host, '_root_owned', side_effect=lambda row: row.st_uid == os.geteuid()),
            patch.object(host, '_exchange', side_effect=self.exchange),
        ):
            setup.start()
            self.addCleanup(setup.stop)

    def write_package(self, path, files):
        path.mkdir(mode=0o755)
        (path / 'state').mkdir(mode=0o700)
        for name, raw in files.items():
            file = path / name
            file.write_bytes(raw)
            file.chmod(host._mode(name))

    def exchange(self, parent):
        temp = self.libexec / 'test-exchange'
        self.install.rename(temp)
        self.staging.rename(self.install)
        temp.rename(self.staging)

    def upgrade(self, replacement=None, **kwargs):
        return host.upgrade_package(
            self.parent, self.replacement if replacement is None else replacement,
            self.manifest, time.monotonic() + 3, **kwargs,
        )

    def test_exact_old_package_updates_and_becomes_idempotent(self):
        self.assertEqual(self.upgrade(), 'UPGRADED')
        self.assertEqual(self.upgrade(), 'ALREADY_CURRENT')
        self.assertEqual({name: (self.install / name).read_bytes() for name in self.new}, self.new)
        self.assertFalse(self.staging.exists())

    def test_wrong_old_manifest_and_out_of_scope_replacement_refuse(self):
        with self.assertRaises(ValueError):
            self.upgrade({**self.replacement, 'forced-command': b'no'})
        changed = self.install / 'eva_test_host.py'
        changed.chmod(0o600)
        changed.write_bytes(b'foreign module\n')
        changed.chmod(0o444)
        with self.assertRaises(ValueError):
            self.upgrade()
        self.assertEqual((self.install / 'eva_test_host.py').read_bytes(), b'foreign module\n')
        self.assertFalse(self.staging.exists())

    def test_idle_lock_refuses_current_work_and_active_leases(self):
        state_parent = self.libexec / 'varlib'
        state_parent.mkdir()
        state = state_parent / host.ACTIVE
        state.mkdir(mode=0o700)
        lock = state / '.lock'
        lock.touch(mode=0o600)
        descriptor = os.open(state_parent, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        with host.idle_receiver(descriptor) as check:
            check()
            with lock.open('wb') as other_lock, self.assertRaises(BlockingIOError):
                fcntl.flock(other_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (state / ('a' * 12)).mkdir()
        with self.assertRaises(BlockingIOError), host.idle_receiver(descriptor):
            self.fail('an active lease was allowed')

    @unittest.skipUnless(sys.platform == 'linux', 'renameat2 is Linux-specific')
    def test_native_atomic_exchange_changes_both_receiver_paths(self):
        self.write_package(self.staging, self.new)
        with patch.object(host, '_exchange', NATIVE_EXCHANGE):
            host._exchange(self.parent)
        self.assertEqual((self.install / 'control.sha').read_bytes(), self.new['control.sha'])
        self.assertEqual((self.staging / 'control.sha').read_bytes(), self.old['control.sha'])

    def test_refuses_symlink_and_unknown_backup(self):
        (self.install / 'control.sha').unlink()
        (self.install / 'control.sha').symlink_to(self.install / 'eva_test_host.py')
        with self.assertRaises(OSError):
            self.upgrade()
        (self.install / 'control.sha').unlink()
        (self.install / 'control.sha').write_bytes(self.old['control.sha'])
        (self.install / 'control.sha').chmod(0o444)
        self.staging.mkdir()
        (self.staging / 'other').write_bytes(b'foreign data')
        with self.assertRaises(ValueError):
            self.upgrade()
        self.assertEqual((self.staging / 'other').read_bytes(), b'foreign data')

    def test_recovery_removes_only_verified_old_residue(self):
        self.assertEqual(self.upgrade(), 'UPGRADED')
        self.write_package(self.staging, {'control.sha': self.old['control.sha']})
        self.assertEqual(self.upgrade(), 'ALREADY_CURRENT')
        self.assertFalse(self.staging.exists())

    def test_recovery_admits_only_a_prefix_of_the_exact_pending_file(self):
        self.write_package(self.staging, {'control.sha': self.new['control.sha']})
        pending = self.staging / (host.INCOMING + 'eva_test_host.py')
        pending.write_bytes(b'foreign data')
        pending.chmod(0o600)
        with self.assertRaises(ValueError):
            self.upgrade()
        self.assertEqual(pending.read_bytes(), b'foreign data')
        self.assertEqual((self.install / 'control.sha').read_bytes(), self.old['control.sha'])
        pending.write_bytes(self.new['eva_test_host.py'][:5])
        self.assertEqual(self.upgrade(), 'UPGRADED')
        self.assertFalse(self.staging.exists())

    def test_verify_failure_rolls_back_exact_original(self):
        verify = host._snapshot
        calls = 0

        def fail_verification_once(folder, manifest, deadline, **kwargs):
            nonlocal calls
            if set(manifest) == set(self.manifest) and manifest['control.sha'] != self.manifest['control.sha']:
                calls += 1
                if calls == 3:
                    raise ValueError('synthetic verification failure after exchange')
            return verify(folder, manifest, deadline, **kwargs)

        with patch.object(host, '_snapshot', side_effect=fail_verification_once):
            self.assertEqual(self.upgrade(), 'ROLLED_BACK')
        self.assertEqual({name: (self.install / name).read_bytes() for name in self.old}, self.old)
        self.assertFalse(self.staging.exists())


class ReceiverUpgradeControlTests(unittest.TestCase):
    sha = '1' * 40
    nonce = '2' * 32
    policy = {
        'status': 'PINNED', 'ingress': 'existing-apache',
        'origin': 'https://eva-isolated-1620.jsmjapan.com',
        'provider_ipv4': '8.8.4.4', 'vhost_sha256': '3' * 64, 'certificate_sha256': '4' * 64,
    }

    def test_capsule_proves_source_scope_and_compiles(self):
        real_read = bootstrap._read_regular

        def synthetic_candidate(path, limit):
            if path.name == 'eva_test_host.py':
                return b'# synthetic fixed module for the capsule test\n'
            return real_read(path, limit)

        with patch.object(bootstrap, '_read_regular', side_effect=synthetic_candidate):
            encoded = bootstrap.upgrade_capsule(self.nonce, self.sha, self.policy)
            compile(encoded, '<test capsule>', 'exec')
            self.assertLess(len(encoded), 110000)
            with self.assertRaisesRegex(ValueError, 'EVA_BOOTSTRAP_CONTEXT_REFUSED'):
                bootstrap.upgrade_capsule(self.nonce, bootstrap.PREVIOUS_SHA, self.policy)

    def test_upgrade_reuses_exact_owner_checks_before_fresh_preflight(self):
        envelope = canonical({
            'version': 'jsm-test-installed-route-outer-v2', 'nonce': self.nonce,
            'principal': 'marinagurina', 'euid': 1001,
            'root_diagnostic': {'version': bootstrap.UPGRADE_VERSION, 'nonce': self.nonce, 'euid': 0,
                                'status': 'UPGRADED'},
        })
        env = {'OPERATION': 'UPGRADE_RECEIVER', 'APPROVED_SCOPE': bootstrap.UPGRADE_SCOPE,
               'GITHUB_SHA': self.sha, 'GITHUB_RUN_ID': '123', 'ROUTE_PREFLIGHT_RUN': '234'}
        with (patch.object(bootstrap, 'authorize') as authorize,
              patch.object(bootstrap, 'approved_policy', return_value=self.policy) as approved_policy,
              patch.object(bootstrap, '_receive', return_value=(envelope, self.nonce)) as receive,
              patch.object(bootstrap, 'verified_key') as key):
            self.assertEqual(bootstrap.execute(env), {'status': 'UPGRADED'})
            self.assertEqual(authorize.call_args.kwargs, {'environment_name': bootstrap.ADMIN_ENV, 'job': 'bootstrap'})
            approved_policy.assert_called_once_with('234', self.sha)
            receive.assert_called_once()
            key.assert_not_called()
            receive.reset_mock()
            with self.assertRaisesRegex(ValueError, 'EVA_BOOTSTRAP_CONTEXT_REFUSED'):
                bootstrap.execute({**env, 'APPROVED_SCOPE': bootstrap.SCOPE})
            receive.assert_not_called()


if __name__ == '__main__':
    unittest.main()
