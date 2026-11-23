"""Offline tests for the exact historical TEST publisher capture capsule."""
import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import test_publisher_capture_capsule as capsule


NONCE = 'a' * 32
PEM = (ROOT / 'scripts/test_installer_recipient.pem').read_bytes()
PEM_SHA = hashlib.sha256(PEM).hexdigest()
FIXTURE = b'public synthetic publisher data'.ljust(255, b'.')
FIXTURE_SHA = hashlib.sha256(FIXTURE).hexdigest()
CIPHERTEXT = b'synthetic CMS output for the filesystem-only fixture'
WITNESS = (b'synthetic issuer and serial', 384, bytes(12), 1)


class RecordingOs:
    """Delegate filesystem operations, recording only synthetic file access."""
    O_NOATIME = getattr(os, 'O_NOATIME', 1 << 30)
    O_PATH = getattr(os, 'O_PATH', 1 << 29)

    def __init__(self, leaf, root):
        self.leaf = leaf
        self.root = root
        self.traversals = []
        self.anchors = []
        self.opens = []
        self.reads = []

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, *args, **kwargs):
        if path == self.leaf:
            self.anchors.append(flags)
        elif path.startswith('/proc/self/fd/'):
            self.opens.append(flags)
            if not hasattr(os, 'O_PATH'):
                # Mac lacks the pinned Linux procfs open. Simulate it against
                # the already opened local test descriptor, with no host I/O.
                return os.dup(int(path.rsplit('/', 1)[1]))
        else:
            assert flags & os.O_DIRECTORY and flags & os.O_NOFOLLOW
            assert path in ('/', 'usr', 'local', 'sbin', 'bin')
            self.traversals.append(path)
            if path == '/':
                path = self.root
        if not hasattr(os, 'O_PATH') and flags & self.O_PATH:
            flags = (flags & ~self.O_PATH) | os.O_NONBLOCK
        if not hasattr(os, 'O_NOATIME'):
            # Linux verifies the real flag and the actual atime, while this
            # local stand-in keeps the same source-path tests runnable on Mac.
            flags &= ~self.O_NOATIME
        return os.open(path, flags, *args, **kwargs)

    def read(self, fd, count):
        self.reads.append(count)
        return os.read(fd, count)


class PublisherCapsuleTests(unittest.TestCase):
    def capsule(self):
        code = capsule.render(NONCE, PEM, PEM_SHA)
        before, footer = code.rsplit('\n_main(', 1)
        self.assertTrue(footer.strip().endswith(')'))
        namespace = {}
        exec(compile(before, '<publisher-capsule-definitions>', 'exec'), namespace)
        return namespace

    def fixture(self, present, *, body=FIXTURE, mutate=None, bad_preflight=False,
                unsafe=None, replaced_sha=FIXTURE_SHA):
        namespace = self.capsule()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        local = base / 'usr/local'
        local.mkdir(parents=True)
        slots = {name: local / name for name in ('sbin', 'bin')}
        for directory in slots.values():
            directory.mkdir()
        leaf_name = namespace['_WRAPPER_LEAF']
        leaves = {name: directory / leaf_name for name, directory in slots.items()}
        for name in present:
            leaves[name].write_bytes(body)
            leaves[name].chmod(0o700)
        if unsafe == 'symlink':
            target = base / 'synthetic-target'
            target.write_bytes(FIXTURE)
            leaves['bin'].symlink_to(target)
        elif unsafe == 'hardlink':
            os.link(leaves['sbin'], base / 'synthetic-hard-link')
        elif unsafe == 'writable':
            leaves['sbin'].chmod(0o722)
        elif unsafe == 'writable-parent':
            slots['bin'].chmod(0o777)
        elif unsafe == 'parent-symlink':
            slots['bin'].rmdir()
            slots['bin'].symlink_to(slots['sbin'], target_is_directory=True)
        crypto = []
        recorded = RecordingOs(leaf_name, base)
        original_safe_mode = namespace['_safe_mode']

        def test_owner(row):
            # The CI fixture owner stands in for uid 0. Real lstat/fstat
            # fields still drive identity, symlink, mode and race decisions.
            owner = 0 if row.st_uid == os.getuid() else row.st_uid
            return original_safe_mode(SimpleNamespace(st_uid=owner, st_mode=row.st_mode))

        def preflight(pem, digest, _deadline):
            self.assertEqual(pem, PEM)
            self.assertEqual(digest, PEM_SHA)
            if bad_preflight:
                raise ValueError('private synthetic refusal')
            return os.open(os.devnull, os.O_RDONLY), WITNESS

        def cms(data, _cert_fd, _deadline):
            crypto.append(bytes(data))
            if mutate is not None:
                mutate(leaves)
            return CIPHERTEXT

        def envelope(data):
            self.assertEqual(data, CIPHERTEXT)
            return WITNESS[:2] + (bytes([1]) + bytes(11), len(FIXTURE))

        namespace.update(os=recorded, _safe_mode=test_owner,
                         _preflight=preflight, _cms=cms, _envelope=envelope, _WRAPPER_SHA256=replaced_sha)
        return namespace, leaves, recorded.traversals, recorded, crypto

    def capture(self, fixture):
        namespace, _, _, _, _ = fixture
        return namespace['_capture'](PEM, PEM_SHA, time.monotonic() + 3)

    def test_renderer_pins_exact_two_paths_size_digest_recipient_and_closed_statuses(self):
        namespace = self.capsule()
        self.assertEqual(namespace['_SLOTS'], (('usr', 'local', 'sbin'), ('usr', 'local', 'bin')))
        self.assertEqual(namespace['_WRAPPER_LEAF'], 'jsm-sandbox-publish')
        self.assertEqual(namespace['_WRAPPER_SIZE'], 255)
        self.assertRegex(namespace['_WRAPPER_SHA256'], re.compile(r'\A[0-9a-f]{64}\Z'))
        self.assertEqual(set(capsule.STATUSES), {'CAPTURED', 'PREFLIGHT_REFUSED', 'PATH_REFUSED',
            'SOURCE_CHANGED', 'HISTORICAL_DIGEST_MISMATCH', 'ENCRYPTION_REFUSED'})
        for args in (('wrong', PEM, PEM_SHA), (NONCE, PEM + b'junk', PEM_SHA)):
            with self.assertRaises(ValueError):
                capsule.render(*args)

    def test_single_historical_leaf_in_either_slot_is_captured_with_noatime(self):
        for selected in ('sbin', 'bin'):
            with self.subTest(slot=selected):
                fixture = self.fixture((selected,))
                _, leaves, traversals, recorded, crypto = fixture
                os.utime(leaves[selected], ns=(1_600_000_000_000_000_000, 1_700_000_000_000_000_000))
                before = leaves[selected].stat().st_atime_ns
                self.assertEqual(self.capture(fixture), ('CAPTURED', base64.b64encode(CIPHERTEXT).decode('ascii')))
                self.assertEqual(crypto, [FIXTURE])
                self.assertEqual(len(recorded.opens), 1)
                self.assertTrue(recorded.opens[0] & recorded.O_NOATIME)
                self.assertEqual(recorded.anchors, [recorded.O_PATH | os.O_NOFOLLOW])
                self.assertTrue({'sbin', 'bin'}.issubset(traversals))
                if hasattr(os, 'O_NOATIME'):
                    self.assertEqual(leaves[selected].stat().st_atime_ns, before)

    def test_failed_preflight_never_traverses_or_reads_either_slot(self):
        fixture = self.fixture(('sbin',), bad_preflight=True)
        _, _, traversals, recorded, crypto = fixture
        self.assertEqual(self.capture(fixture), ('PREFLIGHT_REFUSED', None))
        self.assertEqual(traversals, [])
        self.assertEqual(recorded.opens, [])
        self.assertEqual(recorded.reads, [])
        self.assertEqual(crypto, [])

    def test_ambiguous_unsafe_or_wrong_sized_leaves_are_never_read(self):
        cases = ((('sbin', 'bin'), {}), (('sbin',), {'unsafe': 'symlink'}),
                 (('sbin',), {'unsafe': 'hardlink'}), (('sbin',), {'unsafe': 'writable'}),
                 (('sbin',), {'unsafe': 'writable-parent'}), (('sbin',), {'unsafe': 'parent-symlink'}),
                 (('sbin',), {'body': FIXTURE[:-1]}), (('bin',), {'body': FIXTURE + b'X'}),
                 ((), {}))
        for paths, options in cases:
            with self.subTest(paths=paths, options=tuple(options)):
                fixture = self.fixture(paths, **options)
                _, _, _, recorded, crypto = fixture
                self.assertEqual(self.capture(fixture), ('PATH_REFUSED', None))
                self.assertEqual(recorded.reads, [])
                self.assertEqual(crypto, [])

    def test_size_match_without_historical_digest_never_reaches_encryption(self):
        fixture = self.fixture(('sbin',), replaced_sha='f' * 64)
        _, _, _, recorded, crypto = fixture
        self.assertEqual(self.capture(fixture), ('HISTORICAL_DIGEST_MISMATCH', None))
        self.assertTrue(recorded.reads)
        self.assertEqual(crypto, [])

    def test_second_leaf_appearing_during_encryption_invalidates_capture(self):
        def introduce_second(leaves):
            leaves['bin'].write_bytes(FIXTURE)

        fixture = self.fixture(('sbin',), mutate=introduce_second)
        self.assertEqual(self.capture(fixture), ('SOURCE_CHANGED', None))
        self.assertEqual(fixture[-1], [FIXTURE])

    def test_parent_or_selected_leaf_replacement_invalidates_even_with_identical_bytes(self):
        def replace_parent(slot):
            def replace(leaves):
                leaf = leaves[slot]
                leaf.parent.rename(leaf.parent.with_name(slot + '-old'))
                leaf.parent.mkdir()
                if slot == 'sbin':
                    leaf.write_bytes(FIXTURE)
                    leaf.chmod(0o700)
            return replace

        def replace_leaf(leaves):
            leaf = leaves['sbin']
            leaf.rename(leaf.with_name('old-synthetic-leaf'))
            leaf.write_bytes(FIXTURE)
            leaf.chmod(0o700)

        for mutation in (replace_parent('sbin'), replace_parent('bin'), replace_leaf):
            with self.subTest(mutation=mutation.__name__):
                fixture = self.fixture(('sbin',), mutate=mutation)
                self.assertEqual(self.capture(fixture), ('SOURCE_CHANGED', None))
                self.assertEqual(fixture[-1], [FIXTURE])

    def test_noatime_refusal_does_not_fall_back_to_a_different_open(self):
        fixture = self.fixture(('sbin',))
        namespace, _, _, recorded, crypto = fixture
        original_open = recorded.open

        def deny_atime_open(path, flags, *args, **kwargs):
            if path.startswith('/proc/self/fd/'):
                recorded.opens.append(flags)
                raise PermissionError('synthetic O_NOATIME refusal')
            return original_open(path, flags, *args, **kwargs)

        recorded.open = deny_atime_open
        self.assertEqual(self.capture(fixture), ('SOURCE_CHANGED', None))
        self.assertEqual(len(recorded.opens), 1)
        self.assertTrue(recorded.opens[0] & recorded.O_NOATIME)
        self.assertEqual(recorded.reads, [])
        self.assertEqual(crypto, [])

    def test_special_file_replacement_before_anchor_never_opens_for_reading(self):
        fixture = self.fixture(('sbin',))
        namespace, leaves, _, recorded, crypto = fixture
        original_open = recorded.open

        def substitute_fifo(path, flags, *args, **kwargs):
            if path == namespace['_WRAPPER_LEAF']:
                leaf = leaves['sbin']
                leaf.unlink()
                os.mkfifo(leaf)
            return original_open(path, flags, *args, **kwargs)

        recorded.open = substitute_fifo
        self.assertEqual(self.capture(fixture), ('SOURCE_CHANGED', None))
        self.assertEqual(recorded.anchors, [recorded.O_PATH | os.O_NOFOLLOW])
        self.assertEqual(recorded.opens, [])
        self.assertEqual(recorded.reads, [])
        self.assertEqual(crypto, [])

    def test_change_after_read_and_encryption_failure_produce_no_ciphertext(self):
        fixture = self.fixture(('sbin',))
        _, leaves, _, recorded, crypto = fixture
        original_read = recorded.read

        def inject_after_read(fd, count):
            data = original_read(fd, count)
            if data:
                leaves['bin'].write_bytes(FIXTURE)
            return data

        recorded.read = inject_after_read
        self.assertEqual(self.capture(fixture), ('SOURCE_CHANGED', None))
        self.assertEqual(crypto, [])

        def fail_encryption(_leaves):
            raise RuntimeError('synthetic encryption failure')

        fixture = self.fixture(('sbin',), mutate=fail_encryption)
        self.assertEqual(self.capture(fixture), ('ENCRYPTION_REFUSED', None))

    def test_root_child_envelope_never_emits_plaintext_or_error_details(self):
        fixture = self.fixture(('sbin',), bad_preflight=True)
        namespace, _, traversals, recorded, _ = fixture
        with redirect_stdout(io.StringIO()) as output:
            namespace['_main'](NONCE, PEM, PEM_SHA)
        self.assertEqual(json.loads(output.getvalue()), dict(
            version='jsm-test-publisher-cms-v1', nonce=NONCE, euid=os.geteuid(),
            status='PREFLIGHT_REFUSED', ciphertext=None))
        self.assertNotIn('synthetic refusal', output.getvalue())
        self.assertEqual(traversals, [])
        self.assertEqual(recorded.reads, [])
