"""Atomically replace the fixed Eva receiver on the authorized idle TEST host."""

from contextlib import contextmanager, ExitStack
from hashlib import sha256
import ctypes
import fcntl
import json
import os
import re
import signal
import stat
import sys
import time

ACTIVE = 'jsm-eva-test-1620'
STAGED = '.jsm-eva-test-1620-receiver-upgrade'
INCOMING = '.incoming-'
REPLACE = {'control.sha', 'eva_test_host.py', 'eva_test_live_policy.json'}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
FILE_LIMIT = 65536


def _root_owned(row):
    return row.st_uid == row.st_gid == 0


def _mode(name):
    return 0o755 if name in ('forced-command', 'login-shell') else 0o444


def _remaining(deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError()


def _dir(row, modes):
    return stat.S_ISDIR(row.st_mode) and _root_owned(row) and stat.S_IMODE(row.st_mode) in modes


def _same(row, other):
    return (row.st_dev, row.st_ino) == (other.st_dev, other.st_ino)


def _named(parent, name, descriptor):
    return _same(os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(descriptor))


@contextmanager
def _open(parent, name, modes):
    descriptor = os.open(name, DIR_FLAGS, dir_fd=parent)
    try:
        if not _dir(os.fstat(descriptor), modes) or not _named(parent, name, descriptor):
            raise ValueError()
        yield descriptor
    finally:
        os.close(descriptor)


def _read_file(folder, name, modes, deadline):
    _remaining(deadline)
    fd = os.open(name, FILE_FLAGS, dir_fd=folder)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or not _root_owned(before)
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in modes
                or not 0 <= before.st_size <= FILE_LIMIT):
            raise ValueError()
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(FILE_LIMIT + 1)
        after = os.fstat(fd)
        if (len(data) != before.st_size or not _named(folder, name, fd) or
                (before.st_ctime_ns, before.st_mtime_ns) != (after.st_ctime_ns, after.st_mtime_ns)):
            raise ValueError()
        return data
    finally:
        os.close(fd)


def _snapshot(folder, manifest, deadline, *, subset=False, pending_values=None):
    _remaining(deadline)
    names = set(os.listdir(folder))
    expected = manifest.keys() | {'state'}
    if not subset and names != expected:
        raise ValueError()
    result = {}
    if extra := names - expected:
        if pending_values is None or len(extra) != 1:
            raise ValueError()
        incoming = next(iter(extra))
        intended = incoming.removeprefix(INCOMING)
        if not incoming.startswith(INCOMING) or intended not in pending_values or intended in names:
            raise ValueError()
        data = _read_file(folder, incoming, (0o600, _mode(intended)), deadline)
        if not pending_values[intended].startswith(data):
            raise ValueError()
        result[incoming] = data
    if 'state' in names:
        with _open(folder, 'state', (0o700,)) as state:
            if os.listdir(state):
                raise ValueError()
    for name in sorted(names & manifest.keys()):
        data = _read_file(folder, name, (_mode(name),), deadline)
        if sha256(data).hexdigest() != manifest[name]:
            raise ValueError()
        result[name] = data
    if set(os.listdir(folder)) != names:
        raise ValueError()
    return result


def _exchange(parent):
    # No two-rename fallback: the live command and its SHA must change together.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(ACTIVE), parent, os.fsencode(STAGED), 2) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _discard(parent, folder, manifest, deadline, *, pending_values=None):
    if not _named(parent, STAGED, folder):
        raise ValueError()
    verified = _snapshot(folder, manifest, deadline, subset=True, pending_values=pending_values)
    for name in verified:
        _remaining(deadline)
        os.unlink(name, dir_fd=folder)
    if 'state' in os.listdir(folder):
        os.rmdir('state', dir_fd=folder)
    if not _named(parent, STAGED, folder) or os.listdir(folder):
        raise ValueError()
    os.rmdir(STAGED, dir_fd=parent)
    os.fsync(parent)


def _discard_existing(parent, manifest, deadline, *, pending_values=None):
    try:
        present = os.stat(STAGED, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not _dir(present, (0o700, 0o755)):
        raise ValueError()
    with _open(parent, STAGED, (0o700, 0o755)) as folder:
        _discard(parent, folder, manifest, deadline, pending_values=pending_values)


def _populate(folder, values, deadline):
    os.mkdir('state', 0o700, dir_fd=folder)
    for name, data in sorted(values.items()):
        _remaining(deadline)
        incoming = INCOMING + name
        fd = os.open(incoming, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=folder)
        with os.fdopen(fd, 'wb') as target:
            target.write(data)
            target.flush()
            os.fchmod(target.fileno(), _mode(name))
            os.fsync(target.fileno())
        os.rename(incoming, name, src_dir_fd=folder, dst_dir_fd=folder)
    os.fchmod(folder, 0o755)
    os.fsync(folder)


def upgrade_package(parent, replacements, previous, deadline, *, revalidate=lambda: None):
    if (replacements.keys() != REPLACE or not REPLACE <= previous.keys()
            or not all(type(data) is bytes and 0 < len(data) <= FILE_LIMIT for data in replacements.values())):
        raise ValueError()
    current = {**previous, **{name: sha256(data).hexdigest() for name, data in replacements.items()}}
    if current == previous:
        raise ValueError()
    with _open(parent, ACTIVE, (0o755,)) as original:
        try:
            _snapshot(original, current, deadline)
        except ValueError:
            old_data = _snapshot(original, previous, deadline)
        else:
            revalidate()
            _discard_existing(parent, previous, deadline)
            return 'ALREADY_CURRENT'
        revalidate()
        new_data = {**old_data, **replacements}
        _discard_existing(parent, current, deadline, pending_values=new_data)
        os.mkdir(STAGED, 0o700, dir_fd=parent)
        with _open(parent, STAGED, (0o700,)) as candidate:
            try:
                _populate(candidate, new_data, deadline)
                _snapshot(candidate, current, deadline)
                _snapshot(original, previous, deadline)
                _remaining(deadline)
                revalidate()
                if not (_named(parent, ACTIVE, original) and _named(parent, STAGED, candidate)):
                    raise ValueError()
                _exchange(parent)
                os.fsync(parent)
                if not (_named(parent, ACTIVE, candidate) and _named(parent, STAGED, original)):
                    raise ValueError()
                _snapshot(candidate, current, deadline)
                revalidate()
            except (AttributeError, OSError, ValueError):
                try:
                    if _named(parent, ACTIVE, candidate) and _named(parent, STAGED, original):
                        _snapshot(original, previous, deadline)
                        _exchange(parent)
                        os.fsync(parent)
                    if not (_named(parent, ACTIVE, original) and _named(parent, STAGED, candidate)):
                        raise ValueError()
                    _snapshot(original, previous, deadline)
                    _discard(parent, candidate, current, deadline, pending_values=new_data)
                    return 'ROLLED_BACK'
                except (AttributeError, OSError, ValueError):
                    return 'STATE_UNCERTAIN'
            try:
                _discard(parent, original, previous, deadline)
            except (OSError, ValueError):
                return 'STATE_UNCERTAIN'
    return 'UPGRADED'


@contextmanager
def idle_receiver(parent):
    with _open(parent, ACTIVE, (0o700,)) as base:
        fd = os.open('.lock', os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=base)
        try:
            row = os.fstat(fd)
            if not (stat.S_ISREG(row.st_mode) and _root_owned(row)
                    and row.st_nlink == 1 and stat.S_IMODE(row.st_mode) == 0o600):
                raise ValueError()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            def require_idle():
                if not (_named(parent, ACTIVE, base) and _named(base, '.lock', fd)):
                    raise ValueError()
                if set(os.listdir(base)) != {'.lock'}:
                    raise BlockingIOError()

            require_idle()
            yield require_idle
        finally:
            os.close(fd)


def upgrade_main(nonce, replacements, previous, version):
    # The reviewed bootstrap template supplies the existing exact GCE proof
    # and the anchored root-directory traversal used by the admin transport.
    status = 'INPUT_REFUSED'
    if type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce):
        deadline = time.monotonic() + 3
        signal.signal(signal.SIGTERM, _boot_timeout)
        try:
            if sys.platform != 'linux' or not _boot_host_matches(deadline):
                raise ValueError()
        except (OSError, ValueError):
            status = 'TARGET_REFUSED'
        else:
            try:
                with ExitStack() as stack:
                    anchors = [_boot_anchor(stack, parts, deadline) for parts in (_BOOT_LIBEXEC, ('var', 'lib'))]
                    with idle_receiver(anchors[1][1]) as require_idle:
                        def revalidate():
                            require_idle()
                            _boot_recheck(anchors, deadline)
                        status = upgrade_package(anchors[0][1], replacements, previous, deadline, revalidate=revalidate)
            except BlockingIOError:
                status = 'RECEIVER_BUSY'
            except (OSError, ValueError):
                status = 'PREVIOUS_REFUSED'
    print(json.dumps(dict(version=version, nonce=nonce, euid=os.geteuid(), status=status),
                     ensure_ascii=True, separators=(',', ':'), sort_keys=True))
