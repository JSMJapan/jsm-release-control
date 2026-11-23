"""Stage only the fixed private TEST FastCGI PHP package in /run."""

from contextlib import contextmanager, ExitStack
import hashlib
import os
import re
import stat


_STAGING_NAMES = (
    'test_db_runtime_entry.php', 'test_db_runtime_probe.php', 'test_db_runtime_pdo.php',
    'test_db_runtime_php_channel.php', 'test_db_runtime_startup.php',
)
_STAGING_FILE_LIMIT = 128 * 1024
_STAGING_TOTAL_LIMIT = 256 * 1024


class StagingRefused(ValueError):
    """The exact PHP package could not be staged."""


class DeferCleanup(ValueError):
    """A FastCGI request may still hold the staged files."""


class CleanupUnconfirmed(ValueError):
    """A staged path changed or could not be removed safely."""


def _staging_identity(info):
    return info.st_dev, info.st_ino


def _staging_stamp(info):
    return (_staging_identity(info), info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _staging_same_path(parent, name, fd):
    held = os.fstat(fd)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if _staging_identity(named) != _staging_identity(held):
        raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')
    return held


def _staging_hash(fd, size):
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        data = os.pread(fd, min(8192, size - offset), offset)
        if not data:
            raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')
        digest.update(data)
        offset += len(data)
    if os.pread(fd, 1, size):
        raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')
    return digest.hexdigest()


def _staging_check_root(run_root, parent):
    info = _staging_same_path(None, run_root, parent)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')


def _staging_cleanup(run_root, parent, directory, fd, records):
    refused = False
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in (0o700, 0o711):
            raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')
        os.fchmod(fd, 0o700)
        _staging_check_root(run_root, parent)
        _staging_same_path(parent, directory, fd)
    except (OSError, CleanupUnconfirmed):
        raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED') from None

    for name, (leaf, written, expected_stamp) in records.items():
        try:
            before = _staging_same_path(fd, name, leaf)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid()
                    or before.st_size != len(written)
                    or expected_stamp != _staging_stamp(before)
                    or _staging_hash(leaf, len(written)) != hashlib.sha256(written).hexdigest()
                    or expected_stamp != _staging_stamp(_staging_same_path(fd, name, leaf))):
                raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')
            os.unlink(name, dir_fd=fd)
        except (OSError, CleanupUnconfirmed):
            refused = True

    try:
        _staging_same_path(parent, directory, fd)
        os.rmdir(directory, dir_fd=parent)
        _staging_check_root(run_root, parent)
        try:
            os.stat(directory, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')
    except (OSError, CleanupUnconfirmed):
        refused = True
    if refused:
        raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')


def _staging_source_map(php_sources):
    if (type(php_sources) is not dict or set(php_sources) != set(_STAGING_NAMES)
            or any(type(data) is not bytes or not 0 < len(data) <= _STAGING_FILE_LIMIT
                   for data in php_sources.values())
            or sum(map(len, php_sources.values())) > _STAGING_TOTAL_LIMIT):
        raise StagingRefused('STAGING_REFUSED')
    return dict(php_sources)


@contextmanager
def staged_php(run_root, nonce, php_sources):
    """Expose fixed nonsecret PHP sources to FPM just for the guarded request."""
    sources = _staging_source_map(php_sources)
    if (type(run_root) is not str or not os.path.isabs(run_root)
            or type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None):
        raise StagingRefused('STAGING_REFUSED')
    directory = 'jsm-db-2760-' + nonce
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        try:
            parent = os.open(run_root, flags)
            stack.callback(os.close, parent)
            _staging_check_root(run_root, parent)
            os.mkdir(directory, 0o700, dir_fd=parent)
        except (OSError, ValueError):
            raise StagingRefused('STAGING_REFUSED') from None

        try:
            fd = os.open(directory, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            directory_info = _staging_same_path(parent, directory, fd)
            if directory_info.st_uid != os.geteuid() or stat.S_IMODE(directory_info.st_mode) != 0o700:
                raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED')
        except OSError:
            raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED') from None

        records = {}
        cleanup = True
        try:
            files = {}
            try:
                for name in _STAGING_NAMES:
                    data = sources[name]
                    leaf = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   0o600, dir_fd=fd)
                    stack.callback(os.close, leaf)
                    offset = 0
                    try:
                        while offset < len(data):
                            count = os.write(leaf, data[offset:])
                            if count <= 0:
                                raise StagingRefused('STAGING_REFUSED')
                            offset += count
                        os.fchmod(leaf, 0o644)
                    finally:
                        records[name] = (leaf, data[:offset], _staging_stamp(os.fstat(leaf)))
                    info = _staging_same_path(fd, name, leaf)
                    digest = hashlib.sha256(data).hexdigest()
                    if (info.st_uid != os.geteuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o644 or info.st_size != len(data)
                            or _staging_hash(leaf, len(data)) != digest
                            or records[name][2] != _staging_stamp(_staging_same_path(fd, name, leaf))):
                        raise StagingRefused('STAGING_REFUSED')
                    files[name] = dict(device=info.st_dev, inode=info.st_ino, size=len(data), sha256=digest)
                _staging_same_path(parent, directory, fd)
                _staging_check_root(run_root, parent)
                os.fchmod(fd, 0o711)
            except (OSError, ValueError):
                raise StagingRefused('STAGING_REFUSED') from None
            yield dict(path=os.path.join(run_root, directory), device=directory_info.st_dev,
                       inode=directory_info.st_ino, files=files)
        except DeferCleanup:
            cleanup = False
            try:
                held = os.fstat(fd)
                if held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o711:
                    os.fchmod(fd, 0o700)
            finally:
                raise CleanupUnconfirmed('STAGING_CLEANUP_UNCONFIRMED') from None
        finally:
            if cleanup:
                _staging_cleanup(run_root, parent, directory, fd, records)
