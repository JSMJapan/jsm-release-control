#!/usr/bin/env python3
"""Receiver for one TEST installer update. Provisioning/transport is separate."""

from contextlib import ExitStack
import fcntl
from hashlib import sha256
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import secrets
import select
import stat
import sys
import time
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_installer_update_package import (
    MAX_INSTALLER_BYTES, OPERATIONS, ORIGINAL_SHA256, PROTOCOL, STATUSES, UPDATED_SHA256, transform,
)

_TARGET_CHAIN = ('usr', 'local', 'sbin')
_REPORTER_CHAIN = ('usr', 'local', 'libexec')
_LOCK_CHAIN = ('run',)
_ALLOWED_CHAINS = (_TARGET_CHAIN, _REPORTER_CHAIN, _LOCK_CHAIN)
_TARGET = 'jsm-sandbox-deploy'
_REPORTER = 'jsm-test-db-report'
_REPORTER_PIN = 'jsm-test-db-report.sha256'
_LOCK = 'jsm-sandbox-deploy.lock'
_GCE = '169.254.169.254'
_METADATA = '/computeMetadata/v1/'
_MAX_REQUEST = 128
_MAX_REPORTER = 128 * 1024
_SUCCESS = frozenset(('READY', 'APPLIED', 'ROLLED_BACK', 'ALREADY_APPLIED', 'ALREADY_ORIGINAL'))


class _InvalidSize(ValueError):
    pass


class _Chain(NamedTuple):
    parts: tuple
    fds: list
    identity: tuple


class _File(NamedTuple):
    chain: _Chain
    name: str
    fd: int
    info: os.stat_result


def _canonical(value):
    return (json.dumps(value, ensure_ascii=True, separators=(',', ':'), sort_keys=True) + '\n').encode('ascii')


def _request(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_REQUEST:
        raise ValueError()
    value = json.loads(raw.decode('ascii'))
    if (type(value) is not dict or set(value) != {'version', 'operation'}
            or value['version'] != PROTOCOL or type(value['operation']) is not str
            or value['operation'] not in OPERATIONS or _canonical(value) != raw):
        raise ValueError()
    return value['operation']


def _metadata(field):
    if field not in ('instance/id', 'project/project-id', 'instance/zone'):
        raise ValueError()
    client = HTTPConnection(_GCE, timeout=0.75)
    try:
        client.request('GET', _METADATA + field, headers={
            'Host': 'metadata.google.internal', 'Metadata-Flavor': 'Google', 'Connection': 'close',
        })
        response = client.getresponse()
        flavor = [value for name, value in response.getheaders() if name.lower() == 'metadata-flavor']
        if response.status != 200 or flavor != ['Google']:
            raise ValueError()
        body = response.read(257)
        if not 0 < len(body) <= 256:
            raise ValueError()
        return body[:-1] if body.endswith(b'\n') else body
    finally:
        client.close()


def _host_matches():
    if os.geteuid() != 0:
        return False
    return (
        _metadata('instance/id') == b'150919059249400713'
        and _metadata('project/project-id') == b'dark-berm-508215-d2'
        and re.fullmatch(rb'projects/[1-9][0-9]{0,19}/zones/asia-northeast1-a', _metadata('instance/zone')) is not None
    )


def _safe_mode(info):
    return info.st_uid == 0 and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0


def _directory_stamp(info):
    if not stat.S_ISDIR(info.st_mode) or not _safe_mode(info):
        raise ValueError()
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _safe_file(info, executable):
    return (
        stat.S_ISREG(info.st_mode) and _safe_mode(info) and info.st_nlink == 1
        and info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX) == 0
        and (not executable or bool(info.st_mode & stat.S_IXUSR))
    )


def _open_chain(parts):
    if parts not in _ALLOWED_CHAINS:
        raise ValueError()
    fds = []
    try:
        for component in ('/', *parts):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(component, flags, dir_fd=fds[-1] if fds else None)
            fds.append(fd)
            _directory_stamp(os.fstat(fd))
        return fds
    except BaseException:
        for fd in reversed(fds):
            os.close(fd)
        raise


def _anchor(stack, parts):
    fds = _open_chain(parts)
    for fd in fds:
        stack.callback(os.close, fd)
    return _Chain(parts, fds, tuple(_directory_stamp(os.fstat(fd)) for fd in fds))


def _check_chain(chain):
    if chain.identity != tuple(_directory_stamp(os.fstat(fd)) for fd in chain.fds):
        raise ValueError()
    with ExitStack() as fresh:
        if _anchor(fresh, chain.parts).identity != chain.identity:
            raise ValueError()


def _lstat(chain, name):
    return os.stat(name, dir_fd=chain.fds[-1], follow_symlinks=False)


def _check_file(file):
    _check_chain(file.chain)
    expected = _file_stamp(file.info)
    if _file_stamp(os.fstat(file.fd)) != expected or _file_stamp(_lstat(file.chain, file.name)) != expected:
        raise ValueError()


def _open_regular(stack, chain, name, *, executable=False):
    info = _lstat(chain, name)
    if not _safe_file(info, executable):
        raise ValueError()
    # Resolve a typed leaf without activating it. A replaced FIFO, device
    # or symlink fails fstat before any open that could start I/O.
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    held = os.open(name, flags, dir_fd=chain.fds[-1])
    try:
        _check_file(_File(chain, name, held, info))
        # This is the kernel link for the held descriptor, never a filename
        # or link target supplied by the request or taken from the installer.
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOATIME
        fd = os.open('/proc/self/fd/' + str(held), flags)
        stack.callback(os.close, fd)
        record = _File(chain, name, fd, info)
        _check_file(record)
        return record
    finally:
        os.close(held)


def _read_exact(file, limit):
    size = file.info.st_size
    if not 0 < size <= limit:
        raise _InvalidSize()
    data = bytearray()
    while len(data) <= size:
        part = os.read(file.fd, min(8192, size + 1 - len(data)))
        if not part:
            break
        data.extend(part)
    if len(data) != size:
        raise ValueError()
    _check_file(file)
    return bytes(data)


def _take_lock(stack):
    lock_path = _anchor(stack, _LOCK_CHAIN)
    lock = _open_regular(stack, lock_path, _LOCK)
    fcntl.flock(lock.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    _check_file(lock)
    return lock


def _reporter(stack):
    chain = _anchor(stack, _REPORTER_CHAIN)
    pin = _open_regular(stack, chain, _REPORTER_PIN)
    digest = _read_exact(pin, 65)
    if re.fullmatch(rb'[0-9a-f]{64}\n', digest) is None:
        raise ValueError()
    executable = _open_regular(stack, chain, _REPORTER, executable=True)
    if sha256(_read_exact(executable, _MAX_REPORTER)).hexdigest().encode('ascii') != digest[:-1]:
        raise ValueError()
    _check_file(pin)
    return pin, executable


def _unlink_stage(fd, directory, name):
    try:
        path = os.stat(name, dir_fd=directory, follow_symlinks=False)
        info = os.fstat(fd)
        if (path.st_dev, path.st_ino) == (info.st_dev, info.st_ino):
            os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass


def _stage(stack, target, raw):
    directory = target.chain.fds[-1]
    name = '.jsm-test-installer-update-' + secrets.token_hex(16)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=directory)
    stack.callback(os.close, fd)
    stack.callback(_unlink_stage, fd, directory, name)
    offset = 0
    while offset < len(raw):
        wrote = os.write(fd, raw[offset:])
        if wrote <= 0:
            raise OSError()
        offset += wrote
    os.fchown(fd, target.info.st_uid, target.info.st_gid)
    os.fchmod(fd, stat.S_IMODE(target.info.st_mode))
    os.fsync(fd)
    info = os.fstat(fd)
    if (not _safe_file(info, True) or info.st_size != len(raw)
            or (info.st_mode, info.st_uid, info.st_gid) != (target.info.st_mode, target.info.st_uid, target.info.st_gid)):
        raise ValueError()
    return _File(target.chain, name, fd, info)


def _readback(stack, target, staged, expected):
    path = _open_regular(stack, target.chain, target.name, executable=True)
    # Atomic rename can advance ctime. Device/inode, physical attributes and
    # content must still match the prepared and fsynced object.
    if _file_stamp(path.info)[:-1] != _file_stamp(staged.info)[:-1]:
        raise ValueError()
    if sha256(_read_exact(path, MAX_INSTALLER_BYTES)).hexdigest() != expected:
        raise ValueError()


def _apply(operation):
    phase = 'LOCK_REFUSED'
    try:
        with ExitStack() as stack:
            lock = _take_lock(stack)
            phase = 'TARGET_REFUSED'
            chain = _anchor(stack, _TARGET_CHAIN)
            target = _open_regular(stack, chain, _TARGET, executable=True)
            # The transaction preserves POSIX ownership and mode. Refuse an
            # installer with ACL, capability or other unmanaged attributes.
            if os.listxattr(target.fd):
                return 'TARGET_REFUSED'
            try:
                original = _read_exact(target, MAX_INSTALLER_BYTES)
            except _InvalidSize:
                return 'PREIMAGE_REFUSED'
            phase = 'PREIMAGE_REFUSED'
            status, replacement = transform(original, operation)
            if status not in ('READY', 'ALREADY_APPLIED', 'ALREADY_ORIGINAL'):
                return phase
            if status == 'ALREADY_APPLIED' and operation == 'ROLLBACK':
                return phase
            if status == 'ALREADY_ORIGINAL' and operation != 'ROLLBACK':
                return phase
            write = status == 'READY' and operation != 'CHECK'
            if not write and replacement is not None:
                return phase
            expected = ORIGINAL_SHA256 if operation == 'ROLLBACK' else UPDATED_SHA256
            if write and (type(replacement) is not bytes or not 0 < len(replacement) <= MAX_INSTALLER_BYTES
                          or sha256(replacement).hexdigest() != expected):
                return phase

            reporter = ()
            if operation != 'ROLLBACK':
                phase = 'REPORTER_UNAVAILABLE'
                try:
                    reporter = _reporter(stack)
                except (OSError, ValueError, AttributeError):
                    if operation != 'CHECK':
                        return phase
                    status = 'ORIGINAL_NO_REPORTER' if status == 'READY' else 'UPDATED_NO_REPORTER'
            phase = 'TARGET_REFUSED'
            _check_file(target)
            phase = 'LOCK_REFUSED'
            _check_file(lock)
            if not write:
                return status

            phase = 'WRITE_REFUSED'
            staged = _stage(stack, target, replacement)
            for item in reporter:
                _check_file(item)
            _check_file(staged)
            _check_file(lock)
            _check_file(target)
            if os.listxattr(target.fd) or os.listxattr(staged.fd):
                return phase
            os.replace(staged.name, target.name, src_dir_fd=chain.fds[-1], dst_dir_fd=chain.fds[-1])

            phase = 'READBACK_UNCERTAIN'
            os.fsync(chain.fds[-1])
            _readback(stack, target, staged, expected)
            _check_file(lock)
            for item in reporter:
                _check_file(item)
            return 'ROLLED_BACK' if operation == 'ROLLBACK' else 'APPLIED'
    except (OSError, ValueError, AttributeError):
        return phase


def handle(raw):
    """Execute only a documented canonical command on the fixed TEST host."""
    try:
        operation = _request(raw)
    except (ValueError, RecursionError):
        return 'REQUEST_REFUSED'
    try:
        if not _host_matches():
            return 'TARGET_REFUSED'
    except Exception:
        return 'TARGET_REFUSED'
    return _apply(operation)


def _read_request():
    fd = sys.stdin.fileno()
    deadline = time.monotonic() + 2
    data = bytearray()
    while len(data) <= _MAX_REQUEST:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError()
        part = os.read(fd, _MAX_REQUEST + 1 - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    status = 'REQUEST_REFUSED'
    if args == [PROTOCOL]:
        try:
            status = handle(_read_request())
        except Exception:
            status = 'REQUEST_REFUSED'
    if status not in STATUSES:
        status = 'REQUEST_REFUSED'
    sys.stdout.write(_canonical(dict(version=PROTOCOL, status=status)).decode('ascii'))
    return 0 if status in _SUCCESS else 1


if __name__ == '__main__':
    raise SystemExit(main())
