#!/usr/bin/env python3
"""Check the fixed report installer under a protected shared lock before sudo."""
from contextlib import contextmanager, ExitStack
import fcntl
from hashlib import sha256
import os
import re
import stat
import subprocess
import sys

DEPLOYER = '/usr/local/sbin/jsm-sandbox-deploy'
LOCK = '/run/jsm-sandbox-deploy.lock'
INSTALLER_SIZE = 8432
INSTALLER_SHA256 = '1616495487b7e2ab99169bf449bae3805b9a7ab11511cb95e8fd3f96bfd8bf1b'


class GuardRefused(ValueError):
    pass


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def trusted(info):
    return info.st_uid == 0 and not info.st_mode & 0o022


@contextmanager
def open_trusted_file(path, *, size=None):
    with ExitStack() as stack:
        directory_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open('/', directory_flags)
        stack.callback(os.close, parent)
        chain = []
        *parents, leaf = path[1:].split('/')
        if not trusted(os.fstat(parent)):
            raise GuardRefused()
        for name in parents:
            directory = os.open(name, directory_flags, dir_fd=parent)
            stack.callback(os.close, directory)
            info = os.fstat(directory)
            if not trusted(info):
                raise GuardRefused()
            chain.append((parent, name, directory, stamp(info)))
            parent = directory
        held = os.open(leaf, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        stack.callback(os.close, held)
        source = os.fstat(held)
        if (not stat.S_ISREG(source.st_mode) or not trusted(source) or source.st_nlink != 1
                or size is not None and source.st_size != size):
            raise GuardRefused()
        before = stamp(source)
        fd = os.open('/proc/self/fd/'+str(held), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        stack.callback(os.close, fd)

        def verify():
            if (stamp(os.fstat(fd)) != before or stamp(os.fstat(held)) != before
                    or stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != before):
                raise GuardRefused()
            for root, name, watch, expected in chain:
                if (stamp(os.fstat(watch)) != expected
                        or stamp(os.stat(name, dir_fd=root, follow_symlinks=False)) != expected):
                    raise GuardRefused()

        verify()
        yield fd, verify
        verify()


def fingerprint(fd, size):
    data = bytearray()
    while len(data) <= size:
        chunk = os.read(fd, min(8192, size + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > size:
            break
    if len(data) != size:
        raise GuardRefused()
    return sha256(data).hexdigest()


def main():
    if len(sys.argv) != 2 or re.fullmatch('[0-9a-f]{40}', sys.argv[1]) is None:
        return 65
    try:
        with open_trusted_file(LOCK) as (lock, verify_lock):
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with open_trusted_file(DEPLOYER, size=INSTALLER_SIZE) as (installer, verify_installer):
                if fingerprint(installer, INSTALLER_SIZE) != INSTALLER_SHA256:
                    raise GuardRefused()
                verify_lock()
                verify_installer()
                # This process retains the descriptor while sudo runs. All
                # cooperating installer writers must use the same lock inode.
                result = subprocess.run(['/usr/bin/sudo', '-n', DEPLOYER,
                    'jsm-test-db-report-v1:'+sys.argv[1]], stderr=subprocess.DEVNULL, timeout=13)
            return result.returncode
    except (OSError, AttributeError, GuardRefused, subprocess.SubprocessError):
        return 65


if __name__ == '__main__':
    raise SystemExit(main())
