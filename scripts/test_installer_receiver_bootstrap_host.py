"""Root-side, fixed TEST writer bootstrap capsule. Import has no side effects."""

HOST_SOURCE = r'''
import base64
from contextlib import ExitStack
import grp
from hashlib import sha256
from http.client import HTTPConnection
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import time

_BOOT_VERSION = 'jsm-test-installer-bootstrap-v1'
_BOOT_ACCOUNT = 'jsmtestinstall'
_BOOT_ROOT = '/usr/local/libexec/jsm-test-installer-writer'
_BOOT_HOME = '/var/lib/jsm-test-installer-writer-home'
_BOOT_DEST = 'jsm-test-installer-writer'
_BOOT_HOME_LEAF = 'jsm-test-installer-writer-home'
_BOOT_FORCE = _BOOT_ROOT + '/forced-command'
_BOOT_LOGIN = _BOOT_ROOT + '/login-shell'
_BOOT_PROTOCOL = 'jsm-test-installer-update-v1'
_BOOT_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
_BOOT_LOCAL = ('usr', 'local')
_BOOT_LIBEXEC = ('usr', 'local', 'libexec')
_BOOT_PARENTS = (_BOOT_LOCAL, ('var', 'lib'), ('etc', 'sudoers.d'))
_BOOT_CHAINS = (*_BOOT_PARENTS, _BOOT_LIBEXEC)
_BOOT_MEMBERS = {
    'receiver.py': ('test_installer_update_receiver.py', 0o644, 20349, '092850b35c348f46d5b02a147a28d94bcd6411b307be8120495c72eb8c6b3a74'),
    'package.py': ('test_installer_update_package.py', 0o644, 2468, 'e40fd150cd9b3f639db36024344a1962f96845cfd287077f56df2300e1c79fe5'),
    'forced_command.sh': ('forced-command', 0o755, 371, 'cf1baf6bf9603278af1da8c92b6b6dd49f9f5e24aaf2cd32824694e3709385c4'),
}
_BOOT_PUBLIC_SHA256 = '96c9c617a2c306227515dd9f841278992beaf5229c96e26536c353c5633559b3'
_BOOT_USERADD = '/usr/sbin/useradd'
_BOOT_VISUDO = '/usr/sbin/visudo'
_BOOT_SUDO_LINE = (
    _BOOT_ACCOUNT + ' ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I -B -S '
    + _BOOT_ROOT + '/test_installer_update_receiver.py ' + _BOOT_PROTOCOL + '\n'
).encode('ascii')
_BOOT_SHELL = (
    '#!/bin/sh\n[ "$#" -eq 2 ] && [ "$1" = "-c" ] && [ "$2" = "'
    + _BOOT_FORCE + '" ] || exit 64\nexec ' + _BOOT_FORCE + '\n'
).encode('ascii')


class _BootUncertain(Exception):
    pass


def _boot_remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    return remaining


def _boot_metadata(field, deadline):
    if field not in ('instance/id', 'project/project-id', 'instance/zone'):
        raise ValueError()
    client = HTTPConnection('169.254.169.254', timeout=min(0.5, _boot_remaining(deadline)))
    try:
        client.request('GET', '/computeMetadata/v1/' + field, headers={
            'Host': 'metadata.google.internal', 'Metadata-Flavor': 'Google', 'Connection': 'close',
        })
        response = client.getresponse()
        flavor = [value for name, value in response.getheaders() if name.lower() == 'metadata-flavor']
        if response.status != 200 or flavor != ['Google']:
            raise ValueError()
        body = response.read(257)
        _boot_remaining(deadline)
        if not 0 < len(body) <= 256:
            raise ValueError()
        return body[:-1] if body.endswith(b'\n') else body
    finally:
        client.close()


def _boot_host_matches(deadline):
    return (
        os.geteuid() == 0
        and _boot_metadata('instance/id', deadline) == b'150919059249400713'
        and _boot_metadata('project/project-id', deadline) == b'dark-berm-508215-d2'
        and re.fullmatch(rb'projects/[1-9][0-9]{0,19}/zones/asia-northeast1-a',
                         _boot_metadata('instance/zone', deadline)) is not None
    )


def _boot_input(files, public_key):
    if (type(files) is not dict or set(files) != set(_BOOT_MEMBERS) or type(public_key) is not bytes
            or len(public_key) > 256 or sha256(public_key).hexdigest() != _BOOT_PUBLIC_SHA256):
        raise ValueError()
    key = public_key[:-1] if public_key.endswith(b'\n') else public_key
    match = re.fullmatch(rb'ssh-ed25519 ([A-Za-z0-9+/]{68})', key)
    if not match:
        raise ValueError()
    decoded = base64.b64decode(match[1], validate=True)
    if (len(decoded) != 51 or decoded[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
            or base64.b64encode(decoded) != match[1] or not any(decoded[19:])):
        raise ValueError()
    for source, (_, _, size, digest) in _BOOT_MEMBERS.items():
        raw = files[source]
        if type(raw) is not bytes or len(raw) != size or sha256(raw).hexdigest() != digest:
            raise ValueError()
    return b'restrict,command="' + _BOOT_FORCE.encode('ascii') + b'" ' + key + b'\n'


def _boot_safe(info):
    return info.st_uid == 0 and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _boot_dir_stamp(info):
    if not stat.S_ISDIR(info.st_mode) or not _boot_safe(info):
        raise ValueError()
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _boot_inode(info):
    return info.st_dev, info.st_ino


def _boot_file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _boot_open_chain(parts, deadline):
    if parts not in _BOOT_CHAINS:
        raise ValueError()
    fds = []
    try:
        for component in ('/', *parts):
            _boot_remaining(deadline)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(component, flags, dir_fd=fds[-1] if fds else None)
            fds.append(fd)
            _boot_dir_stamp(os.fstat(fd))
        return fds
    except BaseException:
        for fd in reversed(fds):
            os.close(fd)
        raise


def _boot_anchor(stack, parts, deadline):
    fds = _boot_open_chain(parts, deadline)
    for fd in fds:
        stack.callback(os.close, fd)
    return parts, fds[-1], tuple(_boot_dir_stamp(os.fstat(fd)) for fd in fds)


def _boot_recheck(anchors, deadline):
    with ExitStack() as fresh:
        for parts, last, identity in anchors:
            if _boot_dir_stamp(os.fstat(last)) != identity[-1]:
                raise ValueError()
            if _boot_anchor(fresh, parts, deadline)[2] != identity:
                raise ValueError()


def _boot_absent(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _boot_account_absent():
    try:
        pwd.getpwnam(_BOOT_ACCOUNT)
        return False
    except KeyError:
        pass
    try:
        grp.getgrnam(_BOOT_ACCOUNT)
        return False
    except KeyError:
        return True


def _boot_child_dir(stack, created, parent, name, deadline, mode=0o755):
    _boot_remaining(deadline)
    os.mkdir(name, 0o700, dir_fd=parent)
    try:
        found = os.stat(name, dir_fd=parent, follow_symlinks=False)
        expected = _boot_dir_stamp(found)
    except (OSError, ValueError):
        raise _BootUncertain() from None
    created.append([parent, name, _boot_inode(found), True, mode, None])
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent)
    stack.callback(os.close, fd)
    if _boot_dir_stamp(os.fstat(fd)) != expected:
        raise ValueError()
    os.fchown(fd, 0, 0)
    os.fchmod(fd, mode)
    os.fsync(fd)
    os.fsync(parent)
    return fd


def _boot_file(stack, created, parent, name, data, mode, deadline):
    _boot_remaining(deadline)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=parent)
    stack.callback(os.close, fd)
    try:
        ident = _boot_inode(os.fstat(fd))
    except OSError:
        raise _BootUncertain() from None
    record = [parent, name, ident, False, mode, None]
    created.append(record)
    offset = 0
    while offset < len(data):
        _boot_remaining(deadline)
        count = os.write(fd, data[offset:])
        if count <= 0:
            raise OSError()
        offset += count
    os.fchown(fd, 0, 0)
    os.fchmod(fd, mode)
    os.fsync(fd)
    info = os.fstat(fd)
    by_name = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or not _boot_safe(info) or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != mode or info.st_size != len(data)
            or _boot_inode(info) != ident or _boot_file_stamp(by_name) != _boot_file_stamp(info)):
        raise ValueError()
    record[-1] = _boot_file_stamp(info)
    os.fsync(parent)
    return fd


def _boot_created_intact(created):
    for parent, name, identity, directory, mode, stamp in created:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        expected_kind = stat.S_ISDIR(current.st_mode) if directory else stat.S_ISREG(current.st_mode)
        if (not expected_kind or not _boot_safe(current) or _boot_inode(current) != identity
                or current.st_gid != 0 or stat.S_IMODE(current.st_mode) != mode):
            raise ValueError()
        if not directory and (current.st_nlink != 1 or _boot_file_stamp(current) != stamp):
            raise ValueError()


def _boot_rollback(created):
    clean = True
    for parent, name, identity, directory, _mode, _stamp in reversed(created):
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _boot_inode(current) != identity:
                clean = False
                continue
            if directory:
                os.rmdir(name, dir_fd=parent)
            else:
                os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        except FileNotFoundError:
            pass
        except OSError:
            clean = False
    return clean


def _boot_tool(path):
    if path not in (_BOOT_USERADD, _BOOT_VISUDO):
        raise ValueError()
    item = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(item.st_mode) or not _boot_safe(item) or not item.st_mode & stat.S_IXUSR:
        raise ValueError()


def _boot_visudo(deadline):
    # Validate the exact fragment before publishing it in sudoers.d.
    fd = os.memfd_create('jsm-test-installer-sudoers', os.MFD_CLOEXEC)
    try:
        if os.write(fd, _BOOT_SUDO_LINE) != len(_BOOT_SUDO_LINE):
            raise OSError()
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o440)
        os.lseek(fd, 0, os.SEEK_SET)
        result = subprocess.run([_BOOT_VISUDO, '-cf', '/proc/self/fd/' + str(fd)],
            timeout=_boot_remaining(deadline), pass_fds=(fd,), env=_BOOT_ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if result.returncode != 0:
            raise ValueError()
    finally:
        os.close(fd)


def _boot_useradd(deadline):
    result = subprocess.run([_BOOT_USERADD, '--system', '--no-create-home', '--user-group',
        '--no-log-init', '--groups', '', '--home-dir', _BOOT_HOME,
        '--shell', _BOOT_LOGIN, '--password', '!', _BOOT_ACCOUNT],
        timeout=_boot_remaining(deadline), env=_BOOT_ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        raise _BootUncertain()
    _boot_remaining(deadline)
    account = pwd.getpwnam(_BOOT_ACCOUNT)
    group = grp.getgrnam(_BOOT_ACCOUNT)
    if (account.pw_uid <= 0 or group.gr_gid <= 0 or account.pw_gid != group.gr_gid
            or account.pw_dir != _BOOT_HOME or account.pw_shell != _BOOT_LOGIN
            or set(os.getgrouplist(_BOOT_ACCOUNT, group.gr_gid)) != {group.gr_gid}):
        raise _BootUncertain()


def _boot_apply(files, public_key, deadline):
    try:
        authorized_key = _boot_input(files, public_key)
    except (ValueError, TypeError):
        return 'INPUT_REFUSED'
    try:
        if not _boot_host_matches(deadline):
            return 'TARGET_REFUSED'
    except Exception:
        return 'TARGET_REFUSED'

    created = []
    account_started = False
    phase = 'TARGET_REFUSED'
    with ExitStack() as stack:
        try:
            anchors = [_boot_anchor(stack, parts, deadline) for parts in _BOOT_PARENTS]
            local, varlib, sudoers = (row[1] for row in anchors)
            libexec = None
            if not _boot_absent(local, 'libexec'):
                parent = _boot_anchor(stack, _BOOT_LIBEXEC, deadline)
                if _boot_dir_stamp(os.stat('libexec', dir_fd=local, follow_symlinks=False)) != parent[2][-1]:
                    raise ValueError()
                anchors.append(parent)
                libexec = parent[1]
            phase = 'PREEXISTING_REFUSED'
            if (not _boot_account_absent()
                    or (libexec is not None and not _boot_absent(libexec, _BOOT_DEST))
                    or not _boot_absent(varlib, _BOOT_HOME_LEAF) or not _boot_absent(sudoers, _BOOT_DEST)):
                return phase
            phase = 'BOOTSTRAP_FAILED'
            _boot_tool(_BOOT_USERADD)
            _boot_tool(_BOOT_VISUDO)
            _boot_visudo(deadline)
            _boot_recheck(anchors, deadline)
            if libexec is None:
                libexec = _boot_child_dir(stack, created, local, 'libexec', deadline)
                parent = _boot_anchor(stack, _BOOT_LIBEXEC, deadline)
                if _boot_dir_stamp(os.fstat(libexec)) != parent[2][-1]:
                    raise ValueError()
                anchors.append(parent)
            package = _boot_child_dir(stack, created, libexec, _BOOT_DEST, deadline)
            _boot_child_dir(stack, created, package, 'state', deadline, mode=0o700)
            for source, (name, mode, _, _) in _BOOT_MEMBERS.items():
                _boot_file(stack, created, package, name, files[source], mode, deadline)
            _boot_file(stack, created, package, 'login-shell', _BOOT_SHELL, 0o755, deadline)
            home = _boot_child_dir(stack, created, varlib, _BOOT_HOME_LEAF, deadline)
            ssh = _boot_child_dir(stack, created, home, '.ssh', deadline)
            _boot_file(stack, created, ssh, 'authorized_keys', authorized_key, 0o644, deadline)
            _boot_file(stack, created, sudoers, _BOOT_DEST, _BOOT_SUDO_LINE, 0o440, deadline)
            _boot_recheck(anchors, deadline)
            _boot_created_intact(created)
            if not _boot_account_absent():
                phase = 'PREEXISTING_REFUSED'
                raise ValueError()
            _boot_remaining(deadline)
            # useradd can partially commit account/group state even on error.
            # Revoke only this attempt's artifacts on failure. Never guess
            # whether an account/group transaction can safely be undone.
            account_started = True
            _boot_useradd(deadline)
            _boot_recheck(anchors, deadline)
            _boot_created_intact(created)
            _boot_remaining(deadline)
            return 'BOOTSTRAPPED'
        except _BootUncertain:
            _boot_rollback(created)
            return 'STATE_UNCERTAIN'
        except FileExistsError:
            clean = _boot_rollback(created)
            return 'PREEXISTING_REFUSED' if clean and not account_started else 'STATE_UNCERTAIN'
        except Exception:
            clean = _boot_rollback(created)
            return 'STATE_UNCERTAIN' if account_started or not clean else phase


def _boot_timeout(_signum, _frame):
    raise TimeoutError()


def _boot_main():
    nonce = _BOOT_NONCE if type(_BOOT_NONCE) is str and re.fullmatch('[0-9a-f]{32}', _BOOT_NONCE) else ''
    status = 'INPUT_REFUSED'
    if nonce:
        signal.signal(signal.SIGTERM, _boot_timeout)
        status = _boot_apply(_BOOT_FILES, _BOOT_PUBLIC_KEY, time.monotonic() + 3)
    print(json.dumps(dict(version=_BOOT_VERSION, nonce=nonce, euid=os.geteuid(), status=status),
        ensure_ascii=True, separators=(',', ':'), sort_keys=True))


_boot_main()
'''
