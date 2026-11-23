"""Fixed, encrypted capture of the historically inventoried TEST publisher."""

import re

from test_installer_capture_capsule import _ROOT_OPERATIONS, _ROOT_PREAMBLE, _VALIDATION, _validation

VERSION = 'jsm-test-publisher-cms-v1'
WRAPPER_SIZE = 255
WRAPPER_SHA256 = '5f7e773ed2c8efc3808ff5d8481156d798d292e9cb2dca4142338564896ff10b'
STATUSES = (
    'CAPTURED', 'PREFLIGHT_REFUSED', 'PATH_REFUSED', 'SOURCE_CHANGED',
    'HISTORICAL_DIGEST_MISMATCH', 'ENCRYPTION_REFUSED',
)

_WRAPPER = '_WRAPPER_SIZE = ' + repr(WRAPPER_SIZE) + '\n_WRAPPER_SHA256 = ' + repr(WRAPPER_SHA256) + '\n' + r'''
from contextlib import ExitStack

_SLOTS = (('usr','local','sbin'),('usr','local','bin'))
_WRAPPER_LEAF = 'jsm-sandbox-publish'


def _open_parent_chain(components, deadline):
    if components not in _SLOTS:
        raise ValueError()
    fds = []
    try:
        for component in ('/', *components):
            _remaining(deadline)
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=fds[-1] if fds else None)
            fds.append(fd)
            info = os.fstat(fd)
            if not _safe_mode(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError()
        return fds
    except BaseException:
        for fd in reversed(fds):
            os.close(fd)
        raise


def _open_slots(stack, deadline):
    chains = []
    for components in _SLOTS:
        fds = _open_parent_chain(components, deadline)
        for fd in fds:
            stack.callback(os.close, fd)
        chains.append(fds)
    return chains


def _snapshot(chains, deadline):
    parents, entries = [], []
    for fds in chains:
        snapshots = []
        for fd in fds:
            _remaining(deadline)
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or not _safe_mode(info):
                raise ValueError()
            snapshots.append(_stamp(info))
        parents.append(tuple(snapshots))
        _remaining(deadline)
        try:
            entry = os.stat(_WRAPPER_LEAF, dir_fd=fds[-1], follow_symlinks=False)
        except FileNotFoundError:
            entries.append(None)
        else:
            if (not stat.S_ISREG(entry.st_mode) or not _safe_mode(entry)
                    or not entry.st_mode & stat.S_IXUSR
                    or entry.st_nlink != 1 or entry.st_size != _WRAPPER_SIZE):
                raise ValueError()
            entries.append(_stamp(entry))
    _remaining(deadline)
    return tuple(parents), tuple(entries)


def _check_paths(chains, snapshot, selected, source_fd, deadline):
    _remaining(deadline)
    if _stamp(os.fstat(source_fd)) != snapshot[1][selected] or _snapshot(chains, deadline) != snapshot:
        raise ValueError()
    # The held descriptors are safe even if a parent is renamed. Reopen both
    # paths starting at / to reject detached/replaced parents, including the
    # parent in which the alternative wrapper was absent.
    with ExitStack() as fresh:
        if _snapshot(_open_slots(fresh, deadline), deadline) != snapshot:
            raise ValueError()
    _remaining(deadline)


def _capture(pem, digest, deadline):
    phase = 'PREFLIGHT_REFUSED'
    try:
        with ExitStack() as stack:
            certificate, canary = _preflight(pem, digest, deadline)
            stack.callback(os.close, certificate)
            phase = 'PATH_REFUSED'
            chains = _open_slots(stack, deadline)
            snapshot = _snapshot(chains, deadline)
            occupied = [index for index, entry in enumerate(snapshot[1]) if entry is not None]
            if len(occupied) != 1:
                raise ValueError()
            selected = occupied[0]

            phase = 'SOURCE_CHANGED'
            # O_PATH pins the entry without opening a replaced FIFO or device.
            anchor = os.open(_WRAPPER_LEAF, os.O_PATH | os.O_NOFOLLOW, dir_fd=chains[selected][-1])
            stack.callback(os.close, anchor)
            _check_paths(chains, snapshot, selected, anchor, deadline)
            # Only reopen the verified inode via our own descriptor; never reopen
            # the path by name for reading or retry without O_NOATIME.
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOATIME
            source_fd = os.open('/proc/self/fd/' + str(anchor), flags)
            stack.callback(os.close, source_fd)
            _check_paths(chains, snapshot, selected, source_fd, deadline)
            data = bytearray()
            while len(data) <= _WRAPPER_SIZE:
                _remaining(deadline)
                chunk = os.read(source_fd, _WRAPPER_SIZE + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) != _WRAPPER_SIZE:
                raise ValueError()
            _check_paths(chains, snapshot, selected, source_fd, deadline)
            if hashlib.sha256(data).hexdigest() != _WRAPPER_SHA256:
                return 'HISTORICAL_DIGEST_MISMATCH', None

            phase = 'ENCRYPTION_REFUSED'
            ciphertext = _cms(data, certificate, deadline)
            profile = _envelope(ciphertext)
            if profile[:2] != canary[:2] or profile[2] == canary[2] or profile[3] != _WRAPPER_SIZE:
                raise ValueError()
            phase = 'SOURCE_CHANGED'
            _check_paths(chains, snapshot, selected, source_fd, deadline)
            return 'CAPTURED', base64.b64encode(ciphertext).decode('ascii')
    except Exception:
        return phase, None


def _main(nonce, pem, digest):
    status, ciphertext = _capture(pem, digest, time.monotonic() + 3)
    print(json.dumps(dict(version='jsm-test-publisher-cms-v1', nonce=nonce, euid=os.geteuid(),
                          status=status, ciphertext=ciphertext),
                     ensure_ascii=True, separators=(',', ':'), sort_keys=True))
'''


def render(nonce: str, pem: bytes, digest: str) -> str:
    if (type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None
            or not _validation['_certificate_pinned'](pem, digest)):
        raise ValueError('PREFLIGHT_REFUSED')
    return (_VALIDATION + _ROOT_PREAMBLE + _ROOT_OPERATIONS + _WRAPPER
            + '\n_main(' + repr(nonce) + ',' + repr(pem) + ',' + repr(digest) + ')\n')


def has_wrapper_length(ciphertext: bytes) -> bool:
    """Compare the authenticated-encryption container's payload length."""
    try:
        return _validation['_envelope'](ciphertext)[3] == WRAPPER_SIZE
    except ValueError:
        return False
