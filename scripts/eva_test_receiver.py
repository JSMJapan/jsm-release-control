#!/usr/bin/env python3
"""Fixed forced-command receiver. Its reviewed source is installed separately on TEST."""

from dataclasses import asdict
from hashlib import sha256
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apache_parity_bridge import strict_json
from article_test_receiver import end_input, read_exact
from article_test_state import canonical, valid_run
from test_installer_update_receiver import _host_matches
from eva_test_archive import ARCHIVE_LIMIT, EvaRefused, load_pins, require
from eva_test_host import BASE, State, TTL, arm_expiry, clean, host_lock, read_owned, root_directory, stage

MAGIC = b'JSM_EVA_TEST_1620_V1\n'
PROTOCOL = 'jsm-eva-test-1620-v1'
SHA = re.compile('[0-9a-f]{40}')
NONCE = re.compile('[0-9a-f]{32}')
COMMAND = 'jsm-eva-test-1620-v1'
HOST = 'jsm-sandbox'
SAFE_ERRORS = {
    'EVA_ARTIFACT_NOT_PINNED', 'EVA_STATE_REFUSED', 'EVA_HOST_REFUSED', 'EVA_STAGE_DEADLINE',
    'EVA_FRAME_REFUSED', 'EVA_PACKAGE_REFUSED', 'EVA_NAME_COLLISION', 'EVA_IMAGE_REFUSED',
    'EVA_ISOLATION_REFUSED', 'EVA_PDO_REFUSED', 'EVA_DB_GRANTS_REFUSED', 'EVA_DB_REFUSED',
    'EVA_READINESS_REFUSED', 'EVA_CLEANUP_UNCONFIRMED', 'EVA_EXPIRY_NOT_PROVISIONED',
}


def validate_request(value, approved):
    require(type(value) is dict and value.keys() == {'protocol', 'op', 'run', 'nonce', 'sha', 'artifact', 'size'}
            and value['protocol'] == PROTOCOL and value['op'] in ('STAGE', 'CLEANUP')
            and valid_run(value['run']) and type(value['nonce']) is str and NONCE.fullmatch(value['nonce'])
            and type(value['sha']) is str and SHA.fullmatch(value['sha']) and value['sha'] == approved
            and type(value['size']) is int, 'EVA_FRAME_REFUSED')
    if value['op'] == 'CLEANUP':
        require(value['artifact'] is None and value['size'] == 0, 'EVA_FRAME_REFUSED')
    else:
        require(0 < value['size'] <= ARCHIVE_LIMIT
                and value['artifact'] == asdict(load_pins()), 'EVA_FRAME_REFUSED')
    return value


def prefix(op, run, nonce, sha, build, size):
    request = {'protocol': PROTOCOL, 'op': op, 'run': run, 'nonce': nonce, 'sha': sha,
               'artifact': asdict(build) if build is not None else None, 'size': size}
    data = canonical(validate_request(request, sha))
    return MAGIC + len(data).to_bytes(4, 'big') + data


def frame(fd, deadline, approved):
    require(read_exact(fd, len(MAGIC), deadline) == MAGIC, 'EVA_FRAME_REFUSED')
    size = int.from_bytes(read_exact(fd, 4, deadline), 'big')
    require(1 <= size <= 2048, 'EVA_FRAME_REFUSED')
    raw = read_exact(fd, size, deadline)
    value = strict_json(raw.decode('ascii'))
    require(canonical(value) == raw, 'EVA_FRAME_REFUSED')
    return validate_request(value, approved)


def receive(fd, folder, request, deadline):
    space = os.statvfs(folder)
    require(space.f_bavail * space.f_frsize >= request['size'] + 4 * 1024**3, 'EVA_HOST_REFUSED')
    target = os.open(folder / 'artifact.zip', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    digest = sha256()
    with os.fdopen(target, 'wb') as file:
        remaining = request['size']
        while remaining:
            part = read_exact(fd, min(remaining, 65536), deadline)
            file.write(part)
            digest.update(part)
            remaining -= len(part)
        file.flush()
        os.fsync(file.fileno())
    require(digest.hexdigest() == request['artifact']['archive_sha256'], 'EVA_PACKAGE_REFUSED')
    end_input(fd, deadline)


def expire(run, timed):
    try:
        with State(run) as store:
            state = store.read()
            require(not timed or time.time() >= state['expires'], 'EVA_STAGE_DEADLINE')
            clean(store, state, time.monotonic() + 90)
    except FileNotFoundError:
        # Confirm absence only at the literal path belonging to this run.
        require(not os.path.lexists(BASE / run), 'EVA_CLEANUP_UNCONFIRMED')


def execute(request, fd, deadline):
    run = request['run']
    if request['op'] == 'CLEANUP':
        end_input(fd, deadline)
        expire(run, False)
        return {'status': 'CLEANED', 'run': run}
    build = load_pins()
    with State(run, create=True) as store:
        state = {'run': run, 'expires': int(time.time()) + TTL, 'aliases': [], 'tags': [],
                 'import_started': False, 'import_complete': False, 'prepared': []}
        try:
            store.save(state)
            # Expiry is armed before the first byte of the private archive.
            arm_expiry(store, state['expires'], deadline)
            receive(fd, store.path, request, min(deadline, time.monotonic() + 300))
            return stage(store, state, build, deadline)
        except BaseException:
            try:
                clean(store, store.read(), time.monotonic() + 90)
            except BaseException:
                raise EvaRefused('EVA_CLEANUP_UNCONFIRMED') from None
            raise


def approved_control():
    path = Path(__file__).with_name('control.sha')
    value = read_owned(path, 41, (0o400, 0o444, 0o600))
    require(len(value) == 41 and value.endswith(b'\n'), 'EVA_HOST_REFUSED')
    sha = value[:-1].decode('ascii')
    require(SHA.fullmatch(sha), 'EVA_HOST_REFUSED')
    return sha


def expire_all():
    # This unit is provisioned persistently for reboot recovery, with the same host-global lock.
    candidates = [entry for entry in BASE.iterdir() if valid_run(entry.name)]
    require(len(candidates) <= 32, 'EVA_CLEANUP_UNCONFIRMED')
    failure = False
    for entry in candidates:
        try:
            require(root_directory(entry.lstat()), 'EVA_STATE_REFUSED')
            with State(entry.name) as store:
                if not (entry / 'state.json').exists():
                    # The stage cannot receive payload or access Docker without its durable state.
                    age = time.time() - entry.stat().st_mtime
                    names = {child.name for child in entry.iterdir()}
                    if age >= TTL and names <= {'lock', 'state.tmp'}:
                        clean(store, {'import_started': False}, time.monotonic() + 90)
                    continue
                state = store.read()
                if state['expires'] <= time.time():
                    clean(store, state, time.monotonic() + 90)
        except (OSError, ValueError):
            failure = True
    require(not failure, 'EVA_CLEANUP_UNCONFIRMED')


def main():
    request = None
    expiry = sys.argv[1:2] in (['expire'], ['expire-all'])
    try:
        require(os.geteuid() == 0 and sys.platform == 'linux' and socket.gethostname().split('.')[0] == HOST and _host_matches(), 'EVA_HOST_REFUSED')
        start = time.monotonic()
        def alarm(*_):
            raise EvaRefused('EVA_STAGE_DEADLINE')
        signal.signal(signal.SIGALRM, alarm)
        signal.alarm(110 if expiry else 700)
        with host_lock():
            if sys.argv[1:] == ['expire-all']:
                expire_all()
                return 0
            if len(sys.argv) == 3 and sys.argv[1] == 'expire' and valid_run(sys.argv[2]):
                expire(sys.argv[2], True)
                return 0
            require(sys.argv[1:] == ['serve'], 'EVA_HOST_REFUSED')
            request = frame(0, start + 10, approved_control())
            result = execute(request, 0, start + 600)
            value = {**result, 'protocol': PROTOCOL, 'nonce': request['nonce']}
    except BaseException as error:
        reason = error.args[0] if isinstance(error, EvaRefused) and len(error.args) == 1 and error.args[0] in SAFE_ERRORS else 'EVA_HOST_REFUSED'
        value = {'status': 'BLOCKED', 'protocol': PROTOCOL, 'reason': reason}
        if request is not None:
            value.update(nonce=request['nonce'], run=request['run'])
    finally:
        signal.alarm(0)
    # Only conservative receipts are emitted. No stderr or exception details leave the host.
    sys.stdout.buffer.write(canonical(value))
    return int(expiry)


if __name__ == '__main__':
    raise SystemExit(main())
