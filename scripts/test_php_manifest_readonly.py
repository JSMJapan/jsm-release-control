#!/usr/bin/env python3
"""Compare the fixed #2760 release manifest in a stable TEST FPM process root."""
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _GitHubGet, strict_json
from test_db_os_metadata import LIBRARY as OS_LIBRARY
from test_db_php_endpoint import LIBRARY as PEER_LIBRARY
from test_installer_capture_encrypted import (
    GH_ENV, GH_REPO, OVERALL_SECONDS, REPO, TARGET, _receive, need, verify_policy,
)

VERSION = 'jsm-test-php-manifest-2760-v1'
WORKFLOW = 'test-php-manifest-readonly.yml'
EXPECTED_SITE = '4855198662bc28ee8ba41cf60ec430299f0a2222'
MAIN = GH_REPO + '/branches/main'
CONTEXT = {
    'GITHUB_REPOSITORY': REPO,
    'GITHUB_ACTOR': 'JSMJapan',
    'GITHUB_TRIGGERING_ACTOR': 'JSMJapan',
    'GITHUB_REF': 'refs/heads/main',
    'GITHUB_EVENT_NAME': 'workflow_dispatch',
    'GITHUB_RUN_ATTEMPT': '1',
    'GITHUB_SERVER_URL': 'https://github.com',
    'GITHUB_API_URL': 'https://api.github.com',
    'GITHUB_WORKFLOW_REF': REPO + '/.github/workflows/' + WORKFLOW + '@refs/heads/main',
}
# Expected post-transform bytes of exactly the eight audited first-party files.
MANIFEST = {
    'api_entry': ('api/web/index.php', 651, '5f8fd4230de8f7cd2500cf226faa0a7952a762af73c75d8478aafe1c1082cb7e'),
    'api_main': ('api/config/main.php', 22847, '5e0f81775cf696d6376867b04c53b6927544c1adb9630db96aeb06c686a9ec8f'),
    'common_bootstrap': ('common/config/bootstrap.php', 522, '46c0ce237a1e424586426d0a02b8999649cf550475e6716e19e25f0208d5f514'),
    'api_bootstrap': ('api/config/bootstrap.php', 7, '775fc33df0481713159236f2c706f7bdf1f37a19c5d65dae94068b723a5fca49'),
    'eva_controller': ('api/modules/v1/controllers/EvaController.php', 8201, '6391ec1cff0c6586108f210398087de3a3c715b94594dfa95e5ce6645d545404'),
    'faq_model': ('common/models/Faq.php', 1422, '1466ddb683939ceb42cf75a7755cf511357543433588a6ab1317ea96fe969959'),
    'faq_group_model': ('common/models/FaqGroup.php', 938, '261f583f7a57f889c46ca6b369dc9d4449bf394fed78e80911ee5f768d51ce28'),
    'faq_service': ('common/services/FaqService.php', 3365, '8f3c60ea57a781a495df92909ffc8fc2784ef30d4742f8918d66f3725527fd6c'),
}
STATUSES = ('MATCH', 'MISMATCH', 'UNKNOWN')
REASONS = ('EXACT_MAIN_APPROVAL_REQUIRED', 'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED',
           'TEST_SSH_KEY_NOT_CONFIGURED', 'EXACT_TEST_HOST_PIN_REQUIRED', 'SSH_TRANSPORT_NOT_CONFIRMED',
           'MANIFEST_RECEIPT_REFUSED', 'OVERALL_DEADLINE')

OBSERVATION = r'''
import fcntl
from contextlib import ExitStack

_MANIFEST_TRUSTED_UID = 0

def _manifest_trusted(info):
    return info.st_uid == _MANIFEST_TRUSTED_UID and not info.st_mode & 0o022

def _manifest_stamp(info):
    return _stamp(info) + (info.st_size, info.st_mtime_ns)

def _manifest_lock_path(deadline):
    fds, name = _parents('/run/jsm-sandbox-deploy.lock', deadline)
    try:
        parents = [os.fstat(fd) for fd in fds]
        leaf = os.stat(name, dir_fd=fds[-1], follow_symlinks=False)
        if not (stat.S_ISREG(leaf.st_mode) and leaf.st_nlink == 1 and all(map(_manifest_trusted, parents+[leaf]))):
            raise ValueError()
        return tuple(map(_manifest_stamp, parents)), _manifest_stamp(leaf)
    finally:
        for fd in reversed(fds):
            os.close(fd)

def _manifest_lock(deadline):
    fds, name = _parents('/run/jsm-sandbox-deploy.lock', deadline)
    with ExitStack() as anchors:
        for parent in fds:
            anchors.callback(os.close, parent)
        held = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
        anchors.callback(os.close, held)
        info = os.fstat(held)
        if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and _manifest_trusted(info)
                and all(_manifest_trusted(os.fstat(parent)) for parent in fds)):
            raise ValueError()
        fd = os.open('/proc/self/fd/'+str(held), os.O_RDONLY | os.O_CLOEXEC)
        try:
            if _manifest_stamp(info) != _manifest_stamp(os.fstat(fd)):
                raise ValueError()
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            if _manifest_stamp(info) != _manifest_lock_path(deadline)[1]:
                raise ValueError()
            return fd
        except BaseException:
            os.close(fd)
            raise

def _manifest_snapshot(deadline):
    units = _unit_snapshot(deadline)
    unit = units['php']
    master = unit['pid']
    if unit['load'] != 'loaded' or unit['active'] != 'active' or not _pid_ready(master):
        raise ValueError()
    master_identity = _php_endpoint_identity(master, deadline)
    listener = _unix_snapshot_detailed(deadline).get('php')
    if not listener or listener not in _fd_sockets(master, deadline):
        raise ValueError()
    children = _proc_read('/proc/'+str(master)+'/task/'+str(master)+'/children', deadline, 256).split()
    if (not 0 < len(children) <= 16 or len(set(children)) != len(children)
            or any(not re.fullmatch('[1-9][0-9]{0,9}', value) for value in children)):
        raise ValueError()
    # Follow the filesystem view only when all workers belong to the same
    # master, namespace and root. Do not choose between different roots.
    workers = []
    for worker in sorted(set(map(int, children))):
        identity = _php_endpoint_identity(worker, deadline)
        if identity[1] != master or identity[2:] != master_identity[2:] or identity[0] < master_identity[0]:
            raise ValueError()
        if listener in _fd_sockets(worker, deadline):
            workers.append((worker, identity))
    if not workers:
        raise ValueError()
    return (units, master_identity, listener, tuple(workers)), workers[0][0]

def _manifest_root(snapshot, pid, deadline):
    fds, name = _parents('/proc/'+str(pid)+'/root', deadline)
    try:
        before = os.stat(name, dir_fd=fds[-1], follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):
            raise ValueError()
        # The only followed symlink is Linux's typed process-root link.
        root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fds[-1])
        try:
            info = os.fstat(root)
            if not _manifest_trusted(info) or (info.st_dev, info.st_ino) != snapshot[3][0][1][3]:
                raise ValueError()
            if _stamp(before) != _stamp(os.stat(name, dir_fd=fds[-1], follow_symlinks=False)):
                raise ValueError()
            return root
        except BaseException:
            os.close(root)
            raise
    finally:
        for parent in reversed(fds):
            os.close(parent)

def _manifest_probe(root, rule, deadline):
    relative, size, expected = rule
    components = relative.split('/')
    with ExitStack() as stack:
        chain = []
        parent = root
        if not _manifest_trusted(os.fstat(root)):
            raise ValueError()
        for name in components[:-1]:
            _check(deadline)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if not _manifest_trusted(info):
                raise ValueError()
            chain.append((parent, name, fd, _manifest_stamp(info)))
            parent = fd
        name = components[-1]
        held = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        stack.callback(os.close, held)
        info = os.fstat(held)
        if not stat.S_ISREG(info.st_mode) or not _manifest_trusted(info) or info.st_nlink != 1:
            raise ValueError()
        stamp = _manifest_stamp(info)
        matched = False
        if info.st_size == size:
            # Open just the pinned regular inode. Do not resolve the name again
            # for content or read files of an unreviewed length.
            fd = os.open('/proc/self/fd/'+str(held), os.O_RDONLY | os.O_NOATIME | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            if stamp != _manifest_stamp(os.fstat(fd)):
                raise ValueError()
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                _check(deadline)
                data = os.read(fd, min(8192, remaining))
                if not data:
                    raise ValueError()
                digest.update(data)
                remaining -= len(data)
            if os.read(fd, 1) or stamp != _manifest_stamp(os.fstat(fd)):
                raise ValueError()
            matched = digest.hexdigest() == expected
        if stamp != _manifest_stamp(os.fstat(held)) or stamp != _manifest_stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)):
            raise ValueError()
        for parent, name, fd, expected_dir in chain:
            if expected_dir != _manifest_stamp(os.fstat(fd)) or expected_dir != _manifest_stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)):
                raise ValueError()
        return ('MATCH' if matched else 'MISMATCH'), stamp, tuple(item[3] for item in chain)

def _manifest_read_files(root, deadline):
    files = {}
    for role,(relative,size,expected) in MANIFEST.items():
        rule = ('srv/jsm/app/backend/'+relative, size, expected)
        try:
            files[role] = _manifest_probe(root, rule, deadline)
        except (OSError, ValueError, AttributeError):
            files[role] = ('UNKNOWN',)
    return files

def _read_php_manifest(nonce):
    result = dict(version=VERSION, nonce=nonce, euid=os_geteuid(), fpm_root='UNKNOWN',
                  files={role:'UNKNOWN' for role in MANIFEST}, php_loopback_3306='UNKNOWN')
    deadline = time.monotonic()+3.2
    try:
        with ExitStack() as stack:
            lock = _manifest_lock(deadline)
            stack.callback(os.close, lock)
            lock_path = _manifest_lock_path(deadline)
            if lock_path[1] != _manifest_stamp(os.fstat(lock)):
                return result
            before, pid = _manifest_snapshot(deadline)
            root = _manifest_root(before, pid, deadline)
            stack.callback(os.close, root)
            first = _manifest_read_files(root, deadline)
            peer = _observe_php_endpoint(before[0], before[0], min(deadline,time.monotonic()+.55))
            second = _manifest_read_files(root, deadline)
            after, after_pid = _manifest_snapshot(deadline)
            _check(deadline)
            if before != after or pid != after_pid or first != second:
                return result
            if lock_path[1] != _manifest_stamp(os.fstat(lock)) or lock_path != _manifest_lock_path(deadline):
                return result
            result.update(fpm_root='STABLE', files={role:value[0] for role,value in first.items()},
                          php_loopback_3306='OBSERVED' if peer['state']=='OBSERVED' else 'UNKNOWN')
    except (OSError, ValueError, AttributeError, subprocess.SubprocessError):
        pass
    return result
'''


def root_library():
    return (OS_LIBRARY + PEER_LIBRARY + '\nVERSION=' + repr(VERSION)
            + '\nMANIFEST=' + repr(MANIFEST) + '\n' + OBSERVATION)


def root_program(nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'MANIFEST_RECEIPT_REFUSED')
    return root_library() + '\nprint(json.dumps(_read_php_manifest(' + repr(nonce) + '),sort_keys=True))\n'


def baseline():
    return dict(version=VERSION, target=TARGET, expected_site_sha=EXPECTED_SITE,
                manifest='UNKNOWN', fpm_root='UNKNOWN', files={role:'UNKNOWN' for role in MANIFEST},
                php_loopback_3306='UNKNOWN', active_api_binding='NOT_ESTABLISHED',
                installer_report='NOT_VERIFIED', db_isolation='NOT_ESTABLISHED', sql='NOT_ATTEMPTED')


def project_remote(raw, nonce):
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096:
            raise ValueError()
        outer = strict_json(raw.decode('ascii'))
        if (type(outer) is not dict or set(outer) != {'version','nonce','principal','euid','root_diagnostic'}
                or outer['version'] != 'jsm-test-installed-route-outer-v2' or outer['nonce'] != nonce
                or outer['principal'] != 'marinagurina'
                or type(outer['euid']) is not int or not 0 < outer['euid'] <= 4294967295):
            raise ValueError()
        child = outer['root_diagnostic']
        if (type(child) is not dict or set(child) != {'version','nonce','euid','fpm_root','files','php_loopback_3306'}
                or child['version'] != VERSION or child['nonce'] != nonce
                or type(child['euid']) is not int or child['euid'] != 0
                or child['fpm_root'] not in ('STABLE', 'UNKNOWN')
                or child['php_loopback_3306'] not in ('OBSERVED', 'UNKNOWN')):
            raise ValueError()
        files = child['files']
        if (type(files) is not dict or set(files) != set(MANIFEST)
                or any(type(x) is not str or x not in STATUSES for x in files.values())):
            raise ValueError()
        if child['fpm_root'] == 'UNKNOWN' and (set(files.values()) != {'UNKNOWN'} or child['php_loopback_3306'] != 'UNKNOWN'):
            raise ValueError()
    except Exception:
        raise Refused('MANIFEST_RECEIPT_REFUSED') from None
    outcome = 'MATCH' if set(files.values()) == {'MATCH'} else 'MISMATCH' if 'MISMATCH' in files.values() else 'UNKNOWN'
    return dict(baseline(), manifest=outcome, files=dict(files), fpm_root=child['fpm_root'],
                php_loopback_3306=child['php_loopback_3306'])


def collect(api, env):
    deadline = time.monotonic()+OVERALL_SECONDS
    sha = env.get('GITHUB_SHA', '')
    need(all(env.get(k) == v for k,v in CONTEXT.items()) and re.fullmatch('[0-9a-f]{40}', sha)
         and env.get('GITHUB_WORKFLOW_SHA') == sha and env.get('APPROVED_SHA') == sha
         and re.fullmatch('[1-9][0-9]{0,14}', env.get('GITHUB_RUN_ID', '')), 'EXACT_MAIN_APPROVAL_REQUIRED')
    verify_policy(api)
    main = api.get_json(MAIN)
    need(main.get('name') == 'main' and main.get('protected') is True
         and main.get('commit', {}).get('sha') == sha, 'EXACT_MAIN_APPROVAL_REQUIRED')
    raw, nonce = _receive(env, deadline, root_program)
    result = project_remote(raw, nonce)
    result.update(workflow_sha=sha, run_id=env['GITHUB_RUN_ID'])
    return result


def main():
    result = baseline()
    def expired(*_):
        raise Refused('OVERALL_DEADLINE')
    try:
        need(len(sys.argv) == 1, 'EXACT_MAIN_APPROVAL_REQUIRED')
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS)
        result = collect(_GitHubGet((GH_REPO, GH_ENV, GH_ENV + '/deployment-branch-policies', MAIN)), os.environ)
    except Exception as error:
        code = error.args[0] if isinstance(error, Refused) and len(error.args) == 1 else None
        result['reason'] = code if code in REASONS else 'MANIFEST_RECEIPT_REFUSED'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['manifest'] == 'MATCH' else 1


if __name__ == '__main__':
    raise SystemExit(main())
