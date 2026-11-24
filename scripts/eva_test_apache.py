"""Exact two-route addition to the known TEST TLS vhost, with a hash-bound rollback."""

from contextlib import contextmanager
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import re
import stat

from eva_test_archive import require

PUBLIC_ORIGIN = 'https://develop.jsmjapan.com'
PUBLIC_HOST = 'develop.jsmjapan.com'
PUBLIC_GATE = '/__eva_test_1620/gate?next=%2Fru%2F'
PUBLIC_BRIDGE = '/__eva_test_1620/teacher'
APACHE = Path('/etc/apache2/sites-available/jsm-sandbox-443.conf')
ACTIVE = Path('/etc/apache2/sites-enabled/jsm-sandbox-443.conf')
PROFILE_PORT = 19884
ROOT_USER = 0
MARKER = b'# BEGIN JSM EVA 1620'
MAX_CONFIG = 65536
SOCKET_LOCK = Path('/run/jsm-sandbox-deploy.lock')
INCLUDE = re.compile(rb'^\s*\((?:\*|[0-9]+)\) (/[^\x00-\x20]+)\s*$', re.M)
SENSITIVE_LOG = re.compile(
    rb'%\{(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Eva-Teacher-Secret|eva_teacher_test)\}[iocn]'
    rb'|(?:^|\n)\s*DumpIO(?:Input|Output)\s+On\b|(?:^|\n)\s*LogLevel[^\n#]*\btrace[5-8]\b', re.I,
)
CONFIG = b'''    # BEGIN JSM EVA 1620
    RewriteEngine On
    RewriteRule ^/?__eva_test_1620/(?:gate|teacher)$ - [L]
    ProxyPassMatch "^(/__eva_test_1620/(?:gate|teacher))$" "http://127.0.0.1:19884$1" connectiontimeout=3 timeout=48
    # END JSM EVA 1620
'''
AUTH = b'''    <LocationMatch "^/__eva_test_1620/(?:gate|teacher)$">
        ProxyPreserveHost On
        AuthType None
        AuthMerging Off
        Require all granted
        LimitRequestBody 16384
    </LocationMatch>
'''


def patched(raw, expected):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CONFIG
            and sha256(raw).hexdigest() == expected and b'\0' not in raw and MARKER not in raw,
            'EVA_TEST_VHOST_REFUSED')
    rows = raw.splitlines(keepends=True)
    starts = [i for i, row in enumerate(rows) if re.fullmatch(rb'\s*<VirtualHost\s+[^>]*:443>\r?\n', row, re.I)]
    ends = [i for i, row in enumerate(rows) if re.fullmatch(rb'\s*</VirtualHost>\s*', row, re.I)]
    blocks = [(start, end) for start in starts for end in ends if end > start and not any(start < i < end for i in starts)]
    targets = [(start, end) for start, end in blocks if any(
        re.fullmatch(rb'\s*ServerName\s+develop\.jsmjapan\.com\s*', row, re.I) for row in rows[start + 1:end])]
    require(len(targets) == 1, 'EVA_TEST_VHOST_REFUSED')
    start, end = targets[0]
    block = b''.join(rows[start:end + 1])
    require(re.search(rb'^\s*SSLEngine\s+on\s*$', block, re.I | re.M)
            and not SENSITIVE_LOG.search(block),
            'EVA_TEST_VHOST_REFUSED')
    return b''.join((*rows[:start + 1], CONFIG, *rows[start + 1:end], AUTH, *rows[end:]))


def read_active():
    require(ACTIVE.is_symlink() and ACTIVE.resolve(strict=True) == APACHE,
            'EVA_TEST_VHOST_REFUSED')
    fd = os.open(APACHE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as file:
        observed = os.fstat(file.fileno())
        require(stat.S_ISREG(observed.st_mode) and observed.st_uid == ROOT_USER
                and observed.st_nlink == 1 and not observed.st_mode & 0o022,
                'EVA_TEST_VHOST_REFUSED')
        raw = file.read(MAX_CONFIG + 1)
        after = APACHE.lstat()
        require(0 < len(raw) <= MAX_CONFIG and (observed.st_dev, observed.st_ino, observed.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_ctime_ns), 'EVA_TEST_VHOST_REFUSED')
    return raw, observed


def replace_active(old, new, observed, run):
    require(re.fullmatch('[0-9a-f]{12}', run), 'EVA_TEST_VHOST_REFUSED')
    slot = APACHE.with_name('.jsm-eva-test-1620-' + run + '.tmp')
    leaf = os.open(slot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(leaf, 'wb') as file:
            file.write(new)
            file.flush()
            os.fchmod(file.fileno(), stat.S_IMODE(observed.st_mode))
            os.fchown(file.fileno(), observed.st_uid, observed.st_gid)
            os.fsync(file.fileno())
        current, identity = read_active()
        require(current == old and (observed.st_dev, observed.st_ino, observed.st_ctime_ns)
                == (identity.st_dev, identity.st_ino, identity.st_ctime_ns), 'EVA_TEST_VHOST_REFUSED')
        os.replace(slot, APACHE)
        fd = os.open(APACHE.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if slot.exists():
            slot.unlink()



@contextmanager
def publisher_lock():
    outer = SOCKET_LOCK.parent.lstat()
    require(stat.S_ISDIR(outer.st_mode) and outer.st_uid == ROOT_USER and not outer.st_mode & 0o022,
            'EVA_TEST_DEPLOY_LOCK_UNPROVEN')
    descriptor = os.open(SOCKET_LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_USER and info.st_nlink == 1
                and not info.st_mode & 0o022, 'EVA_TEST_DEPLOY_LOCK_UNPROVEN')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = SOCKET_LOCK.lstat()
        require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), 'EVA_TEST_DEPLOY_LOCK_UNPROVEN')
        yield
    finally:
        os.close(descriptor)


def verify_logs(include_dump):
    paths = {Path(value.decode('ascii')).resolve(strict=True) for value in INCLUDE.findall(include_dump)}
    require(Path('/etc/apache2/apache2.conf') in paths and APACHE in paths and len(paths) <= 128,
            'EVA_TEST_APACHE_LOG_SCOPE_REFUSED')
    total = 0
    for path in sorted(paths):
        require(Path('/etc/apache2') in path.parents or path == Path('/etc/letsencrypt/options-ssl-apache.conf'),
                'EVA_TEST_APACHE_LOG_SCOPE_REFUSED')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_USER and not info.st_mode & 0o022,
                    'EVA_TEST_APACHE_LOG_SCOPE_REFUSED')
            raw = stream.read(MAX_CONFIG + 1)
        total += len(raw)
        require(total <= 1024 * 1024 and len(raw) <= MAX_CONFIG and not SENSITIVE_LOG.search(raw),
                'EVA_TEST_APACHE_LOG_SCOPE_REFUSED')
