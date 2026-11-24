"""Finite local-only Eva TEST on an authorized host, using a new MySQL instance."""

from contextlib import contextmanager
import fcntl
from hashlib import sha256
import http.client
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import time

from apache_parity_bridge import strict_json
from article_test_docker import Docker as BoundedDocker, DockerRefused, FIELDS, ID
from article_test_host import LIMITS, MEMORY, command, namespace, resource_admission
from article_test_images import image_stream, verify
from article_test_state import canonical, valid_run
from eva_test_archive import IMAGE, inspect_archive, require
from eva_test_apache import PUBLIC_GATE, PUBLIC_HOST, PUBLIC_ORIGIN, patched, publisher_lock, read_active, replace_active, verify_logs
from eva_test_live import LEASE_SECONDS, TLS_DIRECTORY, verify_certificate

BASE = Path('/var/lib/jsm-eva-test-1620')
LABEL = 'com.jsmjapan.eva-test.run'
TTL = 1200
PHP_PORT = 19881
RUNNER = '/usr/local/libexec/jsm-eva-test-1620/eva_test_receiver.py'
LIVE_RUNNER = '/usr/local/libexec/jsm-eva-test-1620/eva_test_live.py'
EXPIRY_TIMER = 'jsm-eva-test-1620-expiry.timer'
EXPIRY_UNITS = {'jsm-eva-test-1620-expiry.service': 'f19d123464361a00f99f1121302ee6894b18b425e043735c3cb99db901d77edd', 'jsm-eva-test-1620-expiry.timer': '17a9c4ef89a78be85d76f894c535dd3ffe758da3c17da017601d677b091aea2b'}
FORMAT = '{' + ','.join(
    '"' + key + '":{{json ' + (('(index .Config.Labels "' + LABEL + '")') if key == 'run' else value) + '}}'
    for key, value in FIELDS.items()) + '}'
HEALTH_PROGRAM = 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:' + str(PHP_PORT) + '/private-readiness", timeout=2).read(1024).decode("ascii"))'


class Docker(BoundedDocker):
    def image_id(self, tag):
        require(type(tag) is str and re.fullmatch(r'jsm-eva-(test|mysql):[0-9a-f]{40}', tag), 'EVA_IMAGE_REFUSED')
        raw = self.run(('image', 'ls', '--quiet', '--no-trunc', '--filter', 'reference=' + tag), limit=256)
        rows = raw.decode('ascii').splitlines()
        require(len(rows) <= 1 and all(IMAGE.fullmatch(row) for row in rows), 'EVA_IMAGE_REFUSED')
        return rows[0] if rows else None


def name(role, run):
    return 'jsm-eva-test-1620-' + role + '-' + run


def root_directory(info):
    return stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700


def owned_file(path, modes=(0o600,)):
    info = path.lstat()
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes


def read_owned(path, limit, modes=(0o600,)):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in modes, 'EVA_STATE_REFUSED')
        value = file.read(limit + 1)
        require(len(value) <= limit, 'EVA_STATE_REFUSED')
        return value


@contextmanager
def host_lock(base=BASE):
    base.mkdir(mode=0o700, exist_ok=True)
    require(root_directory(base.lstat()), 'EVA_STATE_REFUSED')
    lock = os.open(base / '.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'EVA_STATE_REFUSED')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(lock)


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as file:
        os.fchmod(file.fileno(), mode)
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


class State:
    def __init__(self, run, create=False, base=BASE):
        require(valid_run(run), 'EVA_RUN_REFUSED')
        self.run, self.path = run, base / run
        self.create = create

    def __enter__(self):
        if self.create:
            self.path.parent.mkdir(mode=0o700, exist_ok=True)
        require(root_directory(self.path.parent.lstat()), 'EVA_STATE_REFUSED')
        if self.create:
            self.path.mkdir(mode=0o700)
        require(root_directory(self.path.lstat()), 'EVA_STATE_REFUSED')
        flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if self.create:
            flags |= os.O_CREAT | os.O_EXCL
        self.lock = os.open(self.path / 'lock', flags, 0o600)
        try:
            info = os.fstat(self.lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'EVA_STATE_REFUSED')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lock)
            raise
        return self

    def __exit__(self, *_):
        os.close(self.lock)

    def read(self):
        raw = read_owned(self.path / 'state.json', 8192)
        state = strict_json(raw.decode('ascii'))
        require(type(state) is dict and state.keys() == {'run', 'expires', 'import_started', 'import_complete', 'aliases', 'tags', 'prepared', 'units'}
                and state.get('run') == self.run and type(state['expires']) is int and type(state['import_started']) is bool
                and type(state['import_complete']) is bool and (not state['import_complete'] or state['import_started'])
                and (not state['prepared'] or state['import_complete']) and type(state['prepared']) is list and state['prepared'] in ([], ['db'], ['db', 'app'])
                and state['units'] in ([], ['relay'], ['relay', 'https'])
                and (not state['units'] or state['prepared'] == ['db', 'app']),
                'EVA_STATE_REFUSED')
        tags, aliases = state['tags'], state['aliases']
        require((tags == aliases == [] and not state['import_started'] and not state['prepared']) or (
            type(tags) is type(aliases) is list and len(tags) == len(aliases) == 2
            and type(tags[0]) is type(tags[1]) is str
            and re.fullmatch(r'jsm-eva-test:[0-9a-f]{40}', tags[0])
            and tags[1] == tags[0].replace('jsm-eva-test:', 'jsm-eva-mysql:')
            and all(type(pair) is list and 1 <= len(pair) <= 2 and all(type(x) is str and IMAGE.fullmatch(x) for x in pair) for pair in aliases)
            and not set(aliases[0]) & set(aliases[1])), 'EVA_STATE_REFUSED')
        return state

    def save(self, state):
        temporary = self.path / 'state.tmp'
        if temporary.exists():
            require(owned_file(temporary), 'EVA_STATE_REFUSED')
            temporary.unlink()
        write_new(temporary, canonical(state))
        os.replace(temporary, self.path / 'state.json')
        fd = os.open(self.path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def arm_expiry(store, expires, deadline):
    for unit, digest in EXPIRY_UNITS.items():
        value = read_owned(Path('/etc/systemd/system') / unit, 8192, (0o444,))
        require(sha256(value).hexdigest() == digest, 'EVA_EXPIRY_NOT_PROVISIONED')
    command(('/usr/bin/systemctl', 'enable', '--now', EXPIRY_TIMER), deadline)
    for condition, expected in (('is-enabled', b'enabled'), ('is-active', b'active')):
        proof = command(('/usr/bin/systemctl', condition, EXPIRY_TIMER), deadline)
        require(proof.strip() == expected, 'EVA_EXPIRY_NOT_PROVISIONED')
    timer = name('expire', store.run)
    state = command(('/usr/bin/systemctl', 'show', timer + '.timer', '--property=LoadState', '--value'), deadline)
    require(state.strip() == b'not-found', 'EVA_NAME_COLLISION')
    delay = expires - int(time.time())
    require(0 < delay <= TTL, 'EVA_STAGE_DEADLINE')
    command(('/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + timer, '--on-active=' + str(delay) + 's',
             '--timer-property=AccuracySec=1s', '--property=Type=oneshot', '--property=TimeoutStartSec=120',
             '--property=UMask=0077', '/usr/bin/python3', '-I', '-B', '-S', RUNNER, 'expire', store.run), deadline)


def lookup(docker, role, run):
    selector = 'name=^/' + name(role, run) + '$'
    raw = docker.run(('container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', selector), limit=256)
    rows = raw.decode('ascii').splitlines()
    require(not rows or len(rows) == 1 and ID.fullmatch(rows[0]), 'EVA_NAME_COLLISION')
    return rows[0] if rows else None


def observe(docker, identity, store, aliases):
    raw = docker.run(('container', 'inspect', '--format', FORMAT, identity), limit=16384)
    row = strict_json(raw.decode('ascii'))
    require(row.get('id') == identity and row.get('run') == store.run and row.get('image') in aliases,
            'EVA_OWNERSHIP_REFUSED')
    return row


def clean(store, state, deadline):
    require(os.geteuid() == 0, 'EVA_HOST_REFUSED')
    # Revoke inputs first, including when provisioning failed before the first unit started.
    for path in (store.path / 'anthropic.key', store.path / 'input' / 'gate-user',
                 store.path / 'input' / 'gate-password', store.path / 'input' / 'bridge-secret'):
        if os.path.lexists(path):
            require(owned_file(path, (0o600, 0o444)), 'EVA_STATE_REFUSED')
            path.unlink()
    restore_apache(store, deadline)
    for role in reversed(state.get('units', [])):
        stop_live(store, role, deadline)
    if state['import_started']:
        if not state['import_complete']:
            # The archive is only needed before import. Keep the inert provenance record
            # for recovery, with no private bytes or uncertain daemon-wide deletion.
            archive = store.path / 'artifact.zip'
            if os.path.lexists(archive):
                require(owned_file(archive), 'EVA_STATE_REFUSED')
                archive.unlink()
        docker = Docker(store.path, deadline)
        for role, aliases in zip(('app', 'db'), state['aliases']):
            if role in state['prepared'] and (identity := lookup(docker, role, store.run)):
                observe(docker, identity, store, aliases)
                docker.run(('rm', '--force', '--volumes', identity), seconds=15, limit=256)
                require(lookup(docker, role, store.run) is None, 'EVA_CLEANUP_UNCONFIRMED')
        for tag, aliases in zip(state['tags'], state['aliases']):
            current = docker.image_id(tag)
            if current is not None:
                require(current in aliases, 'EVA_CLEANUP_UNCONFIRMED')
                docker.run(('image', 'rm', '--no-prune', tag), seconds=20, limit=4096)
                require(docker.image_id(tag) is None, 'EVA_CLEANUP_UNCONFIRMED')
            require(all(docker.image_present(alias) is False for alias in aliases), 'EVA_CLEANUP_UNCONFIRMED')
        require(state['import_complete'], 'EVA_CLEANUP_UNCONFIRMED')
    # This 0700 subtree was created exclusively by this invocation. Symlink-safe rmtree is mandatory.
    require(shutil.rmtree.avoids_symlink_attacks and root_directory(store.path.lstat()), 'EVA_STATE_REFUSED')
    shutil.rmtree(store.path)


def mount(path, target, readonly=True):
    return 'type=bind,source=' + str(path) + ',target=' + target + (',readonly' if readonly else '')


def role_args(store, role, tag, db=None, *, live=False):
    common = ('--name', name(role, store.run), '--label', LABEL + '=' + store.run,
              '--pull', 'never', '--ipc', 'private', *LIMITS)
    if role == 'db':
        return (*common, '--network', 'none', '--cap-drop', 'NET_RAW',
                '--tmpfs', '/var/lib/mysql:rw,noexec,nosuid,nodev,size=512m',
                '--mount', mount(store.path / 'root.password', '/run/eva-root'),
                '--mount', mount(store.path / 'root.cnf', '/run/root.cnf'),
                '--env', 'MYSQL_ROOT_PASSWORD_FILE=/run/eva-root', tag,
                '--bind-address=127.0.0.1', '--skip-name-resolve', '--mysqlx=0')
    common += ('--network', 'container:' + db, '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777')
    if live:
        sockets = ('--mount', mount(store.path / 'ingress', '/run/eva-ingress', readonly=False),
                   '--mount', mount(store.path / 'provider', '/run/eva-provider'))
    else:
        sockets = ('--tmpfs', '/run/eva-ingress:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700',
                   '--tmpfs', '/run/eva-provider:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700')
    return (*common, *sockets, '--mount', mount(store.path / 'input', '/run/eva-input'), tag)


def prove_boundary(docker, identity, store, role, aliases, db=None, *, live=False):
    row = observe(docker, identity, store, aliases)
    is_app = role == 'app'
    mounts = row['mounts']
    expected = {'/run/eva-input': (store.path / 'input', False)} if is_app else {
        '/run/eva-root': (store.path / 'root.password', False), '/run/root.cnf': (store.path / 'root.cnf', False),
    }
    if is_app and live:
        expected.update({'/run/eva-ingress': (store.path / 'ingress', True),
                         '/run/eva-provider': (store.path / 'provider', False)})
    tmpfs = {
        '/tmp': 'rw,noexec,nosuid,nodev,size=64m,mode=1777',
        '/run/eva-ingress': 'rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700',
        '/run/eva-provider': 'rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700',
    } if is_app else {'/var/lib/mysql': 'rw,noexec,nosuid,nodev,size=512m'}
    if is_app and live:
        del tmpfs['/run/eva-ingress'], tmpfs['/run/eva-provider']
    require(row['network'] == ('container:' + db if is_app else 'none')
            and row['memory'] == row['swap'] == MEMORY and row['cpu'] == 500000000 and row['pids'] == 128
            and row['privileged'] is False and row['readonly'] is is_app and row['ports'] in (None, {})
            and row['restart'] == 'no' and row['pidmode'] == '' and row['ipcmode'] == 'private'
            and row['hosts'] in (None, []) and row['tmpfs'] == tmpfs
            and row['log'] == {'Type': 'json-file', 'Config': {'max-size': '2m', 'max-file': '1'}}
            and [value.removeprefix('CAP_') for value in row['capdrop']] == (['ALL'] if is_app else ['NET_RAW'])
            and (not is_app or row['security'] in (['no-new-privileges'], ['no-new-privileges=true']))
            and type(mounts) is list and len(expected) <= len(mounts) <= len(expected) + len(tmpfs),
            'EVA_ISOLATION_REFUSED')
    seen = set()
    for mount_row in mounts:
        require(type(mount_row) is dict, 'EVA_ISOLATION_REFUSED')
        dest = mount_row.get('Destination')
        require(type(dest) is str and dest not in seen
                and ((dest in expected and mount_row.get('Source') == str(expected[dest][0])
                and mount_row.get('Type') == 'bind' and mount_row.get('RW') is expected[dest][1]
                and mount_row.get('Propagation') == 'rprivate')
                or (dest in tmpfs and mount_row.get('Type') == 'tmpfs' and mount_row.get('RW') is True)),
                'EVA_ISOLATION_REFUSED')
        seen.add(dest)
    # CLI --tmpfs lives in HostConfig.Tmpfs. Docker can omit it from Mounts.
    require(seen.issuperset(expected), 'EVA_ISOLATION_REFUSED')
    return row


def prove_tmpfs_mounts(docker, identity, configured):
    targets = {path.encode('ascii') for path in configured}
    required_flags = {b'rw', b'noexec', b'nosuid', b'nodev'}
    seen = set()
    raw = docker.run(('exec', identity, 'cat', '/proc/self/mountinfo'), limit=32768)
    for line in raw.splitlines():
        mount, separator, filesystem = line.partition(b' - ')
        fields = mount.split()
        if len(fields) < 6 or fields[4] not in targets:
            continue
        target = fields[4]
        require(target not in seen and separator and filesystem.startswith(b'tmpfs ')
                and required_flags.issubset(fields[5].split(b',')), 'EVA_ISOLATION_REFUSED')
        seen.add(target)
    require(seen == targets, 'EVA_ISOLATION_REFUSED')


def assert_loopback(docker, identity):
    interfaces = docker.run(('exec', identity, 'cat', '/proc/net/dev'), limit=4096)
    routes = docker.run(('exec', identity, 'cat', '/proc/net/route'), limit=4096).splitlines()
    require(re.findall(rb'^\s*([a-zA-Z0-9_@.-]+):', interfaces, re.M) == [b'lo'] and len(routes) == 1,
            'EVA_ISOLATION_REFUSED')


def start_role(docker, store, state, role, exact_image, db=None, *, live=False):
    index = 0 if role == 'app' else 1
    require(lookup(docker, role, store.run) is None, 'EVA_NAME_COLLISION')
    state['prepared'].append(role)
    store.save(state)
    require(exact_image in state['aliases'][index], 'EVA_IMAGE_REFUSED')
    identity = docker.create(role_args(store, role, exact_image, db, live=live))
    prove_boundary(docker, identity, store, role, state['aliases'][index], db, live=live)
    docker.start(identity)
    running = prove_boundary(docker, identity, store, role, state['aliases'][index], db, live=live)
    prove_tmpfs_mounts(docker, identity, running['tmpfs'])
    assert_loopback(docker, identity)
    net = namespace(running['pid'])
    require(net != namespace(os.getpid()), 'EVA_ISOLATION_REFUSED')
    return identity, net


def wait_ready(action, until):
    while time.monotonic() < until:
        try:
            return action()
        except DockerRefused:
            time.sleep(0.5)
    require(False, 'EVA_READINESS_REFUSED')


def initialize(docker, db, run, password, metadata):
    schema, writer = 'eva_' + run, 'writer_' + run
    ready = wait_ready(lambda: docker.sql(db, b'SELECT 1;'), min(docker.deadline, time.monotonic() + 65))
    require(ready.strip() == b'1', 'EVA_DB_REFUSED')
    for mode in ('schema', 'seed'):
        prefix = 'CREATE DATABASE `' + schema + '` CHARACTER SET utf8mb4;\n' if mode == 'schema' else ''
        docker.sql(db, (prefix + 'USE `' + schema + '`;\n').encode('ascii') + metadata[mode + '.sql'])
    account = "'" + writer + "'@'127.0.0.1'"
    sql = (f"CREATE USER {account} IDENTIFIED BY '{password}';"
           f"GRANT SELECT, UPDATE (`id`) ON `{schema}`.`tnk_faq_group` TO {account};"
           f"GRANT SELECT, INSERT, UPDATE ON `{schema}`.`tnk_faq` TO {account}; SHOW GRANTS FOR {account};")
    rows = docker.sql(db, sql.encode('ascii')).decode('ascii').replace('`', '').splitlines()
    require(len(rows) == 3 and set(rows) == {
        f'GRANT USAGE ON *.* TO {writer}@127.0.0.1',
        f'GRANT SELECT, UPDATE (id) ON {schema}.tnk_faq_group TO {writer}@127.0.0.1',
        f'GRANT SELECT, INSERT, UPDATE ON {schema}.tnk_faq TO {writer}@127.0.0.1',
    }, 'EVA_DB_GRANTS_REFUSED')
    server = docker.sql(db, b'SELECT @@server_uuid;').decode('ascii').strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', server), 'EVA_DB_REFUSED')
    return server


def stage(store, state, build, deadline, policy=None, credentials=None):
    artifact = store.path / 'artifact.zip'
    inspected, metadata = inspect_archive(artifact, build)
    proof = verify(artifact, inspected, deadline, containerd_layer_sources=True)
    docker = Docker(store.path, deadline)
    resource_admission(store, inspected.archive_bytes, proof, docker)
    for tag in build.tags:
        require(docker.image_id(tag) is None, 'EVA_NAME_COLLISION')
    for identity in {value for aliases in proof.aliases for value in aliases}:
        require(docker.image_present(identity) is False, 'EVA_NAME_COLLISION')
    for role in ('db', 'app'):
        require(lookup(docker, role, store.run) is None, 'EVA_NAME_COLLISION')
    state['tags'], state['aliases'] = list(build.tags), [list(values) for values in proof.aliases]
    state['import_started'] = True
    store.save(state)
    with image_stream(artifact, inspected, deadline) as stream:
        docker.run(('load',), stream=stream, input_limit=proof.docker_tar_bytes, seconds=120, limit=4096)
    images = []
    for tag, aliases in zip(build.tags, proof.aliases):
        exact = docker.image_id(tag)
        require(exact in aliases, 'EVA_IMAGE_REFUSED')
        images.append(exact)
        labels = strict_json(docker.run(('image', 'inspect', '--format', '{{json .Config.Labels}}', tag), limit=8192).decode('ascii'))
        require(labels.get('org.opencontainers.image.revision') == build.sha
                and labels.get('com.jsmjapan.scope') == 'eva-test-1620', 'EVA_IMAGE_REFUSED')
    state['import_complete'] = True
    store.save(state)
    root, password = secrets.token_hex(32), secrets.token_hex(32)
    write_new(store.path / 'root.password', root.encode('ascii'), mode=0o444)
    write_new(store.path / 'root.cnf', ('[client]\nuser=root\npassword=' + root + '\n').encode('ascii'))
    db, net = start_role(docker, store, state, 'db', images[1])
    server = initialize(docker, db, store.run, password, metadata)
    inputs = store.path / 'input'
    inputs.mkdir(mode=0o755)
    inputs.chmod(0o755)
    profile = {'mode': 'ci', 'run': store.run, 'origin': 'https://eva-teacher-test.invalid',
               'until': state['expires'], 'server_uuid': server}
    gate = {'bridge-secret': secrets.token_hex(32), 'gate-user': 'eva-local-only', 'gate-password': secrets.token_hex(24)}
    if policy is not None:
        now = int(time.time())
        until = now + LEASE_SECONDS
        require(until <= state['expires'] and (now + 32400) // 86400 == (until + 32400) // 86400,
                'EVA_LIVE_WINDOW_REFUSED')
        profile.update(mode='live', origin=policy['origin'], until=until)
        gate = {key: credentials[key] for key in gate}
        provision_live_paths(store, profile, policy, credentials)
    write_new(inputs / 'profile.json', canonical(profile), mode=0o444)
    for key, value in {'db-password': password, 'session-key': secrets.token_hex(32), **gate}.items():
        write_new(inputs / key, value.encode('ascii'), mode=0o444)
    app, app_net = start_role(docker, store, state, 'app', images[0], db, live=policy is not None)
    require(net == app_net, 'EVA_ISOLATION_REFUSED')
    arguments = ('exec', app, 'python3', '-I', '-B', '-c', HEALTH_PROGRAM)
    ready = wait_ready(lambda: docker.run(arguments, seconds=4, limit=256), min(docker.deadline, time.monotonic() + 20))
    require(strict_json(ready.decode('ascii')) == {'status': 'ready', 'pdo': 'bound', 'tables': 2}, 'EVA_PDO_REFUSED')
    receipt = {'status': 'STAGED_LOCAL_ONLY', 'run': store.run, 'expires': state['expires'],
               'build_sha': build.sha, 'artifact_sha256': build.archive_sha256,
               'pdo': 'BOUND_SYNTHETIC', 'https': 'NOT_CONFIGURED', 'telegram': 'NOT_RUN', 'claude': 'NOT_RUN'}
    if policy is not None:
        live_services(docker, app, store, state, policy, profile['until'], deadline)
        shared = policy['ingress'] == 'existing-apache'
        receipt.update(status='STAGED_LIVE_READY', expires=profile['until'],
                       https='BOUND_EXISTING_TEST_TLS' if shared else 'BOUND_SECONDARY_LOCAL',
                       origin=PUBLIC_ORIGIN if shared else policy['origin'])
    return receipt


def provision_live_paths(store, profile, policy, credentials):
    folder = store.path
    for name in ('ingress', 'provider'):
        path = folder / name
        path.mkdir(mode=0o700)
        os.chown(path, 10001, 10001)
    for name in ('relay-input', 'relay-code'):
        path = folder / name
        path.mkdir(mode=0o755)
        path.chmod(0o755)
    write_new(folder / 'relay-input/profile.json', canonical(profile), mode=0o444)
    write_new(folder / 'anthropic.key', credentials['anthropic'].encode('ascii'))


def host_live_preflight(policy, deadline):
    require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'EVA_LIVE_PROVIDER_ISOLATION_REFUSED')
    if policy['ingress'] == 'existing-apache':
        original, _ = read_active()
        patched(original, policy['vhost_sha256'])
        vhosts = command(('/usr/sbin/apache2ctl', '-S'), deadline, limit=32768)
        require(PUBLIC_HOST.encode('ascii') in vhosts and b'jsm-sandbox-443.conf' in vhosts,
                'EVA_TEST_VHOST_REFUSED')
        return
    cert, key = TLS_DIRECTORY / 'tls.crt', TLS_DIRECTORY / 'tls.key'
    require(root_directory(TLS_DIRECTORY.lstat()) and owned_file(cert, (0o400, 0o600, 0o444))
            and owned_file(key, (0o400, 0o600)), 'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    verify_certificate(cert, policy)
    raw = command(('/usr/sbin/ip', '-j', '-4', 'address', 'show'), deadline, limit=32768)
    interfaces = strict_json(raw.decode('ascii'))
    candidates = [address for entry in interfaces for address in entry.get('addr_info', [])
                  if address.get('local') == policy['listen_ipv4']]
    require(len(candidates) == 1 and candidates[0].get('secondary') is True
            and candidates[0].get('scope') == 'global', 'EVA_LIVE_ADDRESS_REFUSED')

def service_properties():
    return ('--property=User=10001', '--property=Group=10001', '--property=UMask=0077',
            '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict', '--property=ProtectHome=yes',
            '--property=PrivateTmp=yes', '--property=ProtectKernelTunables=yes',
            '--property=RestrictAddressFamilies=AF_INET AF_UNIX', '--property=Restart=no',
            '--property=StandardOutput=null', '--property=StandardError=null')


def service_state(unit, property_name, deadline):
    return command(('/usr/bin/systemctl', 'show', unit, '--property=' + property_name, '--value'), deadline).strip()


def stop_live(store, role, deadline):
    unit = name(role, store.run) + '.service'
    load = service_state(unit, 'LoadState', deadline)
    if load == b'not-found':
        return
    fragment = service_state(unit, 'FragmentPath', deadline)
    description = service_state(unit, 'Description', deadline)
    command_line = service_state(unit, 'ExecStart', deadline)
    require(fragment == ('/run/systemd/transient/' + unit).encode('ascii')
            and description == live_description(store, role).encode('ascii')
            and (LIVE_RUNNER + ' ' + role + ' ' + store.run).encode('ascii') in command_line,
            'EVA_CLEANUP_UNCONFIRMED')
    command(('/usr/bin/systemctl', 'stop', unit), deadline)
    require(service_state(unit, 'ActiveState', deadline) in (b'inactive', b'failed'), 'EVA_CLEANUP_UNCONFIRMED')


def live_description(store, role):
    return 'JSM isolated Eva 1620 ' + role + ' ' + store.run


def open_service(store, state, role, until, properties, deadline):
    unit = name(role, store.run)
    require(service_state(unit + '.service', 'LoadState', deadline) == b'not-found', 'EVA_NAME_COLLISION')
    seconds = until - int(time.time())
    require(0 < seconds <= LEASE_SECONDS, 'EVA_LIVE_WINDOW_REFUSED')
    state['units'].append(role)
    store.save(state)
    command(('/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + unit,
             '--description=' + live_description(store, role), '--property=RuntimeMaxSec=' + str(seconds),
             *service_properties(), *properties,
             '/usr/bin/python3', '-I', '-B', '-S', LIVE_RUNNER, role, store.run, str(until)), deadline)
    require(service_state(unit + '.service', 'ActiveState', deadline) == b'active', 'EVA_LIVE_SERVICE_REFUSED')
    return unit + '.service'


def wait_socket(path, deadline):
    while time.monotonic() < deadline:
        try:
            observed = path.lstat()
        except FileNotFoundError:
            time.sleep(0.2)
            continue
        require(stat.S_ISSOCK(observed.st_mode) and observed.st_uid == 10001, 'EVA_LIVE_SERVICE_REFUSED')
        return
    require(False, 'EVA_LIVE_SERVICE_REFUSED')


def live_services(docker, app, store, state, policy, until, deadline):
    folder = store.path
    host_live_preflight(policy, deadline)
    for filename in ('provider.py', 'gateway.py'):
        code = docker.run(('exec', app, 'cat', '/app/' + filename), limit=16384)
        compile(code, '<pinned private image>', 'exec')
        write_new(folder / 'relay-code' / filename, code, mode=0o444)
    wait_socket(folder / 'ingress/http.sock', min(deadline, time.monotonic() + 12))
    relay = open_service(store, state, 'relay', until, (
        '--property=ReadWritePaths=-/run/eva-provider',
        '--property=BindPaths=' + str(folder / 'provider') + ':/run/eva-provider',
        '--property=BindReadOnlyPaths=' + str(folder / 'relay-input') + ':/run/eva-input '
        + str(folder / 'relay-code') + ':/run/eva-relay-code',
        '--property=LoadCredential=anthropic:' + str(folder / 'anthropic.key'),
        '--property=IPAddressDeny=any', '--property=IPAddressAllow=' + policy['provider_ipv4'] + '/32',
    ), deadline)
    require(policy['provider_ipv4'].encode('ascii') in service_state(relay, 'IPAddressAllow', deadline)
            and service_state(relay, 'IPAddressDeny', deadline), 'EVA_LIVE_PROVIDER_ISOLATION_REFUSED')
    wait_socket(folder / 'provider/anthropic.sock', min(deadline, time.monotonic() + 12))
    (folder / 'anthropic.key').unlink()
    shared = policy['ingress'] == 'existing-apache'
    properties = ('--property=BindReadOnlyPaths=' + str(folder / 'ingress') + ':/run/eva-ingress',)
    if not shared:
        properties += ('--property=AmbientCapabilities=CAP_NET_BIND_SERVICE',
                       '--property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE',
                       '--property=LoadCredential=certificate:' + str(TLS_DIRECTORY / 'tls.crt'),
                       '--property=LoadCredential=key:' + str(TLS_DIRECTORY / 'tls.key'))
    service = open_service(store, state, 'https', until, properties, deadline)
    if shared:
        install_apache(store, policy, deadline)
    host, address = (PUBLIC_HOST, '127.0.0.1') if shared else (policy['origin'][8:], policy['listen_ipv4'])
    probe_tls(host, address, policy, store.run, until, shared, deadline)
    require(service_state(service, 'ActiveState', deadline) == b'active', 'EVA_LIVE_SERVICE_REFUSED')


def apache_reload(deadline):
    command(('/usr/sbin/apache2ctl', 'configtest'), deadline)
    command(('/usr/bin/systemctl', 'reload', 'apache2.service'), deadline)


def install_apache(store, policy, deadline):
    with publisher_lock():
        config = command(('/usr/sbin/apache2ctl', '-t', '-D', 'DUMP_INCLUDES'), deadline, limit=32768)
        verify_logs(config)
        original, info = read_active()
        modified = patched(original, policy['vhost_sha256'])
        write_new(store.path / 'apache-vhost.original', original)
        replace_active(original, modified, info, store.run)
        apache_reload(deadline)


def restore_apache(store, deadline):
    backup = store.path / 'apache-vhost.original'
    if not os.path.lexists(backup):
        return
    with publisher_lock():
        original = read_owned(backup, 65536)
        modified = patched(original, sha256(original).hexdigest())
        current, info = read_active()
        if current == modified:
            replace_active(current, original, info, store.run)
            apache_reload(deadline)
        else:
            require(current == original, 'EVA_CLEANUP_UNCONFIRMED')
            # A prior rollback can have restored disk contents before the reload completed.
            apache_reload(deadline)
        backup.unlink()


def probe_tls(host, address, policy, run, expires, shared, deadline):
    context = ssl.create_default_context()
    until = min(deadline, time.monotonic() + 15)
    while time.monotonic() < until:
        try:
            with socket.create_connection((address, 443), timeout=2) as channel:
                with context.wrap_socket(channel, server_hostname=host) as tls:
                    require(sha256(tls.getpeercert(binary_form=True)).hexdigest() == policy['certificate_sha256'],
                            'EVA_LIVE_SERVICE_REFUSED')
                    path = PUBLIC_GATE if shared else '/__gate/?next=%2Fru%2F'
                    tls.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
                    response = http.client.HTTPResponse(tls)
                    try:
                        response.begin()
                        require(response.status == 401 and response.getheader('X-Eva-Test-Run') == run
                                and response.getheader('X-Eva-Test-Expires') == str(expires), 'EVA_TEST_VHOST_REFUSED')
                    finally:
                        response.close()
                    return
        except ConnectionRefusedError:
            time.sleep(0.2)
    require(False, 'EVA_LIVE_SERVICE_REFUSED')
