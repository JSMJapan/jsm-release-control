"""Finite local-only Eva TEST on an authorized host, using a new MySQL instance."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import time

from apache_parity_bridge import strict_json
from article_test_docker import Docker as BoundedDocker, DockerRefused, FIELDS, ID
from article_test_host import LIMITS, MEMORY, command, namespace, resource_admission
from article_test_images import image_stream, verify
from article_test_state import canonical, valid_run
from eva_test_archive import IMAGE, inspect_archive, require

BASE = Path('/var/lib/jsm-eva-test-1620')
LABEL = 'com.jsmjapan.eva-test.run'
TTL = 1200
PHP_PORT = 19881
RUNNER = '/usr/local/libexec/jsm-eva-test-1620/eva_test_receiver.py'
EXPIRY_TIMER = 'jsm-eva-test-1620-expiry.timer'
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
        require(type(state) is dict and state.keys() == {'run', 'expires', 'import_started', 'import_complete', 'aliases', 'tags', 'prepared'}
                and state.get('run') == self.run and type(state['expires']) is int and type(state['import_started']) is bool
                and type(state['import_complete']) is bool and (not state['import_complete'] or state['import_started'])
                and (not state['prepared'] or state['import_complete']) and type(state['prepared']) is list and state['prepared'] in ([], ['db'], ['db', 'app']),
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


def mount(path, target):
    return 'type=bind,source=' + str(path) + ',target=' + target + ',readonly'


def role_args(store, role, tag, db=None):
    common = ('--name', name(role, store.run), '--label', LABEL + '=' + store.run,
              '--pull', 'never', '--ipc', 'private', *LIMITS)
    if role == 'db':
        return (*common, '--network', 'none', '--cap-drop', 'NET_RAW',
                '--tmpfs', '/var/lib/mysql:rw,noexec,nosuid,nodev,size=512m',
                '--mount', mount(store.path / 'root.password', '/run/eva-root'),
                '--mount', mount(store.path / 'root.cnf', '/run/root.cnf'),
                '--env', 'MYSQL_ROOT_PASSWORD_FILE=/run/eva-root', tag,
                '--bind-address=127.0.0.1', '--skip-name-resolve', '--mysqlx=0')
    return (*common, '--network', 'container:' + db, '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
            '--tmpfs', '/run/eva-ingress:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700',
            '--tmpfs', '/run/eva-provider:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700',
            '--mount', mount(store.path / 'input', '/run/eva-input'), tag)


def prove_boundary(docker, identity, store, role, aliases, db=None):
    row = observe(docker, identity, store, aliases)
    is_app = role == 'app'
    mounts = row['mounts']
    expected = {'/run/eva-input': store.path / 'input'} if is_app else {
        '/run/eva-root': store.path / 'root.password', '/run/root.cnf': store.path / 'root.cnf',
    }
    tmpfs = {
        '/tmp': 'rw,noexec,nosuid,nodev,size=64m,mode=1777',
        '/run/eva-ingress': 'rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700',
        '/run/eva-provider': 'rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700',
    } if is_app else {'/var/lib/mysql': 'rw,noexec,nosuid,nodev,size=512m'}
    require(row['network'] == ('container:' + db if is_app else 'none')
            and row['memory'] == row['swap'] == MEMORY and row['cpu'] == 500000000 and row['pids'] == 128
            and row['privileged'] is False and row['readonly'] is is_app and row['ports'] in (None, {})
            and row['restart'] == 'no' and row['pidmode'] == '' and row['ipcmode'] == 'private'
            and row['hosts'] in (None, []) and row['tmpfs'] == tmpfs
            and row['log'] == {'Type': 'json-file', 'Config': {'max-size': '2m', 'max-file': '1'}}
            and [value.removeprefix('CAP_') for value in row['capdrop']] == (['ALL'] if is_app else ['NET_RAW'])
            and (not is_app or row['security'] in (['no-new-privileges'], ['no-new-privileges=true']))
            and type(mounts) is list and len(mounts) == len(expected) + len(tmpfs), 'EVA_ISOLATION_REFUSED')
    seen = set()
    for mount_row in mounts:
        dest = mount_row.get('Destination')
        require(dest not in seen and ((dest in expected and mount_row.get('Source') == str(expected[dest])
                and mount_row.get('Type') == 'bind' and mount_row.get('RW') is False
                and mount_row.get('Propagation') == 'rprivate')
                or (dest in tmpfs and mount_row.get('Type') == 'tmpfs' and mount_row.get('RW') is True)),
                'EVA_ISOLATION_REFUSED')
        seen.add(dest)
    return row


def assert_loopback(docker, identity):
    interfaces = docker.run(('exec', identity, 'cat', '/proc/net/dev'), limit=4096)
    routes = docker.run(('exec', identity, 'cat', '/proc/net/route'), limit=4096).splitlines()
    require(re.findall(rb'^\s*([a-zA-Z0-9_@.-]+):', interfaces, re.M) == [b'lo'] and len(routes) == 1,
            'EVA_ISOLATION_REFUSED')


def start_role(docker, store, state, role, exact_image, db=None):
    index = 0 if role == 'app' else 1
    require(lookup(docker, role, store.run) is None, 'EVA_NAME_COLLISION')
    state['prepared'].append(role)
    store.save(state)
    require(exact_image in state['aliases'][index], 'EVA_IMAGE_REFUSED')
    identity = docker.create(role_args(store, role, exact_image, db))
    prove_boundary(docker, identity, store, role, state['aliases'][index], db)
    docker.start(identity)
    running = prove_boundary(docker, identity, store, role, state['aliases'][index], db)
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


def stage(store, state, build, deadline):
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
    write_new(inputs / 'profile.json', canonical(profile), mode=0o444)
    for key, value in {'db-password': password, 'bridge-secret': secrets.token_hex(32),
                       'gate-user': 'eva-local-only', 'gate-password': secrets.token_hex(24),
                       'session-key': secrets.token_hex(32)}.items():
        write_new(inputs / key, value.encode('ascii'), mode=0o444)
    app, app_net = start_role(docker, store, state, 'app', images[0], db)
    require(net == app_net, 'EVA_ISOLATION_REFUSED')
    arguments = ('exec', app, 'python3', '-I', '-B', '-c', HEALTH_PROGRAM)
    ready = wait_ready(lambda: docker.run(arguments, seconds=4, limit=256), min(docker.deadline, time.monotonic() + 20))
    require(strict_json(ready.decode('ascii')) == {'status': 'ready', 'pdo': 'bound', 'tables': 2}, 'EVA_PDO_REFUSED')
    return {'status': 'STAGED_LOCAL_ONLY', 'run': store.run, 'expires': state['expires'],
            'build_sha': build.sha, 'artifact_sha256': build.archive_sha256,
            'pdo': 'BOUND_SYNTHETIC', 'https': 'NOT_CONFIGURED', 'telegram': 'NOT_RUN', 'claude': 'NOT_RUN'}
