"""Regression coverage for the exact Eva receiver's Docker isolation checks."""

from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import eva_test_host as host
from eva_test_archive import EvaRefused


IMAGE = 'sha256:' + 'a' * 64
CONTAINER = 'b' * 64
RUN = 'c' * 12
BUSYBOX = 'docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec'


def bind(store, source, target, writable=False):
    return {'Source': str(store.path / source), 'Destination': target, 'Type': 'bind',
            'RW': writable, 'Propagation': 'rprivate'}


class BoundaryTest(unittest.TestCase):
    def setUp(self):
        self.store = SimpleNamespace(run=RUN, path=Path('/test/eva/a'))
        self.row = {
            'id': CONTAINER, 'run': RUN, 'image': IMAGE, 'network': 'none',
            'memory': host.MEMORY, 'swap': host.MEMORY, 'cpu': 500000000, 'pids': 128,
            'privileged': False, 'readonly': False, 'ports': None, 'restart': 'no',
            'pidmode': '', 'ipcmode': 'private', 'hosts': None, 'capdrop': ['CAP_NET_RAW'],
            'log': {'Type': 'json-file', 'Config': {'max-size': '2m', 'max-file': '1'}},
            'tmpfs': {'/var/lib/mysql': 'rw,noexec,nosuid,nodev,size=512m'},
            'mounts': [bind(self.store, 'root.password', '/run/eva-root'),
                       bind(self.store, 'root.cnf', '/run/root.cnf')],
        }
        self.docker = Mock()

    def observe(self, row=None):
        self.docker.run.return_value = json.dumps(self.row if row is None else row).encode('ascii')
        return host.prove_boundary(self.docker, CONTAINER, self.store, 'db', (IMAGE,))

    def test_engine_lists_cli_tmpfs_in_host_config_without_mount_row(self):
        self.assertEqual(self.observe(), self.row)

    def test_accepts_engine_that_also_lists_declared_tmpfs(self):
        self.row['mounts'].append({'Destination': '/var/lib/mysql', 'Type': 'tmpfs', 'RW': True})
        self.assertEqual(self.observe(), self.row)

    def test_still_requires_exact_tmpfs_options_and_binds(self):
        cases = []
        row = deepcopy(self.row)
        row['tmpfs']['/var/lib/mysql'] = 'rw,size=512m'
        cases.append(row)
        row = deepcopy(self.row)
        row['mounts'].pop()
        row['mounts'].append({'Destination': '/var/lib/mysql', 'Type': 'tmpfs', 'RW': True})
        cases.append(row)
        for fields in ({'Source': '/unexpected'}, {'RW': True}, {'Propagation': 'rshared'}):
            row = deepcopy(self.row)
            row['mounts'][0].update(fields)
            cases.append(row)
        for mount in (
            bind(self.store, 'outside', '/var/lib/mysql', True),
            bind(self.store, 'outside', '/unexpected'),
            deepcopy(self.row['mounts'][0]),
            {'Destination': '/var/lib/mysql', 'Type': 'tmpfs', 'RW': False},
            None,
        ):
            row = deepcopy(self.row)
            row['mounts'].append(mount)
            cases.append(row)
        for row in cases:
            with self.subTest(row=row), self.assertRaisesRegex(EvaRefused, 'EVA_ISOLATION_REFUSED'):
                self.observe(row)

    def test_runtime_proof_requires_effective_tmpfs_and_kernel_flags(self):
        safe = b'41 34 0:41 / /var/lib/mysql rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=524288k\n'
        self.docker.run.return_value = safe
        host.prove_tmpfs_mounts(self.docker, CONTAINER, self.row['tmpfs'])
        self.docker.run.assert_called_once_with(('exec', CONTAINER, 'cat', '/proc/self/mountinfo'), limit=32768)
        for mountinfo in (b'', safe + safe, safe.replace(b',noexec', b''), safe.replace(b' - tmpfs ', b' - ext4 ')):
            self.docker.run.return_value = mountinfo
            with self.subTest(mountinfo=mountinfo), self.assertRaisesRegex(EvaRefused, 'EVA_ISOLATION_REFUSED'):
                host.prove_tmpfs_mounts(self.docker, CONTAINER, self.row['tmpfs'])


@unittest.skipUnless(os.environ.get('JSM_EVA_NATIVE_DOCKER') == '1', 'disposable GitHub Docker fixture only')
class NativeBoundaryTest(unittest.TestCase):
    def test_database_and_live_app_pass_exact_controller_checks(self):
        class FixtureDocker(host.Docker):
            def create(self, args):
                # Preserve every receiver flag and substitute just the synthetic image command.
                image = args.index(BUSYBOX)
                app_user = ('--user', '10001:10001') if '--read-only' in args else ()
                return super().create((*args[:image], *app_user, BUSYBOX, 'sleep', '120'))

        with TemporaryDirectory() as folder:
            root = Path(folder)
            for path in ('input', 'ingress', 'provider'):
                (root / path).mkdir()
            for path in ('root.password', 'root.cnf'):
                (root / path).write_text('fixture-only', encoding='ascii')
            store = SimpleNamespace(run=secrets.token_hex(6), path=root, save=lambda _: None)
            docker = FixtureDocker(root, time.monotonic() + 90)
            image = docker.run(('image', 'inspect', '--format', '{{.Id}}', BUSYBOX), limit=128).decode('ascii').strip()
            state = {'prepared': [], 'aliases': [[BUSYBOX, image], [BUSYBOX, image]]}
            try:
                db, db_ns = host.start_role(docker, store, state, 'db', BUSYBOX)
                app, app_ns = host.start_role(docker, store, state, 'app', BUSYBOX, db, live=True)
                self.assertEqual(db_ns, app_ns)
                for identity, bind_count in ((db, 2), (app, 3)):
                    row = host.observe(docker, identity, store, (image,))
                    self.assertEqual(sum(entry['Type'] == 'bind' for entry in row['mounts']), bind_count)
                    observed = {entry['Destination'] for entry in row['mounts'] if entry['Type'] == 'tmpfs'}
                    if observed != set(row['tmpfs']):
                        print('Native Docker reports CLI tmpfs separately from Mounts')
            finally:
                for role in ('app', 'db'):
                    if identity := host.lookup(docker, role, store.run):
                        host.observe(docker, identity, store, (image,))
                        docker.run(('rm', '--force', '--volumes', identity), limit=256)
