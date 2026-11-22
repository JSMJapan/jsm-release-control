"""Passive PHP endpoint observations against closed synthetic proc fixtures."""
import copy
import importlib.util
from pathlib import Path
import json
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('db_endpoint_test_scope', ROOT / 'scripts/test_db_metadata_readonly.py')
SCOPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCOPE)

HEADER = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
TCP = '  0: 0100007F:B000 0100007F:0CEA 01 00000000:00000000 00:00000000 00000000 33 0 987\n'
UNIX = ('Num RefCount Protocol Flags Type St Inode Path\n'
        '0000000000000000: 00000002 00000000 00010000 0001 01 888 /run/php/php7.4-fpm.sock\n')
UNIT = {'php': {'load': 'loaded', 'active': 'active', 'pid': 100}}


def stat_line(pid, parent, start):
    return f'{pid} (test fixture) S {parent}' + ' 0' * 17 + f' {start}\n'


class PhpEndpointTests(unittest.TestCase):
    def observe(self, *, tcp=TCP, worker_fds=(888, 987), second=None, final_unit=UNIT,
                unix=UNIX, children='101\n', parent=100, root_change=False, second_worker_fds=None,
                deadline_mid_read=False, process_state='S'):
        namespace = {}
        exec(SCOPE.LIBRARY + SCOPE.PHP_ENDPOINT_LIBRARY, namespace)
        reads = []
        table = [tcp, tcp if second is None else second]
        current_time = [0]
        fds = [worker_fds, worker_fds if second_worker_fds is None else second_worker_fds]
        def proc_read(path, deadline, limit=65536):
            reads.append(path)
            if path == '/proc/100/stat':
                return stat_line(100, 1, 500)
            if path == '/proc/101/stat':
                return stat_line(101, parent, 501).replace(') S ', f') {process_state} ')
            if path == '/proc/100/task/100/children':
                return children
            if path == '/proc/90/net/unix':
                return unix
            if path == '/proc/90/net/tcp':
                if deadline_mid_read:current_time[0] = 2
                return HEADER + table.pop(0)
            if path == '/proc/90/net/tcp6':
                return HEADER
            self.fail('Unexpected metadata read')
        def proc_link(path, deadline):
            if path.endswith('/exe'):
                return '/usr/sbin/php-fpm7.4'
            axis = path.rsplit('/', 1)[-1]
            return f'{axis}:[456]'
        namespace.update(
            _proc_read=proc_read, _readlink=proc_link, _php_root_identity=lambda pid, deadline: (1, 2 if pid == 100 or not root_change else 3),
            _fd_sockets=lambda pid, deadline: set(fds.pop(0) if pid == 101 else (888,)),
            _unit_snapshot=lambda deadline: copy.deepcopy(final_unit))
        namespace['os'] = SimpleNamespace(getpid=lambda: 90)
        namespace['time'] = SimpleNamespace(monotonic=lambda: current_time[0])
        return namespace['_observe_php_endpoint'](UNIT, UNIT, 2), reads

    def test_stable_fpm_child_listener_and_established_loopback_peer_is_only_transport_evidence(self):
        result, reads = self.observe()
        self.assertEqual(result, dict(state='OBSERVED', reason='NONE', fpm_worker_loopback_3306=True,
            api_route='UNKNOWN', pool='UNKNOWN', forwarding='UNKNOWN', mysql_container='UNKNOWN', schema='UNKNOWN'))
        self.assertEqual(reads.count('/proc/90/net/tcp'), 2)
        self.assertEqual(reads.count('/proc/90/net/tcp6'), 2)

    def test_peers_without_established_worker_fd_or_pinned_listener_are_unknown(self):
        scenarios = (
            dict(tcp=TCP.replace(' 01 ', ' 0A ')),
            dict(tcp=TCP.replace('0100007F:0CEA', '0200000A:0CEA')),
            dict(tcp=TCP.replace('0100007F:0CEA', '0100007F:0CEB')),
            dict(worker_fds=(888,)), dict(worker_fds=(987,)), dict(unix=UNIX.splitlines()[0] + '\n'),
            dict(children=''), dict(parent=99), dict(root_change=True),
            dict(process_state='Z'), dict(process_state='STALE'), dict(process_state='Q'),
            dict(tcp=TCP + TCP.replace('  0:', '  1:').replace('987', '988').replace('B000', 'B001'),
                worker_fds=(888, 987, 988)),
            dict(unix=UNIX + UNIX.splitlines()[-1] + '\n'),
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result, _ = self.observe(**scenario)
                self.assertEqual(result['state'], 'UNKNOWN')
                self.assertIsNone(result['fpm_worker_loopback_3306'])

    def test_drift_in_tuple_or_final_php_mainpid_discards_witness(self):
        swapped = {'php': {'load': 'loaded', 'active': 'active', 'pid': 102}}
        for settings in (dict(second=TCP.replace('B000', 'B001')), dict(final_unit=swapped),
                dict(second_worker_fds=(888, 988))):
            with self.subTest(settings=settings):
                result, _ = self.observe(**settings)
                self.assertEqual(result['state'], 'UNKNOWN')
                self.assertEqual(result['reason'], 'STABILITY_NOT_CONFIRMED')

    def test_closed_projection_rejects_promotion_and_raw_metadata(self):
        result, _ = self.observe()
        self.assertEqual(SCOPE.project_php_endpoint(result), result)
        for changes in (dict(api_route='OBSERVED'), dict(mysql_container='OBSERVED'),
                dict(schema='private_db'), dict(raw_socket='127.0.0.1:3306'), dict(fpm_worker_loopback_3306=1)):
            self.assertIsNone(SCOPE.project_php_endpoint(dict(result, **changes)))

    def test_v6_projection_does_not_admit_database_even_with_stable_worker_evidence(self):
        from test_test_db_metadata_readonly import TransportTests
        suite = TransportTests()
        suite.setUp()
        nonce = 'b' * 32
        outer = suite.fixture(nonce)
        child = outer['root_diagnostic']
        result, _ = self.observe()
        child.update(version='jsm-test-db-os-2760-v6',
            php_endpoint=result,
            additional_services=[dict(id=role,load_state=None,active_state=None,pid_available=None,stable=None)
                for role in ('mariadb','docker')],
            namespace_settings=[dict(id=role,private_tmp=None,private_mounts=None,private_network=None,stable=None)
                for role in ('apache','php')],
            docker_discovery=dict(state='UNKNOWN',attempted=False,error='NOT_ATTEMPTED',containers=[]),
            stages=[dict(id=stage,attempted=True,completed=True,error='NONE') for stage in SCOPE.DETAIL_STAGE_IDS])
        library = {}
        exec(SCOPE.LIBRARY + SCOPE.DOCKER_LIBRARY + SCOPE.BINDING_LIBRARY, library)
        child['docker_binding'] = library['_binding_new']()['public']
        child['observation_state'] = 'PARTIAL'
        project = lambda: SCOPE.project_remote(json.dumps(outer).encode('ascii'), nonce)
        result = project()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['sql'], 'NOT_ATTEMPTED')
        self.assertEqual(result['effective_api_binding'], 'NOT_ESTABLISHED')
        self.assertEqual(result['db_isolation'], 'NOT_ESTABLISHED')
        self.assertIs(result['os_observation']['php_endpoint']['fpm_worker_loopback_3306'], True)
        child['effective_api_binding'] = 'ESTABLISHED'
        self.assertIsNone(project()['os_observation'])
        child['effective_api_binding'] = 'NOT_ESTABLISHED'
        child['processes'][1].update(state='unknown',pid_available=False,stable=None)
        self.assertIsNone(project()['os_observation'])

    def test_inconsistent_socket_inode_rows_refuse_instead_of_accepting_first_match(self):
        duplicate = TCP.replace('  0:', '  1:').replace(' 01 ', ' 0A ')
        result, _ = self.observe(tcp=TCP + duplicate)
        self.assertEqual(result['state'], 'UNKNOWN')
        self.assertEqual(result['reason'], 'METADATA_REFUSED')

    def test_shared_deadline_expires_without_fresh_window_for_second_sample(self):
        result, reads = self.observe(deadline_mid_read=True)
        self.assertEqual(result['state'], 'UNKNOWN')
        self.assertEqual(result['reason'], 'DEADLINE')
        self.assertEqual(reads.count('/proc/90/net/tcp'), 1)
        self.assertNotIn('/proc/90/net/tcp6', reads)
