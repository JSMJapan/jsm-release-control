"""Offline Docker-summary fixtures only; never the real daemon or TEST."""
import importlib.util
import json
from pathlib import Path
import time
import unittest
import copy
import os
import struct
import socket
import sys
import stat
import tempfile
import threading
import multiprocessing
import contextlib
import io
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test_db_docker_metadata.py'
ID = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64


def summary(identity=ID):
    return dict(Id=identity, Image='mysql:5.7', ImageID=IMAGE,
        Ports=[dict(PrivatePort=3306, PublicPort=3306, IP='127.0.0.1', Type='tcp')],
        Command='PRIVATE_COMMAND', Labels={'private': 'PRIVATE_LABEL'},
        Names=['PRIVATE_NAME'], Mounts=[{'Source': 'PRIVATE_MOUNT'}])


class Wire:
    def __init__(self, chunks):
        self.chunks = list(chunks)
    def settimeout(self, value):
        assert 0 < value <= .75
    def recv(self, size):
        if not self.chunks:
            return b''
        value = self.chunks.pop(0)
        assert len(value) <= size
        return value


class DockerMetadataTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'approved Docker discovery parser is missing')
        for folder in ('scripts','tests'):
            if str(ROOT/folder) not in sys.path:sys.path.insert(0,str(ROOT/folder))
        spec = importlib.util.spec_from_file_location('docker_metadata_candidate', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.ns = {}
        spec = importlib.util.spec_from_file_location('os_metadata_candidate', ROOT/'scripts/test_db_os_metadata.py')
        os_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(os_module)
        exec(compile(os_module.LIBRARY, '<existing-os-readers>', 'exec'), self.ns)
        exec(compile(self.module.LIBRARY, '<fixed-docker-discovery>', 'exec'), self.ns)

    def transport(self, peer=(404, 0, 0), response=None):
        wire = response if response is not None else json.dumps([summary()]).encode()
        headers = b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(wire)).encode()+b'\r\n\r\n'
        class Connection(Wire):
            def __init__(self):
                super().__init__([headers+wire]); self.sent=[]; self.connected=[]; self.closed=False
            def connect(self, address): self.connected.append(address)
            def getsockopt(self, level, option, size): return struct.pack('iII', *peer)
            def sendall(self, data): self.sent.append(data)
            def close(self): self.closed=True
        return Connection()

    def probe(self, connection, unit=None, end=None, identities=None):
        self.assertTrue('_docker_begin' in self.ns, 'approved guarded Docker socket connector is missing')
        unit = unit or dict(load='loaded', active='active', pid=404)
        with patch.dict(self.ns, {'_docker_socket_metadata': lambda deadline: next(identities) if identities else ('fixed',)}), \
             patch.object(self.ns['socket'], 'SO_PEERCRED', 17, create=True), \
             patch.object(self.ns['socket'], 'socket', return_value=connection):
            deadline=time.monotonic()+2
            pending=self.ns['_docker_begin'](unit, deadline)
            return self.ns['_docker_finish'](pending, unit if end is None else end, deadline)

    def test_one_fixed_get_after_root_peer_and_stability_keeps_only_closed_receipt(self):
        connection=self.transport(); result=self.probe(connection)
        self.assertEqual(connection.connected, ['/run/docker.sock'])
        self.assertEqual(connection.sent, [b'GET /containers/json?all=1&size=0&limit=9 HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n'])
        self.assertTrue(connection.closed)
        self.assertEqual(result['state'], 'OBSERVED'); self.assertTrue(result['attempted'])
        self.assertEqual(result['error'], 'NONE'); self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(self.module.project_discovery(result), result)

    def test_peer_mismatch_including_pid1_never_sends_get_or_retries(self):
        for peer in [(1, 0, 0), (405, 0, 0), (404, 1000, 1000)]:
            connection=self.transport(peer); result=self.probe(connection)
            self.assertFalse(result['attempted']); self.assertEqual(result['error'], 'PEER_REFUSED')
            self.assertEqual(connection.sent, []); self.assertTrue(connection.closed)
            self.assertEqual(result['containers'], [])

    def test_socket_drift_before_get_and_after_response_is_not_observed(self):
        for stamps in [('before','changed','changed'), ('before','before','changed')]:
            connection=self.transport(); result=self.probe(connection, identities=iter(stamps))
            self.assertEqual(result['state'], 'UNKNOWN'); self.assertEqual(result['error'], 'SOCKET_CHANGED')
            self.assertEqual(result['containers'], [])
            self.assertEqual(len(connection.sent), 0 if stamps[0]!=stamps[1] else 1)

    def test_daemon_change_discards_success_and_ninth_container_is_incomplete(self):
        result=self.probe(self.transport(), end=dict(load='loaded',active='active',pid=405))
        self.assertEqual(result['error'], 'DAEMON_CHANGED'); self.assertEqual(result['containers'], [])
        rows=[summary(format(i,'064x')) for i in range(9)]
        result=self.probe(self.transport(response=json.dumps(rows).encode()))
        self.assertEqual(result['state'],'INCOMPLETE');self.assertEqual(result['error'],'LIMIT_EXCEEDED')
        self.assertTrue(result['attempted']);self.assertEqual(result['containers'],[])
        result=self.probe(self.transport(response=json.dumps(rows).encode()),end=dict(load='loaded',active='active',pid=405))
        self.assertEqual(result['state'],'UNKNOWN');self.assertEqual(result['error'],'DAEMON_CHANGED')

    def test_unknown_summary_values_never_turn_into_complete_empty_inventory(self):
        row=summary();row['Ports']=[{'PrivatePort': True, 'Type':'tcp'}]
        result=self.probe(self.transport(response=json.dumps([row]).encode()))
        self.assertEqual(result['state'],'INCOMPLETE');self.assertEqual(len(result['containers']),1)
        self.assertIsNone(result['containers'][0]['port3306_published'])

    def test_projection_rejects_private_fields_or_forged_completion(self):
        self.assertTrue(hasattr(self.module,'project_discovery'), 'closed Docker projection is missing')
        result=self.probe(self.transport())
        for case in ('raw', 'integer', 'id', 'family', 'false_completion'):
            value=copy.deepcopy(result)
            if case=='raw':value['containers'][0]['Command']='PRIVATE'
            if case=='integer':value['containers'][0]['port3306_published']=1
            if case=='id':value['containers'][0]['image_id']='PRIVATE'
            if case=='family':value['containers'][0]['image_family']='PRIVATE'
            if case=='false_completion':value['attempted']=False
            self.assertIsNone(self.module.project_discovery(value),case)

    def test_v4_observer_integrates_discovery_in_existing_deadline_and_old_routes_stay_closed(self):
        import sys
        sys.path.insert(0,str(ROOT/'tests'));sys.path.insert(0,str(ROOT/'scripts'))
        from test_test_db_os_metadata import OsMetadataTests
        import test_db_metadata_readonly as parent
        fixture=OsMetadataTests();fixture.setUp();ns,additional,_=fixture.detail_fixture()
        additional['docker']=dict(load='loaded',active='active',pid=404)
        exec(compile(self.module.LIBRARY,'<actual-docker-integration>','exec'),ns)
        seen=[]
        def begin(unit,deadline):
            seen.append(('begin',deadline));return {'public':dict(state='OBSERVED',attempted=True,error='NONE',containers=[])}
        def finish(pending,unit,deadline):
            seen.append(('end',deadline));return pending['public']
        ns['_docker_begin']=begin;ns['_docker_finish']=finish
        try:result=ns['_observe']('b'*32,details=True,discovery=True)
        except TypeError:self.fail('actual observer has no approved discovery route')
        self.assertEqual(result['version'],'jsm-test-db-os-2760-v4')
        self.assertEqual([x[0] for x in seen],['begin','end']);self.assertEqual(seen[0][1],seen[1][1])
        self.assertIsNotNone(parent._child_projection(result,'b'*32))
        self.assertEqual(result['sql'],'NOT_ATTEMPTED');self.assertEqual(result['effective_api_binding'],'NOT_ESTABLISHED')
        result['version']='jsm-test-db-os-2760-v3'
        self.assertIsNone(parent._child_projection(result,'b'*32),'v4 fields must not be smuggled into v3')

    def test_full_v4_receipt_max_eight_is_bounded_private_and_never_admits_database(self):
        import test_db_metadata_readonly as parent
        from test_test_db_os_metadata import OsMetadataTests
        fixture=OsMetadataTests();fixture.setUp();ns,additional,_=fixture.detail_fixture()
        additional['docker']=dict(load='loaded',active='active',pid=404)
        exec(compile(self.module.LIBRARY,'<actual-docker-integration>','exec'),ns)
        rows=self.ns['_docker_parse_body'](json.dumps([summary(format(i,'064x')) for i in range(8)]).encode())
        ns['_docker_begin']=lambda unit,deadline:{'public':dict(state='OBSERVED',attempted=True,error='NONE',containers=rows)}
        ns['_docker_finish']=lambda pending,unit,deadline:pending['public']
        child=ns['_observe']('b'*32,details=True,discovery=True)
        outer=dict(version='jsm-test-installed-route-outer-v2',nonce='b'*32,principal='marinagurina',euid=1000,root_diagnostic=child)
        out=io.StringIO();err=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):result=parent.project_remote(json.dumps(outer).encode(),'b'*32)
        self.assertEqual(out.getvalue()+err.getvalue(),'')
        self.assertLessEqual(len(json.dumps(child).encode('ascii')),12288)
        self.assertEqual(result['status'],'BLOCKED');self.assertEqual(result['sql'],'NOT_ATTEMPTED')
        for key in ['db_target_identity','db_data_provenance','db_isolation','effective_api_binding']:
            self.assertEqual(result[key],'NOT_ESTABLISHED')
        self.assertNotIn('PRIVATE',json.dumps(result))
        child['additional_services'][1].update(load_state='not-found',active_state='inactive',pid_available=False)
        self.assertIsNone(parent._child_projection(child,'b'*32),'unavailable Docker service cannot claim an observed peer')

    def test_expired_budget_prevents_path_access_and_private_exception_never_escapes(self):
        connection=self.transport()
        with patch.dict(self.ns,{'_docker_socket_metadata':lambda _:self.fail('expired path read')}):
            pending=self.ns['_docker_begin'](dict(load='loaded',active='active',pid=404),time.monotonic()-1)
        self.assertEqual(pending['public']['error'],'DEADLINE');self.assertFalse(pending['public']['attempted'])
        with patch.dict(self.ns,{'_docker_socket_metadata':lambda _:(_ for _ in ()).throw(RuntimeError('PRIVATE_EXCEPTION'))}):
            pending=self.ns['_docker_begin'](dict(load='loaded',active='active',pid=404),time.monotonic()+1)
        self.assertNotIn('PRIVATE',json.dumps(pending));self.assertEqual(pending['public']['state'],'UNKNOWN')

    def test_socket_cleanup_failure_cannot_leak_private_exception(self):
        connection=self.transport()
        connection.close=lambda:(_ for _ in ()).throw(OSError('PRIVATE_CLOSE'))
        try:result=self.probe(connection)
        except OSError:self.fail('private cleanup exception escaped Docker projection')
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_slowloris_uses_one_absolute_deadline_and_never_resets_it_per_read(self):
        now=[0.0]
        class Slow(Wire):
            def recv(self,size):now[0]+=.2;return b'H'
        with patch.object(self.ns['time'],'monotonic',side_effect=lambda:now[0]):
            with self.assertRaises(ValueError) as caught:self.ns['_docker_http_response'](Slow([]),.75)
        self.assertEqual(caught.exception.code,'DEADLINE');self.assertLessEqual(now[0],.8)

    def test_header_body_limits_and_missing_http_boundaries_are_closed(self):
        cases=[(b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nX-Pad: '+b'x'*8192+b'\r\n\r\n[]','HEADER_LIMIT'),
            (b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n'+b' '*65537,'BODY_LIMIT'),
            (b'HTTP/1.0 200 OK\nContent-Type: application/json\n\n[]','HTTP_REFUSED')]
        for wire,expected in cases:
            chunks=[wire[i:i+4096] for i in range(0,len(wire),4096)]
            with self.subTest(expected=expected),self.assertRaises(ValueError) as caught:
                self.ns['_docker_http_response'](Wire(chunks),time.monotonic()+.7)
            self.assertEqual(caught.exception.code,expected)

    def test_mapped_ipv4_loopback_is_not_reported_as_nonloopback(self):
        row=summary();row['Ports'][0]['IP']='::ffff:127.0.0.1'
        result=self.ns['_docker_parse_body'](json.dumps([row]).encode())[0]
        self.assertTrue(result['port3306_loopback']);self.assertFalse(result['port3306_nonloopback'])

    def test_actual_fixed_path_guard_accepts_0660_but_not_unsafe_owner_kind_or_parent(self):
        def meta(mode,uid=0,inode=7):
            return SimpleNamespace(st_mode=mode,st_uid=uid,st_gid=999,st_dev=1,st_ino=inode,st_nlink=1,st_ctime_ns=1)
        directory=meta(stat.S_IFDIR|0o755);good=meta(stat.S_IFSOCK|0o660)
        for leaf in [good,meta(stat.S_IFLNK|0o777),meta(stat.S_IFSOCK|0o666),meta(stat.S_IFSOCK|0o660,uid=1)]:
            with patch.dict(self.ns,{'_parents':lambda *a:([10,11],'docker.sock')}), \
                 patch.object(self.ns['os'],'fstat',return_value=directory),patch.object(self.ns['os'],'stat',return_value=leaf),patch.object(self.ns['os'],'close'):
                if leaf is good:self.assertEqual(self.ns['_docker_socket_metadata'](time.monotonic()+1),self.ns['_stamp'](good))
                else:
                    with self.assertRaises(ValueError) as caught:self.ns['_docker_socket_metadata'](time.monotonic()+1)
                    self.assertEqual(caught.exception.code,'PATH_REFUSED')
        with patch.dict(self.ns,{'_parents':lambda *a:([10],'docker.sock')}), \
             patch.object(self.ns['os'],'fstat',return_value=meta(stat.S_IFDIR|0o775)), \
             patch.object(self.ns['os'],'stat',side_effect=AssertionError('unsafe parent reached leaf')),patch.object(self.ns['os'],'close'):
            with self.assertRaises(ValueError):self.ns['_docker_socket_metadata'](time.monotonic()+1)

    @unittest.skipUnless(sys.platform=='linux' and hasattr(socket,'SO_PEERCRED'),'Linux native SO_PEERCRED fixture')
    def test_native_unix_http_fixture_uses_one_get_with_only_root_uid_synthetic(self):
        with tempfile.TemporaryDirectory(prefix='jsm-docker-fixture-') as folder:
            address=str(Path(folder)/'fixture.sock');server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            server.bind(address);server.listen(1);server.settimeout(2);seen=[];failures=[]
            def serve():
                try:
                    connection,_=server.accept()
                    with connection:
                        connection.settimeout(2);data=bytearray()
                        while b'\r\n\r\n' not in data:data.extend(connection.recv(1024))
                        seen.append(bytes(data));connection.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]')
                except Exception as error:failures.append(type(error).__name__)
            worker=threading.Thread(target=serve);worker.start();native_socket=socket.socket
            class Connection:
                def __init__(self,*args):self.value=native_socket(*args)
                def settimeout(self,value):self.value.settimeout(value)
                def connect(self,path):
                    assert path=='/run/docker.sock';self.value.connect(address)
                def getsockopt(self,*args):
                    raw=self.value.getsockopt(*args);pid,uid,gid=struct.unpack('iII',raw)
                    assert pid==os.getpid();return struct.pack('iII',pid,0,gid)
                def sendall(self,data):self.value.sendall(data)
                def recv(self,size):return self.value.recv(size)
                def close(self):self.value.close()
            try:
                api=SimpleNamespace(AF_UNIX=socket.AF_UNIX,SOCK_STREAM=socket.SOCK_STREAM,SO_PEERCRED=socket.SO_PEERCRED,SOL_SOCKET=socket.SOL_SOCKET,timeout=socket.timeout,socket=Connection)
                with patch.dict(self.ns,{'_docker_socket_metadata':lambda _:('fixture',),'socket':api}):
                    unit=dict(load='loaded',active='active',pid=os.getpid());deadline=time.monotonic()+2
                    result=self.ns['_docker_finish'](self.ns['_docker_begin'](unit,deadline),unit,deadline)
                self.assertEqual(result,dict(state='OBSERVED',attempted=True,error='NONE',containers=[]))
            finally:worker.join(3);server.close()
            self.assertFalse(worker.is_alive());self.assertEqual(failures,[]);self.assertEqual(len(seen),1)

    @unittest.skipUnless(sys.platform=='linux' and hasattr(socket,'SO_PEERCRED'),'Linux inherited-listener peer fixture')
    def test_native_inherited_listener_creator_pid_is_not_accepting_child_pid(self):
        with tempfile.TemporaryDirectory(prefix='jsm-docker-inherited-') as folder:
            address=str(Path(folder)/'fixture.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(address);listener.listen(1);listener.settimeout(2)
            context=multiprocessing.get_context('fork');received=context.Queue()
            def accept_in_child():
                try:
                    connection,_=listener.accept()
                    with connection:connection.settimeout(2);received.put(connection.recv(128))
                except Exception:received.put(b'FIXTURE_FAILED')
            child=context.Process(target=accept_in_child);child.start();native_socket=socket.socket
            class Connection:
                def __init__(self,*args):self.value=native_socket(*args)
                def settimeout(self,value):self.value.settimeout(value)
                def connect(self,path):self.value.connect(address)
                def getsockopt(self,*args):
                    pid,uid,gid=struct.unpack('iII',self.value.getsockopt(*args))
                    assert pid==os.getpid() and pid!=child.pid
                    return struct.pack('iII',pid,0,gid)
                def sendall(self,data):self.value.sendall(data)
                def close(self):self.value.close()
            try:
                api=SimpleNamespace(AF_UNIX=socket.AF_UNIX,SOCK_STREAM=socket.SOCK_STREAM,SO_PEERCRED=socket.SO_PEERCRED,SOL_SOCKET=socket.SOL_SOCKET,timeout=socket.timeout,socket=Connection)
                with patch.dict(self.ns,{'_docker_socket_metadata':lambda _:('fixture',),'socket':api}):
                    pending=self.ns['_docker_begin'](dict(load='loaded',active='active',pid=child.pid),time.monotonic()+1)
                self.assertEqual(pending['public']['error'],'PEER_REFUSED');self.assertFalse(pending['public']['attempted'])
                self.assertEqual(received.get(timeout=3),b'')
            finally:
                child.join(3);listener.close()
                if child.is_alive():child.terminate();child.join()

    def test_summary_keeps_only_typed_identity_and_endpoint_predicates(self):
        result = self.ns['_docker_parse_body'](json.dumps([summary()]).encode())
        self.assertEqual(result, [dict(id=ID, image_id=IMAGE, image_family='mysql',
            port3306_exposed=True, port3306_published=True,
            port3306_loopback=True, port3306_nonloopback=False)])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_ninth_container_is_not_reported_as_an_empty_success(self):
        eight = [summary(format(i, '064x')) for i in range(8)]
        self.assertEqual(len(self.ns['_docker_parse_body'](json.dumps(eight).encode())), 8)
        with self.assertRaises(ValueError) as caught:
            self.ns['_docker_parse_body'](json.dumps(eight + [summary('f' * 64)]).encode())
        self.assertEqual(caught.exception.code, 'LIMIT_EXCEEDED')

    def test_unknown_image_and_malformed_ports_remain_unknown_without_raw_values(self):
        item = summary(); item.update(Image='PRIVATE/image:tag', ImageID='PRIVATE_ID',
            Ports=[dict(PrivatePort=True, Type='tcp')])
        result = self.ns['_docker_parse_body'](json.dumps([item]).encode())[0]
        self.assertEqual(result['image_family'], 'other')
        self.assertIsNone(result['image_id'])
        self.assertIsNone(result['port3306_exposed'])
        self.assertIsNone(result['port3306_published'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_duplicate_identity_keys_trailing_data_and_wrong_root_are_refused(self):
        duplicate_key = ('[{"Id":"' + ID + '","Id":"' + 'c' * 64 + '"}]').encode()
        for body in (duplicate_key, b'{}', b'[] trailing', b'[true]',
                json.dumps([summary(), summary()]).encode(), b'[{"Id":true}]'):
            with self.subTest(body=body[:30]):
                with self.assertRaises(ValueError): self.ns['_docker_parse_body'](body)

    def test_ipv6_and_nonloopback_publications_are_closed_booleans(self):
        item = summary(); item['Image'] = 'mariadb:10.11'
        item['Ports'] = [dict(PrivatePort=3306, PublicPort=3307, IP='::1', Type='tcp'),
            dict(PrivatePort=3306, PublicPort=3306, IP='0.0.0.0', Type='tcp')]
        result = self.ns['_docker_parse_body'](json.dumps([item]).encode())[0]
        self.assertEqual(result['image_family'], 'mariadb')
        self.assertTrue(result['port3306_loopback']); self.assertTrue(result['port3306_nonloopback'])

    def test_fixed_http_parser_accepts_bounded_200_json_and_no_other_framing(self):
        good = b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]'
        self.assertEqual(self.ns['_docker_http_response'](Wire([good]), time.monotonic()+.7), b'[]')
        for wire in (good.replace(b'200 OK', b'302 Found'),
                good.replace(b'Content-Length: 2', b'Content-Length: 2\r\nContent-Length: 2'),
                good.replace(b'Content-Length: 2', b'Transfer-Encoding: chunked'),
                good.replace(b'application/json', b'text/html'),
                good.replace(b'Content-Length: 2', b' Content-Length: 2'),
                good.replace(b'Content-Length: 2', b'Content-Length: 65537'), good[:-1], good+b'x'):
            with self.subTest(wire=wire[:80]):
                with self.assertRaises(ValueError):
                    self.ns['_docker_http_response'](Wire([wire]), time.monotonic()+.7)


if __name__ == '__main__':
    unittest.main()
