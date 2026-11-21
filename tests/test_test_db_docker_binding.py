"""Synthetic socket-activation evidence, never real services or the daemon."""
import importlib.util
import json
from pathlib import Path
import unittest
import copy
import os
import socket
import sys
import time
import re
import struct
import tempfile
import multiprocessing
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/test_db_docker_binding.py'
UNITS='''Id=docker.socket
LoadState=loaded
ActiveState=active
SubState=listening
Accept=no
Listen=/run/docker.sock (Stream)
Triggers=docker.service
TriggeredBy=

Id=docker.service
LoadState=loaded
ActiveState=active
SubState=running
Triggers=
TriggeredBy=docker.socket
'''
UNIX='''Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 7003 /run/docker.sock
0000000000000000: 00000002 00000000 00000000 0001 03 7004 /run/docker.sock
0000000000000000: 00000002 00000000 00010000 0001 01 9999 /PRIVATE/unrelated.sock
'''


class DockerBindingTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(),'approved socket-binding implementation is missing')
        self.modules=[];self.ns={}
        for name in ['test_db_os_metadata','test_db_docker_metadata','test_db_docker_binding']:
            spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/(name+'.py'))
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);self.modules.append(module)
            exec(compile(module.LIBRARY,'<'+name+'>','exec'),self.ns)
        self.binding=self.modules[-1]

    def fixture(self):
        ns=self.ns;state=dict(units=UNITS,unix=UNIX,start=111,namespace=False,exe=False,missing=None,extra=False)
        def stat_text(pid):return str(pid)+' (synthetic) S '+' '.join(['0']*18+[str(state['start']+pid)]+['0']*10)
        def read(path,deadline,limit=65536):
            if path.endswith('/net/unix'):return state['unix']
            if path=='/proc/404/stat' and state.get('unreadable_docker'):raise OSError('PRIVATE_REFUSED')
            if path in ('/proc/1/stat','/proc/404/stat'):return stat_text(int(path.split('/')[2]))
            raise AssertionError('unapproved synthetic read')
        def link(path,deadline):
            if path=='/proc/1/exe':return '/PRIVATE/wrong' if state['exe'] else '/usr/lib/systemd/systemd'
            if path=='/proc/404/exe':return '/usr/bin/dockerd'
            if '/ns/' in path:
                namespace=path.rsplit('/',1)[1]
                return namespace+':['+('999' if state['namespace'] and path.startswith('/proc/1/') else {'net':'10','mnt':'11','pid':'12'}[namespace])+']'
            raise AssertionError('unapproved synthetic link')
        def fds(pid,deadline):
            self.assertIn(pid,(1,404))
            return ({8000+pid} if state['missing']==pid else {7003,8000+pid})|({99999} if state['extra'] else set())
        ns['_proc_read']=read;ns['_readlink']=link;ns['_fd_sockets']=fds
        ns['_docker_socket_metadata']=lambda deadline:('filesystem',12345)
        ns['_systemctl_snapshot']=lambda properties,units,deadline:state['units']
        return state

    def call(self,peer=(1,0,0),after=None,binding=True,unit=None,after_begin=None,response=None):
        for folder in ('scripts','tests'):
            if str(ROOT/folder) not in sys.path:sys.path.insert(0,str(ROOT/folder))
        from test_test_db_docker_metadata import DockerMetadataTests
        core=DockerMetadataTests();core.setUp();connection=core.transport(peer,response=response)
        credentials=connection.getsockopt;connection.peer_reads=[]
        def peer_read(*args):connection.peer_reads.append(args);return credentials(*args)
        connection.getsockopt=peer_read
        if after:
            send=connection.sendall
            def sent(data):send(data);after()
            connection.sendall=sent
        api=SimpleNamespace(AF_UNIX=socket.AF_UNIX,SOCK_STREAM=socket.SOCK_STREAM,SO_PEERCRED=17,SOL_SOCKET=socket.SOL_SOCKET,timeout=socket.timeout,socket=lambda *args:connection)
        unit=dict(load='loaded',active='active',pid=404) if unit is None else unit
        with patch.dict(self.ns,{'socket':api}):
            try:pending=self.ns['_docker_begin'](unit,time.monotonic()+2,binding=binding)
            except TypeError:self.fail('single-connection binding hook is missing')
            if after_begin:after_begin()
            result=self.ns['_docker_finish'](pending,unit,time.monotonic()+2)
            diagnostic=self.ns['_binding_public'](pending,result) if binding else None
        return result,diagnostic,connection

    def test_strong_inherited_listener_chain_uses_same_single_connection_and_one_get(self):
        self.fixture();result,diagnostic,connection=self.call()
        self.assertEqual(len(connection.connected),1);self.assertEqual(len(connection.sent),1)
        self.assertEqual(len(connection.peer_reads),1)
        self.assertEqual(result['state'],'OBSERVED');self.assertTrue(result['attempted'])
        self.assertEqual(diagnostic['mode'],'SYSTEMD');self.assertEqual(diagnostic['state'],'PROVED')
        self.assertEqual(diagnostic['peer_kind'],'PID1');self.assertTrue(diagnostic['peer_root'])
        self.assertTrue(diagnostic['before_proved']);self.assertTrue(diagnostic['after_stable'])
        for field in ('unit_relation','init_expected','docker_expected','namespaces_match','listener_unique','init_has_listener','docker_has_listener'):
            self.assertTrue(diagnostic[field],field)
        self.assertNotIn('PRIVATE',json.dumps([result,diagnostic]))

    def test_bad_uid_or_peer_kind_does_not_read_association_or_send_get(self):
        self.fixture();self.ns['_systemctl_snapshot']=lambda *args:self.fail('bad peer reached association')
        for peer,reason in [((1,1000,0),'PEER_UID_REFUSED'),((405,0,0),'PEER_PID_REFUSED')]:
            with self.subTest(peer=peer):
                result,diagnostic,connection=self.call(peer)
                self.assertFalse(result['attempted']);self.assertEqual(connection.sent,[])
                self.assertEqual(diagnostic['reason'],reason);self.assertEqual(diagnostic['state'],'UNKNOWN')

    def test_bad_proof_before_get_never_sends_even_if_other_axes_are_good(self):
        for case in ['units','exe','namespace','missing_init','missing_docker','listener']:
            self.setUp();state=self.fixture()
            if case=='units':state['units']=UNITS.replace('Accept=no','Accept=yes')
            if case=='exe':state['exe']=True
            if case=='namespace':state['namespace']=True
            if case=='missing_init':state['missing']=1
            if case=='missing_docker':state['missing']=404
            if case=='listener':state['unix']=UNIX+UNIX.splitlines()[1]+'\n'
            result,diagnostic,connection=self.call()
            self.assertFalse(result['attempted'],case);self.assertEqual(connection.sent,[],case)
            self.assertEqual(diagnostic['state'],'UNKNOWN');self.assertEqual(result['containers'],[])

    def test_post_get_drift_discards_rows_but_preserves_attempt(self):
        for case in ['units','start','namespace','missing','listener']:
            self.setUp();state=self.fixture()
            def change():
                if case=='units':state['units']=UNITS.replace('Accept=no','Accept=yes')
                if case=='start':state['start']+=1
                if case=='namespace':state['namespace']=True
                if case=='missing':state['missing']=404
                if case=='listener':state['unix']=UNIX.replace('7003','7009')
            result,diagnostic,connection=self.call(after=change)
            self.assertTrue(result['attempted'],case);self.assertEqual(len(connection.sent),1)
            self.assertEqual(result['state'],'UNKNOWN');self.assertEqual(result['containers'],[])
            self.assertEqual(diagnostic['state'],'UNKNOWN')

    def test_socket_change_before_get_does_not_claim_a_postcheck_ran(self):
        self.fixture();calls=[0]
        def metadata(deadline):
            calls[0]+=1;return ('filesystem',12345 if calls[0]==1 else 98765)
        self.ns['_docker_socket_metadata']=metadata
        result,diagnostic,connection=self.call()
        self.assertFalse(result['attempted']);self.assertEqual(connection.sent,[])
        self.assertEqual(diagnostic['state'],'UNKNOWN');self.assertEqual(diagnostic['reason'],'SOCKET_CHANGED')
        self.assertIsNone(diagnostic['after_stable'])

    def test_last_preget_socket_guard_must_pass_before_binding_is_marked_proved(self):
        self.fixture();calls=[0]
        def metadata(deadline):
            calls[0]+=1;return ('filesystem',12345 if calls[0]<3 else 98765)
        self.ns['_docker_socket_metadata']=metadata
        result,diagnostic,connection=self.call()
        self.assertFalse(result['attempted']);self.assertEqual(connection.sent,[])
        self.assertIsNone(diagnostic['before_proved']);self.assertIsNone(diagnostic['after_stable'])

    def test_unrelated_fd_churn_does_not_invalidate_same_listener_capability(self):
        state=self.fixture();result,diagnostic,connection=self.call(after=lambda:state.update(extra=True))
        self.assertEqual(result['state'],'OBSERVED');self.assertEqual(diagnostic['state'],'PROVED')
        self.assertEqual(len(connection.sent),1)

    def test_exact_mainpid_uses_old_path_without_any_new_association_read(self):
        self.fixture();self.ns['_systemctl_snapshot']=lambda *args:self.fail('exact MainPID reached new query')
        result,diagnostic,connection=self.call(peer=(404,0,0))
        self.assertEqual(result['state'],'OBSERVED');self.assertEqual(diagnostic['mode'],'MAINPID')
        self.assertEqual(diagnostic['state'],'PROVED');self.assertIsNone(diagnostic['unit_relation'])
        old,_,old_connection=self.call(peer=(404,0,0),binding=False)
        self.assertEqual(result,old);self.assertEqual(connection.sent,old_connection.sent)

    def test_direct_mode_matches_default_v4_on_refusals_and_incomplete_data(self):
        for peer,unit,response in [((404,1000,0),None,None),
                ((404,0,0),dict(load='not-found',active='inactive',pid=0),None),
                ((404,0,0),None,b'{'),((404,0,0),None,b'[]'),
                ((404,0,0),None,json.dumps([{'Id':format(i,'064x')} for i in range(9)]).encode())]:
            with self.subTest(peer=peer,response=response):
                self.fixture();self.ns['_systemctl_snapshot']=lambda *args:self.fail('direct branch queried binding metadata')
                new,_,connection=self.call(peer,unit=unit,response=response)
                old,_,old_connection=self.call(peer,unit=unit,response=response,binding=False)
                self.assertEqual(new,old);self.assertEqual(connection.connected,old_connection.connected)
                self.assertEqual(connection.peer_reads,old_connection.peer_reads);self.assertEqual(connection.sent,old_connection.sent)

    def test_unavailable_unit_skips_binding_and_does_not_claim_peer_or_namespace(self):
        self.fixture();self.ns['_systemctl_snapshot']=lambda *args:self.fail('unavailable unit reached association')
        result,diagnostic,connection=self.call(unit=dict(load='not-found',active='inactive',pid=0))
        self.assertEqual(diagnostic['state'],'SKIPPED');self.assertEqual(diagnostic['reason'],'UNIT_UNAVAILABLE')
        self.assertIsNone(diagnostic['peer_root']);self.assertEqual(diagnostic['peer_kind'],'UNKNOWN')
        self.assertFalse(result['attempted']);self.assertEqual(connection.connected,[])

    def test_partial_process_read_does_not_claim_all_namespaces_match(self):
        state=self.fixture();state['unreadable_docker']=True
        result,diagnostic,connection=self.call()
        self.assertIsNone(diagnostic['namespaces_match']);self.assertFalse(result['attempted'])
        self.assertEqual(connection.sent,[]);self.assertNotIn('PRIVATE',json.dumps(diagnostic))

    def test_preproof_and_postproof_share_initial_absolute_deadline(self):
        now=[0.0];self.fixture()
        def late_query(*args):now[0]=.8;return UNITS
        self.ns['_systemctl_snapshot']=late_query
        with patch.object(self.ns['time'],'monotonic',side_effect=lambda:now[0]):
            result,diagnostic,connection=self.call()
        self.assertFalse(result['attempted']);self.assertEqual(connection.sent,[]);self.assertEqual(diagnostic['reason'],'DEADLINE')
        self.setUp();self.fixture();now[0]=0
        with patch.object(self.ns['time'],'monotonic',side_effect=lambda:now[0]):
            result,diagnostic,connection=self.call(after_begin=lambda:now.__setitem__(0,.8))
        self.assertTrue(result['attempted']);self.assertEqual(len(connection.sent),1)
        self.assertEqual(result['state'],'UNKNOWN');self.assertEqual(diagnostic['reason'],'DEADLINE')

    def test_new_unit_query_uses_existing_bounded_transport_and_rejects_other_shapes(self):
        properties=('Id','LoadState','ActiveState','SubState','Accept','Listen','Triggers','TriggeredBy')
        def reached(*args):raise RuntimeError('BOUNDED_PATH_GUARD')
        with patch.dict(self.ns,{'_parents':reached}):
            try:self.ns['_systemctl_snapshot'](properties,('docker.socket','docker.service'),time.monotonic()+1)
            except RuntimeError as error:self.assertEqual(str(error),'BOUNDED_PATH_GUARD')
            except ValueError:self.fail('approved fixed query was refused before the bounded path guard')
            for bad in [(properties,('docker.service','docker.socket')),(properties+('Environment',),('docker.socket','docker.service'))]:
                with self.assertRaises(ValueError):self.ns['_systemctl_snapshot'](*bad,time.monotonic()+1)

    def test_closed_binding_projection_rejects_raw_fields_bad_axes_and_false_phase(self):
        self.assertTrue(hasattr(self.binding,'project_binding'),'closed binding projector is missing')
        self.fixture();packet,diagnostic,_=self.call()
        self.assertEqual(self.binding.project_binding(diagnostic,packet),diagnostic)
        for case in ('raw','integer','root','kind','after','missing'):
            value=copy.deepcopy(diagnostic)
            if case=='raw':value['raw_unit']='PRIVATE'
            if case=='integer':value['init_has_listener']=1
            if case=='root':value['peer_root']=False
            if case=='kind':value['peer_kind']='OTHER'
            if case=='after':value['after_stable']=None
            if case=='missing':del value['unit_relation']
            self.assertIsNone(self.binding.project_binding(value,packet),case)
        self.setUp();self.fixture();packet,diagnostic,_=self.call(unit=dict(load='not-found',active='inactive',pid=0))
        self.assertIsNotNone(self.binding.project_binding(diagnostic,packet))
        diagnostic['after_stable']=False
        self.assertIsNone(self.binding.project_binding(diagnostic,packet),'no GET cannot claim a postcheck')

    def test_v5_dispatch_and_projection_leave_v2_v3_v4_closed_and_sql_blocked(self):
        for folder in ('scripts','tests'):
            if str(ROOT/folder) not in sys.path:sys.path.insert(0,str(ROOT/folder))
        from test_test_db_os_metadata import OsMetadataTests
        import test_db_metadata_readonly as parent
        self.fixture();packet,diagnostic,_=self.call()
        fixture=OsMetadataTests();fixture.setUp();ns,additional,_=fixture.detail_fixture()
        additional['docker']=dict(load='loaded',active='active',pid=404)
        exec(compile(self.modules[1].LIBRARY,'<docker>','exec'),ns);exec(compile(self.binding.LIBRARY,'<binding>','exec'),ns)
        ns['_docker_begin']=lambda unit,deadline,binding=False:{'binding':{'public':diagnostic},'public':packet}
        ns['_docker_finish']=lambda pending,unit,deadline:pending['public']
        try:child=ns['_observe']('b'*32,details=True,discovery=True,binding=True)
        except TypeError:self.fail('actual observer has no fixed v5 binding route')
        self.assertEqual(child['version'],'jsm-test-db-os-2760-v5')
        outer=dict(version='jsm-test-installed-route-outer-v2',nonce='b'*32,principal='marinagurina',euid=1000,root_diagnostic=child)
        result=parent.project_remote(json.dumps(outer).encode(),'b'*32)
        self.assertEqual(result['sql'],'NOT_ATTEMPTED');self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['os_observation']['docker_binding']['state'],'PROVED')
        child['version']='jsm-test-db-os-2760-v4'
        self.assertIsNone(parent._child_projection(child,'b'*32))

    @unittest.skipUnless(sys.platform=='linux' and hasattr(socket,'SO_PEERCRED'),'Linux inherited Unix listener/FD fixture')
    def test_native_inherited_listener_wire_and_shared_kernel_fd_with_synthetic_role_mapping(self):
        # No host PID1/root/service is read. Only fixture parent/child own FDs
        # are native; UID, fixed role PIDs/exes/namespaces/unit text are doubles.
        state=self.fixture()
        with tempfile.TemporaryDirectory(prefix='jsm-binding-native-') as folder:
            address=str(Path(folder)/'fixture.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(address);listener.listen(1);listener.settimeout(2);fd=listener.fileno()
            def inode(pid):
                target=os.readlink('/proc/'+str(pid)+'/fd/'+str(fd))
                match=re.fullmatch(r'socket:\[([0-9]+)\]',target)
                if match is None:raise AssertionError('fixture socket inode missing')
                return int(match[1])
            kernel=inode(os.getpid());context=multiprocessing.get_context('fork');stop=context.Event();ready=context.Queue();received=context.Queue()
            def serve():
                try:
                    ready.put(inode(os.getpid()));connection,_=listener.accept()
                    with connection:
                        connection.settimeout(2);data=bytearray()
                        while b'\r\n\r\n' not in data:
                            chunk=connection.recv(1024)
                            if not chunk:break
                            data.extend(chunk)
                        received.put(bytes(data))
                        if data:connection.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]')
                except Exception:received.put(b'FIXTURE_FAILURE')
                finally:stop.wait(3)
            child=context.Process(target=serve);child.start();native_socket=socket.socket;peer_reads=[];connections=[]
            class Connection:
                def __init__(self,*args):self.value=native_socket(*args);connections.append(self)
                def settimeout(self,value):self.value.settimeout(value)
                def connect(self,path):
                    assert path=='/run/docker.sock';self.value.connect(address)
                def getsockopt(self,*args):
                    pid,uid,gid=struct.unpack('iII',self.value.getsockopt(*args));peer_reads.append(pid)
                    assert pid==os.getpid() and pid!=child.pid
                    return struct.pack('iII',1,0,gid)
                def sendall(self,data):self.value.sendall(data)
                def recv(self,size):return self.value.recv(size)
                def close(self):self.value.close()
            try:
                self.assertEqual(ready.get(timeout=2),kernel)
                state['unix']=UNIX.replace('7003',str(kernel))
                self.ns['_fd_sockets']=lambda pid,deadline:{inode(os.getpid() if pid==1 else child.pid)}
                api=SimpleNamespace(AF_UNIX=socket.AF_UNIX,SOCK_STREAM=socket.SOCK_STREAM,SO_PEERCRED=socket.SO_PEERCRED,SOL_SOCKET=socket.SOL_SOCKET,timeout=socket.timeout,socket=Connection)
                with patch.dict(self.ns,{'socket':api}):
                    unit=dict(load='loaded',active='active',pid=404);deadline=time.monotonic()+2
                    pending=self.ns['_docker_begin'](unit,deadline,binding=True)
                    packet=self.ns['_docker_finish'](pending,unit,deadline);diagnostic=self.ns['_binding_public'](pending,packet)
                self.assertEqual(packet['state'],'OBSERVED');self.assertEqual(diagnostic['state'],'PROVED')
                self.assertEqual(len(connections),1);self.assertEqual(peer_reads,[os.getpid()])
                self.assertEqual(received.get(timeout=2),b'GET /containers/json?all=1&size=0&limit=9 HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n')
            finally:
                stop.set();child.join(3);listener.close()
                if child.is_alive():child.terminate();child.join()

    def test_fixed_unit_relation_requires_single_stream_and_reciprocity(self):
        value=self.ns['_binding_units'](UNITS)
        self.assertEqual(value['socket']['Listen'],'/run/docker.sock (Stream)')
        for bad in [UNITS.replace('Accept=no','Accept=yes'),
                UNITS.replace('SubState=listening','SubState=running'),
                UNITS.replace('Triggers=docker.service','Triggers=PRIVATE.service'),
                UNITS.replace('TriggeredBy=docker.socket','TriggeredBy=PRIVATE.socket'),
                UNITS.replace('Listen=/run/docker.sock (Stream)','Listen=/run/docker.sock (Stream) /PRIVATE.sock (Stream)'),
                UNITS.replace('Accept=no','Accept=no\nAccept=no'),UNITS+'Environment=PRIVATE\n']:
            with self.subTest(bad=bad[:60]),self.assertRaises(ValueError):self.ns['_binding_units'](bad)

    def test_unique_listener_uses_kernel_inode_and_ignores_legitimate_connected_rows(self):
        self.assertEqual(self.ns['_binding_listener'](UNIX),7003)
        self.assertNotIn('PRIVATE',str(self.ns['_binding_listener'](UNIX)))

    def test_duplicate_or_malformed_listener_is_unknown_instead_of_first_match(self):
        target=UNIX.splitlines()[1]
        for text in [UNIX+target+'\n',UNIX.replace('7003','PRIVATE'),
                UNIX.replace('00010000 0001 01 7003','00010000 0001 03 7003'),
                UNIX.replace('00010000 0001 01 7003','00010000 0002 01 7003'),
                UNIX.replace('/run/docker.sock','/PRIVATE.sock'),UNIX+'truncated\n']:
            with self.subTest(text=text[:60]),self.assertRaises(ValueError):self.ns['_binding_listener'](text)

    def test_nonzero_protocol_on_target_listener_or_connected_row_is_refused(self):
        for old in ('00000000 00010000 0001 01 7003','00000000 00000000 0001 03 7004'):
            text=UNIX.replace(old,old.replace('00000000','00000001',1))
            with self.subTest(row=old),self.assertRaises(ValueError):self.ns['_binding_listener'](text)

    def test_unit_and_proc_payload_bounds_refuse_without_returning_raw_text(self):
        for function,value in [('_binding_units','PRIVATE'*1000),('_binding_listener',UNIX+'PRIVATE'*10000)]:
            with self.assertRaises(ValueError) as caught:self.ns[function](value)
            self.assertNotIn('PRIVATE',str(caught.exception))


if __name__=='__main__':unittest.main()
