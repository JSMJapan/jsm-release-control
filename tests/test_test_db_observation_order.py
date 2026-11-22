"""Actual observer ordering with synthetic clock/socket/proc metadata only."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
import test_test_db_os_metadata as os_fixtures
import test_test_db_docker_binding as binding_fixtures
import test_test_db_docker_metadata as docker_fixtures


class ObservationOrderTests(unittest.TestCase):
    def case(self,version=5,delay=0,post_delay=.2,action=None,body=None,peer=1,fail_read=None,initial=None):
        oscase=os_fixtures.OsMetadataTests();oscase.setUp()
        ns,additional,privacy=oscase.detail_fixture();units=ns['_parse_units'](os_fixtures.UNITS)
        ns['_unit_snapshot']=lambda deadline:copy.deepcopy(units)
        additional['docker']=dict(load='loaded',active='active',pid=404)
        binding=binding_fixtures.DockerBindingTests();binding.setUp();proof=binding.fixture()
        exec(binding.modules[1].LIBRARY,ns);exec(binding.binding.LIBRARY,ns)
        real_fd=ns['_fd_sockets']
        for key in ('_proc_read','_readlink'):ns[key]=binding.ns[key]
        clock=[0.0];events=[];queries=[];counts={};state=dict(fd_counts={1:2,404:2},socket=('fixed',1))
        if initial=='unit':additional['docker']=dict(load='not-found',active='inactive',pid=0)
        elif initial=='exe':proof['exe']=True
        elif initial=='namespace':proof['namespace']=True
        elif initial=='cap':state['fd_counts'][1]=513
        ns['time']=SimpleNamespace(monotonic=lambda:clock[0])
        def query(properties,names,deadline):
            queries.append(deadline);events.append('binding_query')
            if len(queries)==2:clock[0]+=post_delay
            return binding_fixtures.UNITS
        ns['_systemctl_snapshot']=query
        def metadata(deadline):events.append('docker_socket');return state['socket']
        ns['_docker_socket_metadata']=metadata
        class Entries:
            def __init__(inner,count):inner.count=count
            def __enter__(inner):return iter(SimpleNamespace(name=str(i)) for i in range(inner.count))
            def __exit__(inner,*args):pass
        def fds(pid,deadline,*,init_binding=False):
            events.append('init_fds' if pid==1 else 'docker_fds')
            with patch.dict(ns,{'_parents':lambda *a:([40,41],'fd')}), \
                    patch.object(ns['os'],'open',return_value=42), \
                    patch.object(ns['os'],'scandir',return_value=Entries(state['fd_counts'][pid])), \
                    patch.object(ns['os'],'readlink',return_value='socket:[8000]' if proof['missing'] else 'socket:[7003]'), \
                    patch.object(ns['os'],'close'):
                return real_fd(pid,deadline,init_binding=True) if init_binding else real_fd(pid,deadline)
        ns['_fd_sockets']=fds
        for name in ('_unit_snapshot','_additional_unit_snapshot','_privacy_snapshot','_proc_snapshot',
                '_unix_snapshot','_unix_snapshot_detailed','_socket_metadata','_datadir_metadata','_mount_snapshot','_proc_still_same'):
            original=ns[name]
            def observed(*args,_name=name,_original=original):
                role=args[0] if _name in ('_proc_snapshot','_socket_metadata','_proc_still_same') else ''
                key=_name+(':'+role if role else '');counts[key]=counts.get(key,0)+1
                label=key+':'+str(counts[key]);events.append(label)
                if key=='_socket_metadata:php' and counts[key]==1:clock[0]+=delay
                if label==fail_read:raise FileNotFoundError('PRIVATE_READ')
                return _original(*args)
            ns[name]=observed
        transport=docker_fixtures.DockerMetadataTests();transport.setUp()
        connection=transport.transport((peer,0,0),response=body)
        for method,label in (('connect','connect'),('getsockopt','peer'),('close','close')):
            original=getattr(connection,method)
            def traced(*args,_original=original,_label=label):events.append(_label);return _original(*args)
            setattr(connection,method,traced)
        original_send=connection.sendall
        def send(data):
            events.append('GET');original_send(data)
            if action in ('apache','php'):units[action]['pid']+=50
            elif action=='docker':additional['docker']['pid']=405
            elif action=='namespace':proof['namespace']=True
            elif action=='start':proof['start']+=1
            elif action=='fd':proof['missing']=1
            elif action=='cap':state['fd_counts'][1]=513
            elif action=='socket':state['socket']=('changed',2)
        connection.sendall=send
        ns['socket']=SimpleNamespace(AF_UNIX=socket.AF_UNIX,SOCK_STREAM=socket.SOCK_STREAM,
            SO_PEERCRED=17,SOL_SOCKET=socket.SOL_SOCKET,timeout=socket.timeout,socket=lambda *a:connection)
        for name in ('_docker_begin','_docker_finish'):
            original=ns[name]
            def observed(*args,_name=name,_original=original,**kwargs):
                events.append(_name);return _original(*args,**kwargs)
            ns[name]=observed
        child=ns['_observe']('b'*32,details=version>=3,discovery=version>=4,binding=version==5)
        self.assertIsNotNone(oscase.projection(child));self.assertNotIn('PRIVATE',json.dumps(child))
        self.assertEqual(child['sql'],'NOT_ATTEMPTED');self.assertEqual(child['db_proof'],'BLOCKED_TARGET_ADMISSION')
        return child,events,connection,queries

    def test_actual_observer_avoids_unrelated_delay_without_resetting_deadlines(self):
        child,events,connection,queries=self.case(delay=.6,post_delay=.2)
        self.assertEqual(child['docker_discovery']['state'],'OBSERVED')
        self.assertEqual(child['docker_binding']['state'],'PROVED')
        self.assertEqual(len(connection.connected),1);self.assertEqual(len(connection.sent),1)
        self.assertEqual(sum(x=='peer' for x in events),1)
        order=['_socket_metadata:php:1','_docker_begin','GET','_unit_snapshot:2',
            '_additional_unit_snapshot:2','_docker_finish','_privacy_snapshot:2']
        self.assertEqual(sorted(order,key=events.index),order)
        self.assertEqual(len(queries),2);self.assertAlmostEqual(queries[0],1.35);self.assertEqual(queries[0],queries[1])
        for delay,post in ((3.0,.2),(2.9,.2),(.6,.8)):
            child,events,connection,queries=self.case(delay=delay,post_delay=post)
            self.assertEqual(child['docker_discovery']['containers'],[])
            self.assertEqual(child['docker_binding']['reason'],'DEADLINE')
            self.assertEqual(len(connection.sent),0 if delay>=3 else 1)
            if delay>=3:self.assertEqual(connection.connected,[])
            if delay==2.9:self.assertEqual(queries,[3.0,3.0])

    def test_get_still_sits_inside_main_and_docker_unit_brackets(self):
        for role in ('apache','php'):
            child,events,connection,_=self.case(action=role,post_delay=0)
            self.assertEqual(child['docker_binding']['state'],'PROVED')
            self.assertEqual(child['observation_state'],'PARTIAL')
            self.assertEqual(next(s for s in child['stages'] if s['id']=='units_end')['error'],'INCONSISTENT')
            row=next(r for r in child['processes'] if r['id']==role)
            self.assertIs(row['stable'],False);self.assertEqual(row['state'],'unknown')
            if role=='php':self.assertIsNone(child['sockets'][0]['owned_by_service_mainpid'])
            self.assertLess(events.index('GET'),events.index('_unit_snapshot:2'))
        child,events,connection,_=self.case(action='docker',post_delay=0)
        self.assertEqual(child['docker_discovery']['error'],'DAEMON_CHANGED')
        self.assertEqual(child['docker_discovery']['containers'],[])
        self.assertLess(events.index('GET'),events.index('_additional_unit_snapshot:2'))

    def test_post_proof_drift_and_prior_schema_refusal_remain_closed(self):
        for action in ('namespace','start','fd','cap','socket'):
            child,events,connection,_=self.case(action=action,post_delay=0)
            self.assertTrue(child['docker_discovery']['attempted']);self.assertEqual(child['docker_discovery']['containers'],[])
            self.assertEqual(child['docker_discovery']['state'],'UNKNOWN')
            self.assertNotEqual(child['docker_binding']['state'],'PROVED')
            self.assertEqual(len(connection.sent),1)
        child,events,connection,_=self.case(body=b'{',post_delay=0)
        self.assertEqual(child['docker_discovery']['error'],'SCHEMA_REFUSED')
        self.assertEqual(child['docker_discovery']['containers'],[])
        self.assertEqual(child['docker_binding']['state'],'PROVED')

    def test_stable_v5_keeps_read_multiset_and_mainpid_mode(self):
        systemd,events,_,_=self.case(post_delay=0)
        mainpid,direct,connection,_=self.case(post_delay=0,peer=404)
        self.assertEqual(mainpid['docker_binding']['mode'],'MAINPID')
        self.assertEqual(mainpid['docker_binding']['state'],'PROVED');self.assertEqual(len(connection.sent),1)
        self.assertEqual(events.count('binding_query'),2)
        self.assertEqual(events.count('init_fds'),2);self.assertEqual(events.count('docker_fds'),2)
        self.assertEqual(events.count('docker_socket'),5)
        self.assertEqual(events.count('_unit_snapshot:1'),events.count('_unit_snapshot:2'))
        # Measured on the actual f588 observer before the reorder. Order alone
        # changes in v5; this digest includes every synthetic read/cleanup event.
        self.assertEqual(hashlib.sha256(json.dumps(sorted(events),separators=(',',':')).encode()).hexdigest(),
            'bd26bef2ae5bfa07d59c256171be6b5524a5a615bc20ab25b7829a7dabdcd695')

    def test_legacy_ordered_output_io_and_cleanup_equal_observed_base(self):
        # Literal behavioral receipts from f588e9e, not a copy of its observer.
        expected=(
            ('073fc4a167b57d251ff6a8d931e551ab4d2b40636965808cf0aaeeadfa83d5c5',
             'aa28e135d9a7bb164e26452ca739ced192b7c307166f1bcf0e0e23f15e6c8faa',
             '073fc4a167b57d251ff6a8d931e551ab4d2b40636965808cf0aaeeadfa83d5c5'),
            ('7b531d2ca187ba9b004d38e2fec8a8f2c348ad1af4382f82622d420906a07499',
             '5c73ea08efa59650728aa6d111eb1b9f165fc0d4e67b66c0c1d94ff0cfb4cd8b',
             'b94da6d5ff8c526e1a6b90afa89031adc974054943938840a3e2a2f4833e1e79'),
            ('07c50936b9254161618c162f35ef4050dbfc3e30f1a9fdcb61116bb39615cbaf',
             '97988f62ee634158f2e0f1f8ce94dc66b15443d1934201a59f57e9147ddc30e3',
             'c0b46a8276c7c6ff2259174ced47abf257a5b6c2bf787b0df5aebc17d12f6f31'))
        for version,hashes in zip((2,3,4),expected):
            for failure,want in zip((None,'_socket_metadata:php:1','_additional_unit_snapshot:2'),hashes):
                with self.subTest(version=version,failure=failure):
                    child,events,connection,_=self.case(version=version,post_delay=0,peer=404,fail_read=failure)
                    actual=[child,events,connection.connected,connection.sent and ['FIXED_GET'],connection.closed]
                    self.assertEqual(hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':')).encode()).hexdigest(),want)

    def test_initial_unavailable_or_unproved_binding_never_sends_get(self):
        for initial in ('unit','exe','namespace','cap'):
            child,events,connection,_=self.case(initial=initial,post_delay=0)
            self.assertFalse(child['docker_discovery']['attempted']);self.assertEqual(connection.sent,[])
            self.assertEqual(child['docker_discovery']['containers'],[])
            self.assertNotEqual(child['docker_binding']['state'],'PROVED')


if __name__=='__main__':unittest.main()
