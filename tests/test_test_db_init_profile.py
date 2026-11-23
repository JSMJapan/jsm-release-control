"""Code-owned init binding profile; synthetic FDs, no host PID1 or daemon."""
import json
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
import test_test_db_docker_binding as fixtures


class InitProfileTests(unittest.TestCase):
    def setUp(self):
        self.core=fixtures.DockerBindingTests();self.core.setUp()
        self.ns=self.core.ns;self.actual=self.ns['_fd_sockets']

    def engine(self,init_count=512,docker_count=128,listener_at=1):
        state=self.core.fixture();state.update(counts={1:init_count,404:docker_count},
            phase='before',failure=None,missing=False,target_size=None)
        reads=[];scans=[];closed=[];check=self.ns['_check']
        class Entries:
            def __init__(inner,count):inner.count=count
            def __enter__(inner):return iter(SimpleNamespace(name=str(i)) for i in range(1,inner.count+1))
            def __exit__(inner,*args):pass
        def read(pid,deadline,*,init_binding=False):
            phase=state['phase'];scans.append((phase,pid,init_binding));index=[0]
            def parents(path,deadline):
                self.assertEqual(path,'/proc/'+str(pid)+'/fd');return [40,41],'fd'
            def checked(value):
                index[0]+=1
                if state['failure']==('deadline',index[0]):raise self.ns['MetadataRefused']('DEADLINE')
                check(value)
            def link(name,*,dir_fd):
                self.assertEqual(dir_fd,42);reads.append((phase,pid,int(name)))
                if state['failure']==('missing',int(name)):raise FileNotFoundError('PRIVATE')
                if state['target_size'] is not None and int(name)==129:return 'X'*state['target_size']
                position=listener_at[pid] if type(listener_at)is dict else listener_at
                return 'socket:[7003]' if int(name)==position and not state['missing'] else 'anon_inode:[PRIVATE]'
            os_values={name:getattr(self.ns['os'],name) for name in ('O_RDONLY','O_DIRECTORY','O_NOFOLLOW')}
            fake_os=SimpleNamespace(**os_values,open=lambda *args,**kwargs:42,
                scandir=lambda fd:Entries(state['counts'][pid]),readlink=link,close=closed.append)
            with patch.dict(self.ns,{'_parents':parents,'_check':checked,'os':fake_os}):
                return self.actual(pid,deadline,init_binding=True) if init_binding else self.actual(pid,deadline)
        self.ns['_fd_sockets']=read
        return state,reads,scans,closed

    def assert_packet(self,packet,diagnostic,connection,attempted,reason):
        self.assertEqual(diagnostic['reason'],reason)
        self.assertIs(packet['attempted'],attempted)
        self.assertEqual(len(connection.connected),1);self.assertEqual(len(connection.peer_reads),1)
        self.assertEqual(len(connection.sent),int(attempted))
        self.assertIsNotNone(self.core.binding.project_binding(diagnostic,packet))
        if reason!='NONE':
            self.assertEqual(packet['state'],'UNKNOWN');self.assertEqual(packet['containers'],[])
        self.assertNotIn('PRIVATE',json.dumps([packet,diagnostic]))

    def test_init_boundaries_scan_every_entry_before_and_after_one_get(self):
        for count in (127,128,129,511,512,513):
            with self.subTest(count=count):
                self.setUp();state,reads,scans,closed=self.engine(count)
                def after():state['phase']='after'
                packet,diagnostic,connection=self.core.call(after=after)
                self.assert_packet(packet,diagnostic,connection,count<=512,'NONE' if count<=512 else 'FD_ENTRY_LIMIT')
                if count<=512:
                    self.assertEqual(packet['state'],'OBSERVED');self.assertEqual(diagnostic['state'],'PROVED')
                    self.assertEqual(scans,[('before',1,True),('before',404,False),('after',1,True),('after',404,False)])
                    self.assertEqual(len(reads),2*(count+128));self.assertEqual(closed,[42,41,40]*4)
                else:
                    self.assertEqual(scans,[('before',1,True)]);self.assertEqual(len(reads),512)
                    self.assertEqual(closed,[42,41,40])

    def test_listener_at_last_entry_and_later_errors_cannot_short_circuit_scan(self):
        self.engine(512,128,listener_at={1:512,404:128})
        self.assert_packet(*self.core.call(),True,'NONE')
        self.setUp();state,reads,scans,closed=self.engine(512,512,listener_at=512)
        # Docker must retain128 even when its listener is beyond that bound.
        self.assert_packet(*self.core.call(),False,'FD_ENTRY_LIMIT')
        self.assertEqual(sum(pid==404 for _,pid,_ in reads),128)
        for failure,expected in [(('missing',129),'FD_NOT_FOUND'),(('missing',512),'FD_NOT_FOUND'),
                (('deadline',129),'DEADLINE'),(('deadline',512),'DEADLINE')]:
            with self.subTest(failure=failure):
                self.setUp();state,reads,scans,closed=self.engine();state['failure']=failure
                self.assert_packet(*self.core.call(),False,expected)
                self.assertEqual(scans,[('before',1,True)]);self.assertEqual(closed,[42,41,40])
                self.assertEqual(len(reads),failure[1]-(failure[0]=='deadline'))
        for size in (4096,4097):
            with self.subTest(target_size=size):
                self.setUp();state,reads,scans,closed=self.engine();state['target_size']=size
                self.assert_packet(*self.core.call(),size==4096,'NONE' if size==4096 else 'FD_TARGET_LIMIT')

    def test_default_pid1_and_docker_keep128_and_bad_selectors_fail_before_reads(self):
        self.engine()
        for pid in (1,404):
            for count in (128,129):
                self.setUp();state,reads,scans,closed=self.engine();state['counts'][pid]=count
                if count==128:self.assertEqual(self.ns['_fd_sockets'](pid,time.monotonic()+1),{7003})
                else:
                    with self.assertRaises(ValueError) as caught:self.ns['_fd_sockets'](pid,time.monotonic()+1)
                    self.assertEqual(caught.exception.fd_reason,'FD_ENTRY_LIMIT')
                self.assertEqual(len(reads),128);self.assertEqual(closed,[42,41,40])
        for pid,selector in [(1,None),(1,1),(1,'init'),(1,512),(1,{}),(True,True),
                ('1',True),(0,True),(-1,True),(404,True)]:
            with self.subTest(pid_type=type(pid).__name__,selector_type=type(selector).__name__):
                with patch.dict(self.ns,{'_parents':lambda *a:self.fail('invalid profile reached paths')}):
                    try:self.actual(pid,time.monotonic()+1,init_binding=selector)
                    except TypeError:self.fail('fixed boolean profile selector missing')
                    except ValueError:pass
                    else:self.fail('invalid profile accepted')
        with patch.dict(self.ns,{'_parents':lambda *a:self.fail('arbitrary cap reached paths')}):
            with self.assertRaises(TypeError):self.actual(1,time.monotonic()+1,max_fds=512)

    def test_profile_is_selected_only_after_init_identity_proof(self):
        for case in ('role','pid','exe','namespace'):
            with self.subTest(case=case):
                self.setUp();state=self.core.fixture();calls=[]
                self.ns['_fd_sockets']=lambda *a,**kw:calls.append((a,kw))
                if case=='exe':state['exe']=True
                if case=='namespace':state['namespace']=True
                with self.assertRaises(self.ns['BindingRefused']):
                    self.ns['_binding_process']('other' if case=='role' else 'init',2 if case=='pid' else 1,time.monotonic()+1,{})
                self.assertEqual(calls,[])

    def test_post_get_overflow_missing_listener_drift_and_deadline_discard_every_row(self):
        for case in ('overflow','listener','start','deadline'):
            with self.subTest(case=case):
                self.setUp();state,reads,scans,closed=self.engine();now=[0.0]
                def after():
                    state['phase']='after'
                    if case=='overflow':state['counts'][1]=513
                    elif case=='listener':state['missing']=True
                    elif case=='start':state['start']+=1
                    else:now[0]=.8
                with patch.object(self.ns['time'],'monotonic',side_effect=lambda:now[0]):
                    packet,diagnostic,connection=self.core.call(after=after)
                self.assert_packet(packet,diagnostic,connection,True,
                    {'overflow':'FD_ENTRY_LIMIT','listener':'FD_REFUSED','start':'BINDING_CHANGED','deadline':'DEADLINE'}[case])
                self.assertTrue(diagnostic['before_proved']);self.assertNotEqual(diagnostic['state'],'PROVED')
                if case=='overflow':self.assertEqual(sum(phase=='after' and pid==1 for phase,pid,_ in reads),512)


if __name__=='__main__':unittest.main()
