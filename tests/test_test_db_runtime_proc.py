"""Exact typed proc-net reader regression; no raw proc text reaches assertions."""
from pathlib import Path
from types import SimpleNamespace
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_db_runtime_proc as reader
from test_db_runtime_kernel import namespace
from test_db_runtime_protocol import Rejected


def info(change=None):
    value=dict(st_dev=1,st_ino=2,st_mode=0o100444,st_uid=0,st_gid=0,st_nlink=1,st_ctime_ns=8)
    value.update(change or {});return SimpleNamespace(**value)


class ProcReaderTests(unittest.TestCase):
    def fixture(self,path_change=None,held_change=None,identities=(1,1),pid=20,suffix='tcp'):
        closed=[];ids=iter(identities)
        ns={'_parents':lambda p,d:([100,101],'tcp'),'_check':lambda d:None,
            '_stamp':lambda i:(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_ctime_ns)}
        with patch.object(reader.os,'open',return_value=102),patch.object(reader.os,'fstat',side_effect=[info(),info(held_change)]),\
             patch.object(reader.os,'stat',return_value=info(path_change)),patch.object(reader.os,'read',side_effect=[b'fixture',b'']),\
             patch.object(reader.os,'close',side_effect=closed.append):
            try:return reader.read_tcp(pid,suffix,time.monotonic()+1,ns,lambda:next(ids))
            finally:self.assertEqual(closed,[102,101,100])

    def test_path_ctime_only_is_allowed_but_full_held_fd_is_required(self):
        self.assertTrue(self.fixture({'st_ctime_ns':100})=='fixture')
        with self.assertRaises(Rejected):self.fixture(held_change={'st_ctime_ns':100})

    def test_every_other_identity_field_and_process_change_refused(self):
        for field,value in [('st_dev',2),('st_ino',3),('st_mode',0o100640),('st_uid',2),('st_gid',2),('st_nlink',2)]:
            with self.subTest(field=field):
                with self.assertRaises(Rejected):self.fixture({field:value})
        with self.assertRaises(Rejected):self.fixture(identities=((1,'ns1'),(2,'ns1')))
        with self.assertRaises(Rejected):self.fixture(identities=((1,'ns1'),(1,'ns2')))

    def test_invalid_path_selectors_before_any_read(self):
        for pid,suffix in [(True,'tcp'),(1,'tcp'),('20','tcp'),(20,'unix'),(20,'../tcp')]:
            with patch.object(reader.os,'open',side_effect=AssertionError('no read')):
                with self.assertRaises(Rejected):reader.read_tcp(pid,suffix,1,{},lambda:(_ for _ in ()).throw(AssertionError('no identity')))

    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux proc-net semantics required')
    def test_native_old_reader_red_and_typed_target_reader_green_after_tick(self):
        process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            ns=namespace();deadline=time.monotonic()+3
            path='/proc/'+str(process.pid)+'/net/tcp';original=os.stat
            def tick(name,*args,**kwargs):
                if name=='tcp':time.sleep(.02)
                return original(name,*args,**kwargs)
            old_refused=False
            with patch.object(os,'stat',side_effect=tick):
                try:ns['_proc_read'](path,deadline)
                except ValueError as error:old_refused=error.args==('CHANGED_DURING_READ',)
                identity=lambda:(ns['_proc_start'](ns['_proc_read']('/proc/'+str(process.pid)+'/stat',deadline,4096),process.pid),
                                 ns['_readlink']('/proc/'+str(process.pid)+'/ns/net',deadline))
                value=reader.read_tcp(process.pid,'tcp',deadline,ns,identity)
            self.assertTrue(old_refused,'OLD_PROCNET_CTIME_REFUSAL_NOT_REPRODUCED')
            self.assertTrue(isinstance(value,str) and value.startswith('  sl'),'NEW_TYPED_READER_NOT_OBSERVED')
        finally:process.terminate();process.wait(timeout=3)

if __name__=='__main__':unittest.main()
