"""Actual local streaming/framing/import checks, no remote SSH or private artifacts."""
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import article_test_delivery as d
import article_test_receiver as r
from article_test_artifact import Build
from article_test_host import HostRefused
from article_test_state import canonical


class DeliveryTests(unittest.TestCase):
    def test_real_pyz_loader_closure_and_not_pinned_refusal(self):
        bundle=d.package();self.assertLess(len(bundle),131072)
        self.assertLess(len(d.outer_program(bundle,'a'*32).encode()),131071)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bundle.pyz';path.write_bytes(bundle)
            script='import sys;sys.path.insert(0,sys.argv[1]);from article_test_receiver import pins\ntry:pins()\nexcept Exception as e:print(str(e))'
            result=subprocess.run([sys.executable,'-I','-B','-c',script,str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2)
            self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'ARTIFACT_NOT_PINNED\n');self.assertEqual(result.stderr,b'')

    def test_actual_header_typed_pins_and_truncated_or_extra_fields(self):
        build=Build('a'*40,'123','456','b'*64)
        raw=d.frame('STAGE','c'*12,'d'*32,'e'*40,build,7)
        def parse(raw):
            read,write=os.pipe();os.write(write,raw);os.close(write)
            try:return r.header(read,time.monotonic()+1)
            finally:os.close(read)
        with patch.object(r,'pins',return_value=build):
            self.assertEqual(parse(raw)['build'],asdict(build))
            for bad in (raw[:-1],raw.replace(b'"archive_size":7',b'"archive_size":true'),raw.replace(b'"STAGE"',b'"OTHER"')):
                with self.assertRaises(Exception):parse(bad)
        with self.assertRaises(HostRefused):parse(raw)

    def test_actual_transfer_full_duplex_stream_and_stalled_stdin_budget(self):
        actual=subprocess.Popen
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture';payload=b'x'*200000;path.write_bytes(payload)
            def drain(*args,**kwargs):return actual([sys.executable,'-I','-c','import sys;raw=sys.stdin.buffer.read();print(len(raw))'],**kwargs)
            with patch.object(d.subprocess,'Popen',drain):
                self.assertEqual(d.transfer(['synthetic'],b'prefix',path,time.monotonic()+2),b'200006\n')
            children=[]
            def stalled(*args,**kwargs):
                child=actual([sys.executable,'-I','-c','import time;time.sleep(2)'],**kwargs);children.append(child);return child
            started=time.monotonic()
            with patch.object(d.subprocess,'Popen',stalled):
                with self.assertRaises(HostRefused):d.transfer(['synthetic'],b'p'*131072,path,started+.04)
            self.assertLess(time.monotonic()-started,.5);self.assertTrue(all(x.poll() is not None for x in children))

    def test_closed_root_receipts_reject_private_extra_and_wrong_nonce(self):
        child=dict(version=r.VERSION,status='CLEANED',nonce='a'*32,euid=0,run='b'*12,containers_removed=True,owned_tags_removed=True)
        outer=dict(version='jsm-article-test-outer-v1',nonce='a'*32,principal='marinagurina',euid=1001,root=child)
        self.assertEqual(d.project(canonical(outer),'a'*32,'CLEANUP','b'*12,None)['status'],'CLEANED')
        for value in ({**outer,'nonce':'c'*32},{**outer,'root':{**child,'private':'CANARY-PRIVATE'}},
                      {**outer,'root':{**child,'containers_removed':1}},{**outer,'euid':True}):
            with self.assertRaises(HostRefused):d.project(canonical(value),'a'*32,'CLEANUP','b'*12,None)

    def test_killed_partial_receiver_has_pending_expiry_and_no_docker_cleanup(self):
        import article_test_state as state_module
        from test_article_test_host import fixture_cleanup
        payload=b'x'*131072;build=Build('a'*40,'123','456',sha256(payload).hexdigest());run='b'*12
        scripts=Path(__file__).resolve().parents[1]/'scripts'
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)/'state';marker=Path(directory)/'armed';path=base/run
            script="""import sys,os
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
import article_test_receiver as r
import article_test_host as h
import article_test_state as s
from article_test_artifact import Build
s.ROOT_UID=os.getuid()
os.geteuid=lambda:0
original=s.Store
r.Store=lambda run,create=False:original(run,sys.argv[2],create)
r.pins=lambda:Build('a'*40,'123','456',sys.argv[4])
os.statvfs=lambda path:SimpleNamespace(f_bavail=10**9,f_frsize=4096)
def arm(store,state,deadline):
 state['timer_armed']=True;store.save(state);Path(sys.argv[3]).write_bytes(b'ARMED')
h.timer=arm
r.perform(b'public-cleanup-fixture')
"""
            process=subprocess.Popen([sys.executable,'-I','-B','-c',script,str(scripts),str(base),str(marker),build.archive_sha256],
                stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                process.stdin.write(d.frame('STAGE',run,'c'*32,'d'*40,build,len(payload))+payload[:65536]);process.stdin.flush()
                end=time.monotonic()+2
                while time.monotonic()<end and (not marker.exists() or not (path/'artifact.zip').exists() or (path/'artifact.zip').stat().st_size<65536):time.sleep(.01)
                self.assertTrue(marker.exists(),'PENDING_TIMER_NOT_ARMED')
                self.assertEqual((path/'artifact.zip').stat().st_size,65536)
                process.kill();process.wait(timeout=2)
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=2)
                process.stdin.close()
            with patch.object(state_module,'ROOT_UID',os.getuid()):
                store=state_module.Store(run,base);state=store.read();store.close()
                self.assertTrue(state['pending']);self.assertTrue(state['timer_armed']);self.assertEqual(state['images'],[None,None])
                self.assertTrue((path/'bundle.pyz').exists())
                with patch.object(r,'Store',side_effect=lambda value:state_module.Store(value,base)),\
                     patch.object(r.os,'geteuid',return_value=0),patch.object(r.time,'time',return_value=state['expires']+1),\
                     patch.object(r,'Docker',side_effect=AssertionError('DOCKER_ON_PENDING')),fixture_cleanup():
                    result=r.expire(b'public-cleanup-fixture',run)
            self.assertEqual(result['status'],'CLEANED');self.assertFalse(path.exists())

if __name__=='__main__':unittest.main()
