"""Real local subprocess/file boundary tests; never invoke Docker or a VM."""
from copy import deepcopy
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import article_test_docker as d
import article_test_state as s


def record(run):
    return dict(version=s.VERSION,run=run,control_sha='a'*40,build_sha='b'*40,artifact_sha256='c'*64,
        bundle_sha256='d'*64,schema_sha256='e'*64,seed_sha256='f'*64,images=[None,None],artifact_images=['sha256:'+'a'*64,'sha256:'+'b'*64],image_aliases=[['sha256:'+'a'*64],['sha256:'+'b'*64]],container_images={'db':None,'app':None},
        tags=['jsm-article-test:'+'b'*40,'jsm-article-mysql:'+'b'*40],containers={'db':None,'app':None},create_attempted={'db':False,'app':False},created=10,
        expires=10+s.TTL,timer='jsm-article-2760-expire-'+run,timer_armed=False,import_started=False,import_complete=False,pending=False)


class HostBoundaryTests(unittest.TestCase):
    def test_real_pipe_nonreading_child_cannot_overrun_deadline(self):
        runner=d.Docker.__new__(d.Docker);runner.config=Path('/synthetic');runner.deadline=time.monotonic()+2
        actual=subprocess.Popen;children=[]
        def spawn(*args,**kwargs):
            child=actual([sys.executable,'-I','-c','import time;time.sleep(2)'],**kwargs);children.append(child);return child
        started=time.monotonic()
        with patch.object(d.subprocess,'Popen',spawn):
            with self.assertRaisesRegex(d.DockerRefused,'ARTICLE_STAGE_DEADLINE'):
                runner.run(('exec','synthetic'),data=b'x'*131072,seconds=.04)
        self.assertLess(time.monotonic()-started,.5)
        self.assertTrue(all(child.poll() is not None for child in children))

    def test_real_stream_pipe_and_output_cap(self):
        runner=d.Docker.__new__(d.Docker);runner.config=Path('/synthetic');runner.deadline=time.monotonic()+2
        actual=subprocess.Popen
        def spawn(*args,**kwargs):return actual([sys.executable,'-I','-c','import sys;sys.stdout.write(str(len(sys.stdin.buffer.read())))'],**kwargs)
        with patch.object(d.subprocess,'Popen',spawn):
            self.assertEqual(runner.run(('load',),stream=BytesIO(b'x'*200000),input_limit=200000),b'200000')
            with self.assertRaises(d.DockerRefused):runner.run(('load',),stream=BytesIO(b'x'*200001),input_limit=200000)
        def overflow(*args,**kwargs):return actual([sys.executable,'-I','-c','print("x"*100)'],**kwargs)
        with patch.object(d.subprocess,'Popen',overflow):
            with self.assertRaises(d.DockerRefused):runner.run(('info',),limit=16)

    def test_closed_state_file_and_lock_ownership(self):
        run='a'*12;value=record(run)
        self.assertTrue(s.record_valid(value,run))
        extra=deepcopy(value);extra['private_payload']='CANARY-PRIVATE'
        self.assertFalse(s.record_valid(extra,run))
        with tempfile.TemporaryDirectory() as directory,patch.object(s,'ROOT_UID',os.getuid()):
            base=Path(directory)/'state';store=s.Store(run,base,create=True)
            try:
                store.save(value);self.assertEqual(store.read(),value)
                with self.assertRaises(s.StateRefused):store.save(extra)
                with self.assertRaises(s.StateRefused):s.Store(run,base)
                store.write('root.password',b'synthetic-only',0o444)
                with self.assertRaises(FileExistsError):store.write('root.password',b'replace')
                with self.assertRaises(s.StateRefused):store.write('private.env',b'CANARY-PRIVATE')
            finally:store.close()
            again=s.Store(run,base);again.close()

    def test_interrupted_atomic_save_recovers_only_owned_temporary_file(self):
        run='b'*12;value=record(run)
        with tempfile.TemporaryDirectory() as directory,patch.object(s,'ROOT_UID',os.getuid()):
            store=s.Store(run,Path(directory)/'state',create=True)
            try:
                store.save(value);temporary=store.path/'state.tmp';temporary.write_bytes(b'{"partial":')
                store.save(value);self.assertFalse(temporary.exists());self.assertEqual(store.read(),value)
                (store.path/'state.json').unlink();temporary.write_bytes(s.canonical(value))
                self.assertEqual(store.read(),value);self.assertFalse(temporary.exists())
                temporary.symlink_to(store.path/'state.json')
                with self.assertRaises(s.StateRefused):store.save(value)
                self.assertTrue(temporary.is_symlink());self.assertTrue((store.path/'state.json').exists())
            finally:store.close()

    def test_mysql_fixed_client_character_set_is_utf8mb4(self):
        runner=d.Docker.__new__(d.Docker)
        with patch.object(runner,'run',return_value=b'') as execute:
            runner.sql('a'*64,b'SELECT 1;')
        self.assertIn('--default-character-set=utf8mb4',execute.call_args.args[0])

if __name__=='__main__':unittest.main()
