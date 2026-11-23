"""FPM namespace/inode/hash view of root-staged public PHP, synthetic only."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_db_runtime_staging_view as view
from test_db_runtime_control_contract import PHP_FILES
from test_db_control_staging import staged_php
from test_db_runtime_protocol import Rejected


class StagingViewTests(unittest.TestCase):
    def setup_view(self,root):
        directory=root/'run'/('jsm-db-2760-'+'a'*32);directory.mkdir(parents=True)
        files={}
        for name in PHP_FILES:
            raw=b'<?php // synthetic public source\n';path=directory/name;path.write_bytes(raw)
            info=path.stat();files[name]=dict(device=info.st_dev,inode=info.st_ino,size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        info=directory.stat();staging=dict(path='/run/'+directory.name,device=info.st_dev,inode=info.st_ino,files=files)
        return directory,staging

    def kernel(self,fd):
        return SimpleNamespace(deadline=time.monotonic()+3,check=lambda:None,
            ns={'_manifest_root':lambda snapshot,pid,deadline:os.dup(fd)})

    def test_actual_fpm_root_view_matches_then_manifest_and_user_ini_refusals(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(view,'root_owned',return_value=True):
            root=Path(temporary);directory,staging=self.setup_view(root);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                snapshot=(None,None,None,((40,),));kernel=self.kernel(fd)
                self.assertEqual(len(view.verify(staging,kernel,snapshot)[2]),5)
                staging['files'][PHP_FILES[0]]['inode']+=1
                with self.assertRaises(Rejected):view.verify(staging,kernel,snapshot)
                staging['files'][PHP_FILES[0]]['inode']-=1
                (directory/'.user.ini').write_text('auto_prepend_file=PRIVATE')
                with self.assertRaises(Rejected):view.verify(staging,kernel,snapshot)
                (directory/'.user.ini').unlink()
                (directory/PHP_FILES[1]).write_bytes(b'x'*staging['files'][PHP_FILES[1]]['size'])
                with self.assertRaises(Rejected):view.verify(staging,kernel,snapshot)
            finally:os.close(fd)

    def test_real_stager_to_consumer_has_same_namespace_files_and_verified_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(view,'root_owned',return_value=True):
            root=Path(temporary);(root/'run').mkdir();fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            sources={name:b'<?php // fixed synthetic source\n' for name in PHP_FILES}
            try:
                with staged_php(str(root/'run'),'b'*32,sources) as staging:
                    through_fpm=dict(staging,path='/run/jsm-db-2760-'+'b'*32)
                    self.assertTrue(bool(view.verify(through_fpm,self.kernel(fd),(None,None,None,((40,),)))))
                self.assertEqual(list((root/'run').iterdir()),[])
            finally:os.close(fd)

    def test_wrong_fpm_root_file_symlink_size_and_hash_refused(self):
        for mutation in ('root','symlink','size','hash'):
            with tempfile.TemporaryDirectory() as temporary,patch.object(view,'root_owned',return_value=True):
                root=Path(temporary);directory,staging=self.setup_view(root)
                selected=root
                if mutation=='root':
                    selected=root/'other';selected.mkdir();self.setup_view(selected)
                if mutation=='symlink':
                    path=directory/PHP_FILES[0];path.unlink();path.symlink_to(PHP_FILES[1])
                if mutation=='size':staging['files'][PHP_FILES[0]]['size']+=1
                if mutation=='hash':staging['files'][PHP_FILES[0]]['sha256']='0'*64
                fd=os.open(selected,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    with self.assertRaises(Rejected):view.verify(staging,self.kernel(fd),(None,None,None,((40,),)))
                finally:os.close(fd)

    def test_invalid_path_bool_identity_and_total_limit_before_any_root_read(self):
        for staging in ({},dict(path='/private',device=1,inode=2,files={}),
            dict(path='/run/jsm-db-2760-'+'a'*32,device=1,inode=True,files={} )):
            with self.assertRaises(Rejected):view.verify(staging,SimpleNamespace(),None)
        self.assertFalse(view.root_owned(SimpleNamespace(st_uid=5,st_mode=0o100644),0o100000))
        self.assertFalse(view.root_owned(SimpleNamespace(st_uid=0,st_mode=0o100666),0o100000))

if __name__=='__main__':unittest.main()
