"""Fixed pre-entry selectors, stock-size data and actual bounded file readers."""
from pathlib import Path
from types import SimpleNamespace
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import test_db_runtime_preentry as p
from test_db_runtime_protocol import Rejected


def unit(pid=20):
    rows=dict(Id='php7.4-fpm.service',LoadState='loaded',ActiveState='active',MainPID=str(pid),
        ExecStart='{ path=/usr/sbin/php-fpm7.4 ; argv[]=/usr/sbin/php-fpm7.4 --nodaemonize --fpm-config /etc/php/7.4/fpm/php-fpm.conf ; ignore_errors=no ; pid='+str(pid)+' ; code=(null) ; status=0/0 }')
    return '\n'.join(key+'='+value for key,value in rows.items())+'\n'


class PreEntryTests(unittest.TestCase):
    def test_active_launch_exact_no_environment_or_ini_override(self):
        self.assertEqual(p.launch(unit(),20),20)
        cases=[unit().replace('--nodaemonize','--nodaemonize -d auto_prepend_file=PRIVATE'),
               unit().replace('MainPID=20','MainPID=21'),unit()+ 'Id=private\n']
        for text in cases:
            with self.assertRaisesRegex(Rejected,'^PRE_ENTRY_UNIT_REFUSED$'):p.launch(text,20)

    def test_ini_hooks_path_host_env_and_pool_selectors_fail_before_entry(self):
        self.assertEqual(p.ini_selectors(b'[PHP]\nauto_prepend_file = ""\nauto_append_file = ""\nuser_ini.filename = .user.ini\n')[0]['auto_prepend_file'],'')
        self.assertEqual(p.ini_selectors(b'[www]\nphp_admin_value[auto_prepend_file] = ""\n',True)[0]['auto_prepend_file'],'')
        for text,pool in [(b'auto_prepend_file = PRIVATE',False),(b'auto_append_file = "${PRIVATE}"',False),(b'auto_prepend_file="none"',False),
                (b'[PATH=/private]\nauto_prepend_file=',False),(b'[HOST=private]',False),
                (b'user_ini.filename=custom.ini',False),(b'auto_prepend_file[0]=none',False),
                (b'php_admin_value [ auto_prepend_file ]=PRIVATE',True),(b'env[PHP_ADMIN_VALUE] = PRIVATE',True),
                (b'env[PHPRC] = PRIVATE',True)]:
            with self.assertRaises(Rejected):p.ini_selectors(text,pool)

    def view(self,root):return p.View(root,time.monotonic()+3,time.time()+10)

    def test_actual_main_ini_stock_size_and_128k_limit_with_cleanup(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(p,'trusted',return_value=True):
            path=Path(directory);(path/'main.ini').write_bytes(b';'+b'x'*72582+b'\n')
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                self.assertEqual(len(self.view(fd).file('main.ini',131072)),72584)
                (path/'large.ini').write_bytes(b'x'*131073)
                with self.assertRaisesRegex(Rejected,'^PRE_ENTRY_LIMIT$'):self.view(fd).file('large.ini',131072)
                (path/'link.ini').symlink_to('main.ini')
                with self.assertRaises(OSError):self.view(fd).file('link.ini',131072)
            finally:os.close(fd)

    def test_actual_directory_caps_and_owner_timestamp_guards(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(p,'trusted',return_value=True):
            path=Path(directory);(path/'conf.d').mkdir()
            for n in range(32):(path/'conf.d'/('%02d-test.ini'%n)).touch()
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                self.assertEqual(len(self.view(fd).directory('conf.d',32)),32)
                (path/'conf.d'/'33-test.ini').touch()
                with self.assertRaisesRegex(Rejected,'^PRE_ENTRY_LIMIT$'):self.view(fd).directory('conf.d',32)
                old=p.View(fd,time.monotonic()+1,time.time()-10)
                with self.assertRaisesRegex(Rejected,'^PRE_ENTRY_CHANGED$'):old.directory('conf.d',64)
            finally:os.close(fd)
        self.assertFalse(p.trusted(SimpleNamespace(st_uid=5,st_mode=0o100644)))
        self.assertFalse(p.trusted(SimpleNamespace(st_uid=0,st_mode=0o100666)))
        self.assertTrue(p.trusted(SimpleNamespace(st_uid=0,st_mode=0o100644)))

    def test_actual_observe_stock_closure_and_changed_pool_refused(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(p,'trusted',return_value=True):
            root=Path(directory);base=root/'etc/php/7.4'
            for rel in ('fpm/conf.d','fpm/pool.d','mods-available'):(base/rel).mkdir(parents=True,exist_ok=True)
            (root/'usr/sbin').mkdir(parents=True)
            (base/'fpm/php.ini').write_text('[PHP]\nauto_prepend_file=\nauto_append_file=\n')
            (base/'mods-available/test.ini').write_text('memory_limit=128M\n')
            (base/'fpm/conf.d/20-test.ini').symlink_to('../../mods-available/test.ini')
            (base/'fpm/php-fpm.conf').write_text('[global]\ninclude=/etc/php/7.4/fpm/pool.d/*.conf\n')
            (base/'fpm/pool.d/www.conf').write_text('[www]\nuser=www-data\n')
            time.sleep(1.1)
            ticks=int(time.clock_gettime(time.CLOCK_BOOTTIME)*os.sysconf('SC_CLK_TCK')) if hasattr(time,'CLOCK_BOOTTIME') else 1
            identity=(ticks,1,('net:[1]','mnt:[1]','pid:[1]'),(1,1))
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            snapshot=({'php':{'pid':20}},identity,None,((40,identity,(33,33,33,33)),),(1000,1000))
            ns={'_manifest_root':lambda snapshot,pid,deadline:os.dup(fd),'_php_endpoint_identity':lambda pid,deadline:identity}
            kernel=SimpleNamespace(ns=ns,deadline=time.monotonic()+3)
            try:
                with patch.object(p,'unit_text',return_value=unit()),patch.object(p.time,'CLOCK_BOOTTIME',getattr(time,'CLOCK_BOOTTIME',1),create=True),patch.object(p.time,'clock_gettime',return_value=ticks/os.sysconf('SC_CLK_TCK')):
                    fingerprint=p.observe(kernel,snapshot)
                    self.assertTrue(len(fingerprint)>5)
                    (base/'fpm/pool.d/www.conf').write_text('[www]\nphp_admin_value[auto_prepend_file]=PRIVATE\n')
                    with self.assertRaises(Rejected):p.observe(kernel,snapshot)
            finally:os.close(fd)

if __name__=='__main__':unittest.main()
