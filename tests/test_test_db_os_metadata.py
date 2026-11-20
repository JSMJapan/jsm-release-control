"""Synthetic proc/systemd fixtures for #2760; no SSH, SQL or real /proc reads."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test_db_os_metadata.py'
NONCE = 'b' * 32
UNITS = '''Id=apache2.service
LoadState=loaded
ActiveState=active
MainPID=101

Id=php7.4-fpm.service
LoadState=loaded
ActiveState=active
MainPID=202

Id=mysql.service
LoadState=loaded
ActiveState=active
MainPID=303
'''
UNIX = '''Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 7001 /run/php/php7.4-fpm.sock
0000000000000000: 00000002 00000000 00010000 0001 01 7002 /run/mysqld/mysqld.sock
0000000000000000: 00000002 00000000 00010000 0001 01 9999 /PRIVATE/customer/file
'''


class OsMetadataTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'Missing fixed OS metadata observer')
        spec = importlib.util.spec_from_file_location('test_db_os_metadata', SCRIPT)
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.ns = {}; exec(compile(self.m.LIBRARY, '<fixed-os-metadata>', 'exec'), self.ns)

    def test_service_snapshot_only_accepts_three_fixed_units_and_typed_pids(self):
        result = self.ns['_parse_units'](UNITS)
        self.assertEqual(result, {'apache': {'load': 'loaded', 'active': 'active', 'pid': 101},
            'php': {'load': 'loaded', 'active': 'active', 'pid': 202},
            'mysql': {'load': 'loaded', 'active': 'active', 'pid': 303}})
        for value in (UNITS.replace('303', '0;PRIVATE'), UNITS + '\nId=other.service\n',
                UNITS.replace('MainPID=303', 'MainPID=303\nMainPID=303'),
                UNITS.replace('mysql.service', 'mariadb.service'), UNITS.replace('MainPID=303', 'MainPID=-1')):
            with self.subTest(value=value):
                with self.assertRaises(ValueError): self.ns['_parse_units'](value)

    def test_proc_starttime_uses_field22_and_refuses_pid_reuse_or_truncation(self):
        text = '303 (mysqld) S ' + ' '.join(['0'] * 18 + ['7654321'] + ['0'] * 10)
        self.assertEqual(self.ns['_proc_start'](text, 303), 7654321)
        for bad in ('303 (mysqld) S 0', text.replace('303 ', '304 ', 1), text.replace('7654321', 'PRIVATE')):
            with self.assertRaises(ValueError): self.ns['_proc_start'](bad, 303)

    def test_kernel_unix_inode_is_separate_from_filesystem_socket_inode(self):
        value = self.ns['_parse_unix'](UNIX)
        self.assertEqual(value, {'php': 7001, 'mysql': 7002})
        self.assertNotIn('PRIVATE', json.dumps(value))
        for bad in (UNIX + UNIX.splitlines()[2] + '\n', UNIX.replace('00010000', '00000000'),
                UNIX.replace(' 7002 ', ' PRIVATE ')):
            self.assertIsNone(self.ns['_parse_unix'](bad).get('mysql'))

    def test_mount_parser_only_projects_covering_mount_without_private_sources(self):
        text = ('21 1 8:1 / / rw - ext4 /dev/sda1 rw\n'
                '22 21 0:44 /PRIVATE /unrelated rw - nfs PRIVATE:/customer rw\n')
        value = self.ns['_parse_mount'](text, (8, 1))
        self.assertEqual(value, {'state': 'observed', 'filesystem': 'local_block', 'device_matches': True})
        self.assertNotIn('PRIVATE', json.dumps(value))
        value = self.ns['_parse_mount'](text + '23 21 0:44 / /var/lib/mysql rw - nfs PRIVATE:/customer rw\n', (0, 44))
        self.assertEqual(value['filesystem'], 'unsupported')
        self.assertEqual(self.ns['_parse_mount'](text, (8, 2))['state'], 'unknown')

    def fixture(self):
        ns = self.ns
        calls = []
        units = ns['_parse_units'](UNITS)
        ns['_unit_snapshot'] = lambda deadline: copy.deepcopy(units)
        ns['_proc_snapshot'] = lambda role,pid,deadline: dict(state='observed', start=pid * 100,
            exe_matches=True, namespace_matches=True, sockets={7001} if role == 'php' else {7002} if role == 'mysql' else set())
        ns['_proc_still_same'] = lambda role,pid,start,deadline: True
        ns['_unix_snapshot'] = lambda deadline: ns['_parse_unix'](UNIX)
        ns['_socket_metadata'] = lambda role,deadline: dict(state='observed', is_socket=True, identity=('fs-inode',11 if role=='php' else 22))
        ns['_datadir_metadata'] = lambda deadline: dict(state='observed', is_directory=True, device=(8,1), identity=('dir-inode',33))
        ns['_mount_snapshot'] = lambda device,deadline: dict(state='observed', filesystem='local_block', device_matches=True, _identity='synthetic-mount-snapshot')
        ns['os_geteuid'] = lambda: 0
        return ns, units, calls

    def test_observed_kernel_relationships_never_claim_api_db_or_disk_identity(self):
        ns, _, _ = self.fixture()
        result = ns['_observe'](NONCE)
        self.assertEqual(result['observation_state'], 'OBSERVED')
        self.assertTrue(result['sockets'][0]['owned_by_service_mainpid'])
        self.assertTrue(result['sockets'][1]['owned_by_service_mainpid'])
        self.assertEqual(result['sql'], 'NOT_ATTEMPTED')
        self.assertEqual(result['effective_api_binding'], 'NOT_ESTABLISHED')
        self.assertEqual(result['test_disk_identity'], 'NOT_ESTABLISHED')
        self.assertEqual(result['db_proof'], 'BLOCKED_TARGET_ADMISSION')
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('start', json.dumps(result))

    def test_inactive_zero_pid_custom_exe_or_namespace_never_produces_socket_binding(self):
        for change in ('inactive', 'zero', 'custom', 'namespace', 'fd_limit', 'denied'):
            with self.subTest(change=change):
                ns, units, _ = self.fixture()
                if change == 'inactive': units['mysql']['active'] = 'inactive'
                elif change == 'zero': units['mysql']['pid'] = 0
                else:
                    previous = ns['_proc_snapshot']
                    def snapshot(role,pid,deadline):
                        row = previous(role,pid,deadline)
                        if role == 'mysql':
                            row['state'] = 'unknown'
                            if change == 'custom': row['exe_matches'] = False
                            if change == 'namespace': row['namespace_matches'] = False
                        return row
                    ns['_proc_snapshot'] = snapshot
                result = ns['_observe'](NONCE)
                self.assertEqual(result['observation_state'], 'PARTIAL')
                self.assertIsNone(result['sockets'][1]['owned_by_service_mainpid'])
                self.assertEqual(result['sql'], 'NOT_ATTEMPTED')

    def test_changed_mainpid_or_starttime_invalidates_relationship_instead_of_reusing_pid(self):
        for changed in ('unit', 'start'):
            ns, units, _ = self.fixture()
            if changed == 'unit':
                count = [0]
                def snapshot(deadline):
                    count[0] += 1; value = copy.deepcopy(units)
                    if count[0] > 1: value['mysql']['pid'] = 999
                    return value
                ns['_unit_snapshot'] = snapshot
            else: ns['_proc_still_same'] = lambda role,pid,start,deadline: role != 'mysql'
            result = ns['_observe'](NONCE)
            self.assertEqual(result['observation_state'], 'PARTIAL')
            self.assertIsNone(result['sockets'][1]['owned_by_service_mainpid'])

    def test_nonroot_or_failed_metadata_stays_unknown_without_sql(self):
        ns, _, _ = self.fixture(); ns['os_geteuid'] = lambda: 1001
        result = ns['_observe'](NONCE)
        self.assertEqual(result['observation_state'], 'PARTIAL')
        self.assertEqual(result['sql'], 'NOT_ATTEMPTED')
        self.assertTrue(all(row['state'] == 'unknown' for row in result['processes']))

    def test_namespace_fd_or_kernel_listener_change_invalidates_relationship(self):
        for change in ('namespace','fd','kernel','filesystem'):
            with self.subTest(change=change):
                ns, _, _ = self.fixture();counts={'mysql':0,'unix':0,'fs':0}
                if change in ('namespace','fd'):
                    previous=ns['_proc_snapshot']
                    def process(role,pid,deadline):
                        result=previous(role,pid,deadline)
                        if role=='mysql':
                            counts['mysql']+=1
                            if counts['mysql']>1:
                                if change=='namespace':result.update(state='unknown',namespace_matches=False)
                                else:result['sockets']=set()
                        return result
                    ns['_proc_snapshot']=process
                elif change=='kernel':
                    def unix(deadline):
                        counts['unix']+=1
                        return dict(php=7001,mysql=7002 if counts['unix']==1 else 7999)
                    ns['_unix_snapshot']=unix
                else:
                    previous=ns['_socket_metadata']
                    def filesystem(role,deadline):
                        result=previous(role,deadline)
                        if role=='mysql':
                            counts['fs']+=1
                            if counts['fs']>1:result['identity']=('changed',999)
                        return result
                    ns['_socket_metadata']=filesystem
                result=ns['_observe'](NONCE)
                self.assertEqual(result['observation_state'],'PARTIAL')
                self.assertIsNone(result['sockets'][1]['owned_by_service_mainpid'])

    def test_actual_fd_helper_rejects_invalid_pid_before_path_access(self):
        for pid in (True,0,-1,'303/../PRIVATE',2147483648):
            with patch.dict(self.ns,{'_parents':lambda *args: self.fail('Invalid PID reached path reader')}):
                with self.assertRaises(ValueError):self.ns['_fd_sockets'](pid,time.monotonic()+1)

    def test_actual_fd_reader_caps_names_targets_count_and_denied_links(self):
        class Entries:
            def __init__(inner,names):inner.names=names
            def __enter__(inner):return iter(SimpleNamespace(name=n) for n in inner.names)
            def __exit__(inner,*args):pass
        for names,link,error in ((['1','2'],'socket:[7002]',None),
                ([str(i) for i in range(129)],'socket:[7002]',ValueError),
                (['1','PRIVATE'],'socket:[7002]',ValueError),
                (['1'],'X'*4097,ValueError),(['1'],None,PermissionError)):
            def readlink(*args,**kwargs):
                if link is None:raise PermissionError('PRIVATE')
                return link
            with self.subTest(count=len(names),error=error), \
                    patch.dict(self.ns,{'_parents':lambda *a:([41],'fd')}), \
                    patch.object(self.ns['os'],'open',return_value=42), \
                    patch.object(self.ns['os'],'close'), \
                    patch.object(self.ns['os'],'scandir',return_value=Entries(names)), \
                    patch.object(self.ns['os'],'readlink',side_effect=readlink):
                if error:
                    with self.assertRaises(error):self.ns['_fd_sockets'](303,time.monotonic()+1)
                else:self.assertEqual(self.ns['_fd_sockets'](303,time.monotonic()+1),{7002})

    def test_actual_bounded_read_accepts_proc_size_zero_rejects_oversize_and_symlink(self):
        with tempfile.TemporaryDirectory(prefix='jsm-2760-offline-',dir='/private/tmp') as folder:
            root=Path(folder);source=root/'source';source.write_bytes(b'proc-stat-fixture')
            actual_fstat=os.fstat
            def zero_size(fd):
                value=actual_fstat(fd)
                names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_ctime_ns')
                return SimpleNamespace(**{name:getattr(value,name) for name in names},st_size=0)
            with patch.object(self.ns['os'],'fstat',side_effect=zero_size):
                self.assertEqual(self.ns['_proc_read'](str(source),time.monotonic()+1),'proc-stat-fixture')
            source.write_bytes(b'X'*4097)
            with self.assertRaises(ValueError):self.ns['_proc_read'](str(source),time.monotonic()+1,4096)
            leaf=root/'leaf';leaf.symlink_to(source)
            with self.assertRaises(OSError):self.ns['_proc_read'](str(leaf),time.monotonic()+1)
            directory=root/'real';directory.mkdir();(directory/'file').write_text('PRIVATE')
            parent=root/'parent';parent.symlink_to(directory,target_is_directory=True)
            with self.assertRaises(OSError):self.ns['_proc_read'](str(parent/'file'),time.monotonic()+1)

    def test_actual_metadata_directory_symlink_is_unknown_without_listing_or_contents(self):
        with tempfile.TemporaryDirectory(prefix='jsm-2760-offline-',dir='/private/tmp') as folder:
            root=Path(folder);target=root/'data';target.mkdir();(target/'PRIVATE').write_text('PRIVATE')
            alias=root/'link';alias.symlink_to(target,target_is_directory=True)
            with patch.object(self.ns['os'],'scandir',side_effect=AssertionError('No directory listing')):
                observed=self.ns['_object_metadata'](str(target),time.monotonic()+1,'directory')
                refused=self.ns['_object_metadata'](str(alias),time.monotonic()+1,'directory')
            self.assertEqual(observed['state'],'observed');self.assertEqual(refused['state'],'unknown')
            self.assertNotIn('PRIVATE',json.dumps(observed))


if __name__ == '__main__': unittest.main()
