"""Synthetic proc/systemd fixtures for #2760; no SSH, SQL or real /proc reads."""
import copy
import errno
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
FIXTURE_TMP = str(Path(tempfile.gettempdir()).resolve())
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

    def test_fixed_additional_units_are_metadata_only_and_cannot_replace_mysql_role(self):
        self.assertTrue('_parse_additional_units' in self.ns, 'missing approved fixed unit metadata')
        text = ('Id=mariadb.service\nLoadState=loaded\nActiveState=active\nMainPID=404\n\n'
                'Id=docker.service\nLoadState=not-found\nActiveState=inactive\nMainPID=0\n')
        self.assertEqual(self.ns['_parse_additional_units'](text), {
            'mariadb': dict(load='loaded', active='active', pid=404),
            'docker': dict(load='not-found', active='inactive', pid=0)})
        for bad in (text.replace('404', '404;PRIVATE'), text.replace('mariadb.service', 'mysql.service'),
                    text + '\nId=PRIVATE.service\n', text.replace('MainPID=404', 'MainPID=404\nMainPID=404')):
            with self.assertRaises(ValueError): self.ns['_parse_additional_units'](bad)
        self.assertEqual(self.ns['ROLES'], ('apache', 'php', 'mysql'))

    def test_namespace_properties_are_closed_apache_php_only_and_unknown_is_not_admission(self):
        self.assertTrue('_parse_privacy' in self.ns, 'missing approved private-namespace properties')
        text = ('Id=apache2.service\nPrivateTmp=yes\nPrivateMounts=no\nPrivateNetwork=yes\n\n'
                'Id=php7.4-fpm.service\nPrivateTmp=disconnected\nPrivateMounts=yes\nPrivateNetwork=no\n')
        value = self.ns['_parse_privacy'](text)
        self.assertEqual(value['apache'], dict(private_tmp=True, private_mounts=False, private_network=True))
        self.assertEqual(value['php'], dict(private_tmp=None, private_mounts=True, private_network=False))
        self.assertNotIn('disconnected', json.dumps(value))
        for bad in (text.replace('apache2.service', 'mariadb.service'), text + '\nEnvironment=PRIVATE\n',
                    text.replace('PrivateTmp=yes', 'PrivateTmp=yes\nPrivateTmp=no')):
            with self.assertRaises(ValueError): self.ns['_parse_privacy'](bad)

    def test_existing_path_failures_have_closed_errno_without_private_message(self):
        self.assertTrue('_error_code' in self.ns, 'missing closed errno projection')
        for error, expected in ((FileNotFoundError('PRIVATE'), 'NOT_FOUND'),
                                (PermissionError('PRIVATE'), 'PERMISSION_REFUSED'),
                                (OSError(errno.ELOOP, 'PRIVATE'), 'UNSAFE_LINK_OR_KIND'),
                                (OSError(errno.ENOTDIR, 'PRIVATE'), 'UNSAFE_LINK_OR_KIND'),
                                (OSError(errno.EIO, 'PRIVATE'), 'OS_REFUSED'),
                                (UnicodeError('PRIVATE'), 'PARSER_REFUSED')):
            with self.subTest(expected=expected):
                self.assertEqual(self.ns['_error_code'](error), expected)
        with tempfile.TemporaryDirectory(prefix='jsm-2760-reasons-', dir=FIXTURE_TMP) as folder:
            root = Path(folder); leaf = root/'missing'
            missing = self.ns['_object_metadata'](str(leaf), time.monotonic()+1, 'directory')
            self.assertEqual(missing['error'], 'NOT_FOUND')
            target = root/'target'; target.mkdir(); leaf.symlink_to(target)
            unsafe = self.ns['_object_metadata'](str(leaf), time.monotonic()+1, 'directory')
            self.assertEqual(unsafe['error'], 'UNSAFE_LINK_OR_KIND')
            self.assertNotIn(folder, json.dumps([missing, unsafe]))

    def test_systemctl_extension_rejects_unapproved_properties_and_units_before_execution(self):
        self.assertTrue('_systemctl_snapshot' in self.ns, 'missing fixed query reuse')
        for props, units in ((('Id','Environment'), ('apache2.service',)),
                             (('Id','LoadState','ActiveState','MainPID'), ('PRIVATE.service',)),
                             (('Id','PrivateTmp','PrivateMounts','PrivateNetwork'), ('mariadb.service','docker.service'))):
            with patch.dict(self.ns, {'_parents': lambda *a: self.fail('unapproved command reached path access')}):
                with self.assertRaises(ValueError): self.ns['_systemctl_snapshot'](props, units, time.monotonic()+1)

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
            exe_matches=True, namespace_matches=True, net_namespace_matches=True, mount_namespace_matches=True,
            sockets={7001} if role == 'php' else {7002} if role == 'mysql' else set())
        ns['_proc_still_same'] = lambda role,pid,start,deadline: True
        ns['_unix_snapshot'] = lambda deadline: ns['_parse_unix'](UNIX)
        ns['_socket_metadata'] = lambda role,deadline: dict(state='observed', is_socket=True, identity=('fs-inode',11 if role=='php' else 22))
        ns['_datadir_metadata'] = lambda deadline: dict(state='observed', is_directory=True, device=(8,1), identity=('dir-inode',33))
        ns['_mount_snapshot'] = lambda device,deadline: dict(state='observed', filesystem='local_block', device_matches=True, _identity='synthetic-mount-snapshot')
        ns['os_geteuid'] = lambda: 0
        return ns, units, calls

    def detail_fixture(self):
        ns, units, calls = self.fixture()
        additional = dict(mariadb=dict(load='loaded',active='active',pid=404),
                          docker=dict(load='not-found',active='inactive',pid=0))
        privacy = {r:dict(private_tmp=True,private_mounts=False,private_network=False) for r in ('apache','php')}
        ns['_additional_unit_snapshot'] = lambda deadline: copy.deepcopy(additional)
        ns['_privacy_snapshot'] = lambda deadline: copy.deepcopy(privacy)
        ns['_unix_snapshot_detailed'] = ns['_unix_snapshot']
        return ns, additional, privacy

    def test_v3_actual_observer_has_only_fixed_additional_facts_and_still_no_db_admission(self):
        ns, _, _ = self.detail_fixture()
        result = ns['_observe'](NONCE, details=True)
        self.assertEqual(result['version'], 'jsm-test-db-os-2760-v3')
        self.assertEqual(result['additional_services'], [
            dict(id='mariadb',load_state='loaded',active_state='active',pid_available=True,stable=True),
            dict(id='docker',load_state='not-found',active_state='inactive',pid_available=False,stable=True)])
        self.assertEqual(result['namespace_settings'][0], dict(id='apache',private_tmp=True,
            private_mounts=False,private_network=False,stable=True))
        self.assertEqual(result['observation_state'], 'OBSERVED')
        self.assertEqual(result['sql'], 'NOT_ATTEMPTED')
        self.assertEqual(result['db_proof'], 'BLOCKED_TARGET_ADMISSION')
        self.assertEqual(len(result['stages']), 22)
        self.assertNotIn('404', json.dumps(result))
        self.assertIsNotNone(self.projection(result))
        self.assertLessEqual(len(json.dumps(result).encode('ascii')), 12288)

    def test_v3_private_tmp_does_not_admit_existing_namespace_mismatch(self):
        ns, _, _ = self.detail_fixture(); previous = ns['_proc_snapshot']
        def process(role,pid,deadline):
            value = previous(role,pid,deadline)
            if role in ('apache','php'): value.update(state='unknown',namespace_matches=False,mount_namespace_matches=False)
            return value
        ns['_proc_snapshot'] = process
        result = ns['_observe'](NONCE, details=True)
        self.assertEqual(result['observation_state'], 'PARTIAL')
        self.assertTrue(result['namespace_settings'][0]['private_tmp'])
        self.assertIsNone(result['sockets'][0]['owned_by_service_mainpid'])
        self.assertIsNotNone(self.projection(result))

    def test_v3_unknown_changed_and_refused_service_settings_are_partial_and_closed(self):
        for case in ('unknown', 'unit_change', 'privacy_change', 'unit_refused'):
            with self.subTest(case=case):
                ns, additional, privacy = self.detail_fixture(); count = [0]
                if case == 'unknown': privacy['apache']['private_tmp'] = None
                if case == 'unit_change':
                    def units(deadline):
                        count[0] += 1; value = copy.deepcopy(additional)
                        if count[0] > 1: value['mariadb']['pid'] = 505
                        return value
                    ns['_additional_unit_snapshot'] = units
                if case == 'privacy_change':
                    def settings(deadline):
                        count[0] += 1; value = copy.deepcopy(privacy)
                        if count[0] > 1: value['apache']['private_mounts'] = True
                        return value
                    ns['_privacy_snapshot'] = settings
                if case == 'unit_refused':
                    def refused(deadline): raise PermissionError('PRIVATE unit failure')
                    ns['_additional_unit_snapshot'] = refused
                result = ns['_observe'](NONCE, details=True)
                self.assertEqual(result['observation_state'], 'PARTIAL')
                self.assertIsNotNone(self.projection(result))
                self.assertNotIn('PRIVATE', json.dumps(result))
                if case == 'unknown':
                    self.assertEqual(next(s for s in result['stages'] if s['id']=='privacy_begin')['error'], 'UNKNOWN_PROPERTY_VALUE')
                    self.assertIsNone(result['namespace_settings'][0]['stable'])
                if case == 'unit_refused':
                    self.assertEqual(next(s for s in result['stages'] if s['id']=='additional_units_begin')['error'], 'PERMISSION_REFUSED')

    def test_v3_fixed_path_errno_size_change_parser_are_not_generic_or_raw(self):
        for error, expected in ((FileNotFoundError('PRIVATE'), 'NOT_FOUND'),
                (PermissionError('PRIVATE'), 'PERMISSION_REFUSED'),
                (OSError(errno.ELOOP,'PRIVATE'), 'UNSAFE_LINK_OR_KIND')):
            ns, _, _ = self.detail_fixture()
            def failed(deadline): raise error
            ns['_unix_snapshot_detailed'] = failed
            result = ns['_observe'](NONCE, details=True)
            self.assertEqual(next(s for s in result['stages'] if s['id']=='unix_begin')['error'], expected)
            self.assertIsNotNone(self.projection(result))
            self.assertNotIn('PRIVATE', json.dumps(result))
        with tempfile.TemporaryDirectory(prefix='jsm-2760-reasons-',dir=FIXTURE_TMP) as folder:
            source = Path(folder)/'source'; source.write_bytes(b'x'*4097)
            with self.assertRaises(ValueError) as caught: self.ns['_proc_read'](str(source),time.monotonic()+1,4096)
            self.assertEqual(self.ns['_error_code'](caught.exception),'SIZE_LIMIT')
        for value in ('PRIVATE', UNIX + UNIX.splitlines()[2]+'\n', UNIX.replace('00010000','00000000')):
            with self.assertRaises(ValueError) as caught: self.ns['_parse_unix'](value,details=True)
            self.assertEqual(self.ns['_error_code'](caught.exception),'PARSER_REFUSED')

    def test_v3_each_stage_failure_is_closed_and_never_becomes_a_success(self):
        for target in self.m.DETAIL_STAGE_IDS:
            with self.subTest(target=target):
                ns, _, _ = self.detail_fixture(); counts = {}
                for helper, kind in (('_unit_snapshot','units'),('_unix_snapshot_detailed','unix'),
                        ('_proc_snapshot','process'),('_socket_metadata','socket'),
                        ('_datadir_metadata','datadir'),('_mount_snapshot','mount'),
                        ('_additional_unit_snapshot','additional_units'),('_privacy_snapshot','privacy')):
                    original=ns[helper]
                    def read(*args,_original=original,_kind=kind):
                        role=args[0] if _kind in ('process','socket') else None
                        prefix=(role+'_'+_kind) if role is not None else _kind
                        counts[prefix]=counts.get(prefix,0)+1
                        name=prefix+('_begin' if counts[prefix]==1 else '_end')
                        if name==target:raise FileNotFoundError('PRIVATE')
                        return _original(*args)
                    ns[helper]=read
                result=ns['_observe'](NONCE,details=True)
                stage=next(row for row in result['stages'] if row['id']==target)
                self.assertTrue(stage['attempted']);self.assertFalse(stage['completed'])
                self.assertEqual(stage['error'],'NOT_FOUND')
                self.assertEqual(result['observation_state'],'PARTIAL')
                self.assertIsNotNone(self.projection(result))
                self.assertNotIn('PRIVATE',json.dumps(result))

    def test_v3_strict_projection_refuses_raw_or_forged_service_properties_and_v2_stays_closed(self):
        ns, _, _ = self.detail_fixture(); good=ns['_observe'](NONCE,details=True)
        for case in ('pid','role','bool','raw_setting','unknown_stable','field','error','count'):
            with self.subTest(case=case):
                value=copy.deepcopy(good)
                if case=='pid':value['additional_services'][0]['MainPID']=404
                if case=='role':value['additional_services'][0]['id']='mysql'
                if case=='bool':value['additional_services'][0]['pid_available']=1
                if case=='raw_setting':value['namespace_settings'][0]['private_tmp']='PRIVATE'
                if case=='unknown_stable':value['namespace_settings'][0]['private_tmp']=None
                if case=='field':value['namespace_settings'][0]['Environment']='PRIVATE'
                if case=='error':value['stages'][0]['error']='PRIVATE'
                if case=='count':value['additional_services'].append(value['additional_services'][0])
                self.assertIsNone(self.projection(value))
        ns, _, _ = self.fixture(); legacy=ns['_observe'](NONCE)
        self.assertIsNotNone(self.projection(legacy))
        legacy['stages'][0].update(completed=False,error='NOT_FOUND')
        legacy['observation_state']='PARTIAL'
        self.assertIsNone(self.projection(legacy),'v3 reasons cannot be smuggled into historical v2')

    def test_v3_systemctl_wrappers_only_use_three_fixed_query_shapes(self):
        seen=[]
        add=('Id=mariadb.service\nLoadState=loaded\nActiveState=active\nMainPID=404\n\n'
             'Id=docker.service\nLoadState=not-found\nActiveState=inactive\nMainPID=0\n')
        privacy=('Id=apache2.service\nPrivateTmp=yes\nPrivateMounts=no\nPrivateNetwork=no\n\n'
                 'Id=php7.4-fpm.service\nPrivateTmp=no\nPrivateMounts=no\nPrivateNetwork=no\n')
        def query(properties,units,deadline):
            seen.append((properties,units))
            return privacy if properties[1]=='PrivateTmp' else add if units[0]=='mariadb.service' else UNITS
        with patch.dict(self.ns,{'_systemctl_snapshot':query}):
            self.ns['_unit_snapshot'](time.monotonic()+1)
            self.ns['_additional_unit_snapshot'](time.monotonic()+1)
            self.ns['_privacy_snapshot'](time.monotonic()+1)
        self.assertEqual(seen,[(('Id','LoadState','ActiveState','MainPID'),('apache2.service','php7.4-fpm.service','mysql.service')),
                              (('Id','LoadState','ActiveState','MainPID'),('mariadb.service','docker.service')),
                              (('Id','PrivateTmp','PrivateMounts','PrivateNetwork'),('apache2.service','php7.4-fpm.service'))])

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
        with tempfile.TemporaryDirectory(prefix='jsm-2760-offline-',dir=FIXTURE_TMP) as folder:
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
        with tempfile.TemporaryDirectory(prefix='jsm-2760-offline-',dir=FIXTURE_TMP) as folder:
            root=Path(folder);target=root/'data';target.mkdir();(target/'PRIVATE').write_text('PRIVATE')
            alias=root/'link';alias.symlink_to(target,target_is_directory=True)
            with patch.object(self.ns['os'],'scandir',side_effect=AssertionError('No directory listing')):
                observed=self.ns['_object_metadata'](str(target),time.monotonic()+1,'directory')
                refused=self.ns['_object_metadata'](str(alias),time.monotonic()+1,'directory')
            self.assertEqual(observed['state'],'observed');self.assertEqual(refused['state'],'unknown')
            self.assertNotIn('PRIVATE',json.dumps(observed))

    def test_unix_refusal_does_not_hide_independent_fixed_socket_and_datadir_metadata(self):
        ns,_,_=self.fixture();calls=[]
        def refused(deadline):raise ValueError('PRIVATE')
        ns['_unix_snapshot']=refused
        original=ns['_datadir_metadata']
        ns['_datadir_metadata']=lambda deadline:(calls.append('datadir') or original(deadline))
        result=ns['_observe'](NONCE);stages={r['id']:r for r in result['stages']}
        self.assertEqual(result['observation_state'],'PARTIAL')
        self.assertEqual(result['datadir']['state'],'observed')
        self.assertEqual(len(calls),2)
        self.assertTrue(result['sockets'][0]['is_socket'])
        self.assertIsNone(result['sockets'][0]['kernel_listener'])
        self.assertIsNone(result['sockets'][0]['owned_by_service_mainpid'])
        self.assertEqual(stages['unix_begin'],dict(id='unix_begin',attempted=True,completed=False,error='PARSE_OR_GUARD_REFUSED'))
        self.assertTrue(stages['datadir_begin']['completed'])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_first_socket_refusal_does_not_hide_other_fixed_metadata(self):
        ns,_,_=self.fixture();original=ns['_socket_metadata']
        def socket(role,deadline):
            if role=='php':raise PermissionError('PRIVATE')
            return original(role,deadline)
        ns['_socket_metadata']=socket
        result=ns['_observe'](NONCE);stages={r['id']:r for r in result['stages']}
        self.assertEqual(stages['php_socket_begin']['error'],'OS_REFUSED')
        self.assertTrue(stages['mysql_socket_begin']['completed'])
        self.assertEqual(result['datadir']['state'],'observed')
        self.assertEqual(result['observation_state'],'PARTIAL')

    def test_deadline_marks_skipped_stages_without_more_operations(self):
        ns,_,_=self.fixture();clock=[0.0]
        def unix(deadline):clock[0]=4.0;raise ValueError('PRIVATE')
        ns['_unix_snapshot']=unix
        ns['_socket_metadata']=lambda *a:self.fail('Socket after deadline')
        ns['_datadir_metadata']=lambda *a:self.fail('Datadir after deadline')
        with patch.object(ns['time'],'monotonic',side_effect=lambda:clock[0]):
            result=ns['_observe'](NONCE)
        stages={r['id']:r for r in result['stages']}
        self.assertTrue(stages['unix_begin']['attempted'])
        self.assertEqual(stages['unix_begin']['error'],'DEADLINE')
        self.assertFalse(stages['datadir_begin']['attempted'])
        self.assertEqual(stages['datadir_begin']['error'],'DEADLINE')
        self.assertEqual(result['sql'],'NOT_ATTEMPTED')

    def test_already_validated_unit_states_disambiguate_mysql_process_not_attempted(self):
        ns,units,_=self.fixture();units['mysql'].update(active='inactive',pid=0)
        result=ns['_observe'](NONCE);mysql=result['processes'][2]
        self.assertEqual((mysql['load_state'],mysql['active_state'],mysql['pid_available']),('loaded','inactive',False))
        stages={r['id']:r for r in result['stages']}
        self.assertEqual(stages['mysql_process_begin'],dict(id='mysql_process_begin',attempted=False,completed=False,error='UNIT_UNAVAILABLE'))
        self.assertEqual(result['db_proof'],'BLOCKED_TARGET_ADMISSION')

    def test_separate_namespace_axes_do_not_admit_mount_mismatch_or_read_fds(self):
        ns=self.ns;pid=303
        text='303 (mysqld) S '+' '.join(['0']*18+['7654321']+['0']*10)
        own='/proc/'+str(os.getpid())
        def link(path,deadline):
            if path.endswith('/exe'):return '/usr/sbin/mysqld'
            if path.endswith('/net'):return 'net:[1]'
            if path.endswith('/mnt'):return 'mnt:[1]' if path.startswith(own+'/') else 'mnt:[2]'
            self.fail('Unexpected path')
        ns['_proc_read']=lambda *a:text;ns['_readlink']=link
        ns['_fd_sockets']=lambda *a:self.fail('FD read after namespace refusal')
        result=ns['_proc_snapshot']('mysql',pid,time.monotonic()+1)
        self.assertIs(result['net_namespace_matches'],True)
        self.assertIs(result['mount_namespace_matches'],False)
        self.assertIs(result['namespace_matches'],False)
        self.assertEqual(result['state'],'unknown')

    def projection(self,child):
        spec=importlib.util.spec_from_file_location('stages_projection',ROOT/'scripts/test_db_metadata_readonly.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module._child_projection(child,NONCE)

    def test_each_existing_stage_refusal_is_closed_and_cannot_promote_complete(self):
        for target in self.m.STAGE_IDS:
            with self.subTest(target=target):
                ns,_,_=self.fixture();counts={}
                for helper,kind in (('_unit_snapshot','units'),('_unix_snapshot','unix'),
                        ('_proc_snapshot','process'),('_socket_metadata','socket'),
                        ('_datadir_metadata','datadir'),('_mount_snapshot','mount')):
                    original=ns[helper]
                    def read(*args,_original=original,_kind=kind):
                        role=args[0] if _kind in ('process','socket') else None
                        prefix=(role+'_'+_kind) if role is not None else _kind
                        counts[prefix]=counts.get(prefix,0)+1
                        name=prefix+('_begin' if counts[prefix]==1 else '_end')
                        if name==target:raise PermissionError('PRIVATE')
                        return _original(*args)
                    ns[helper]=read
                result=ns['_observe'](NONCE);stages={r['id']:r for r in result['stages']}
                self.assertTrue(stages[target]['attempted'])
                self.assertFalse(stages[target]['completed'])
                self.assertEqual(stages[target]['error'],'OS_REFUSED')
                self.assertEqual(result['observation_state'],'PARTIAL')
                self.assertIsNotNone(self.projection(result))
                self.assertNotIn('PRIVATE',json.dumps(result))
                self.assertLessEqual(len(json.dumps(result).encode('ascii')),12288)

    def test_actual_observer_full_and_namespace_partial_packets_fit_strict_v2_projection(self):
        for mismatch in (False,True):
            ns,_,_=self.fixture()
            if mismatch:
                original=ns['_proc_snapshot']
                def process(role,pid,deadline):
                    row=original(role,pid,deadline)
                    if role in ('apache','php'):
                        row.update(state='unknown',namespace_matches=False,mount_namespace_matches=False)
                    return row
                ns['_proc_snapshot']=process
            result=ns['_observe'](NONCE)
            self.assertIsNotNone(self.projection(result))
            self.assertEqual(result['observation_state'],'PARTIAL' if mismatch else 'OBSERVED')
            self.assertEqual(result['sql'],'NOT_ATTEMPTED')
            self.assertLessEqual(len(json.dumps(result).encode('ascii')),12288)


if __name__ == '__main__': unittest.main()
