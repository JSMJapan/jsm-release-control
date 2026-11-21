"""Synthetic socket-activation evidence, never real services or the daemon."""
import importlib.util
import json
from pathlib import Path
import unittest

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

    def test_unit_and_proc_payload_bounds_refuse_without_returning_raw_text(self):
        for function,value in [('_binding_units','PRIVATE'*1000),('_binding_listener',UNIX+'PRIVATE'*10000)]:
            with self.assertRaises(ValueError) as caught:self.ns[function](value)
            self.assertNotIn('PRIVATE',str(caught.exception))


if __name__=='__main__':unittest.main()
