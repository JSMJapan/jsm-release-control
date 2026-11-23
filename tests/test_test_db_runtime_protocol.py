"""Synthetic local socket/PHP fixtures; never contact FPM, MySQL or TEST."""
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from test_db_runtime_protocol import Wire, Rejected, canonical, encode, decode, context_digest
from test_db_installer_receipt import _SCOPE


class RuntimeProtocolTests(unittest.TestCase):
    nonce = 'a' * 32
    digest = 'b' * 64

    def test_actual_socketpair_nonce_dialogue(self):
        root, php = socket.socketpair()
        with root, php:
            before = time.monotonic() + 3
            sender, receiver = Wire(root, self.nonce, self.digest, before), Wire(php, self.nonce, self.digest, before)
            sender.send('ROOT', 0, {'stage': 'HELLO', 'publisher_uid': 1000})
            self.assertEqual(receiver.receive('ROOT', 0), {'stage': 'HELLO', 'publisher_uid': 1000})
            receiver.send('PHP', 1, {'stage':'TARGET','same_db':True,'host':'127.0.0.1','port':3306,'schema':'stand'})
            self.assertEqual(sender.receive('PHP', 1), {'stage':'TARGET','same_db':True,'host':'127.0.0.1','port':3306,'schema':'stand'})

    def test_wrong_nonce_context_stage_and_replay_are_refused(self):
        raw = encode(self.nonce, self.digest, 'ROOT', 2, {'stage': 'OPEN'})
        for nonce, digest, role, sequence in [('c'*32,self.digest,'ROOT',2),
                (self.nonce,'c'*64,'ROOT',2),(self.nonce,self.digest,'PHP',2),
                (self.nonce,self.digest,'ROOT',4)]:
            with self.assertRaisesRegex(Rejected, '^FRAME_REFUSED$'):
                decode(raw,nonce,digest,role,sequence)

    def test_duplicate_extra_noncanonical_and_oversized_closed(self):
        raw = encode(self.nonce,self.digest,'PHP',1,{'stage':'TARGET','same_db':True,'host':'127.0.0.1','port':3306,'schema':'stand'})
        values = [raw.replace(b'{',b'{"context":"PRIVATE",',1),raw+b'PRIVATE',
                  raw.replace(b'"sequence":1',b'"sequence":true'),b'x'*4097,
                  raw.replace(b'"stage":"TARGET"',b'"stage":NaN')]
        for value in values:
            with self.assertRaisesRegex(Rejected,'^FRAME_REFUSED$'):
                decode(value,self.nonce,self.digest,'PHP',1)

    def test_expired_deadline_before_send(self):
        a,b=socket.socketpair()
        with a,b:
            w=Wire(a,self.nonce,self.digest,time.monotonic()-1)
            with self.assertRaisesRegex(Rejected,'^DEADLINE$'):w.send('ROOT',0,{'stage':'HELLO','publisher_uid':1000})

    def test_context_is_supplied_not_fabricated_by_control_run(self):
        context={'scope':dict(_SCOPE),'run':dict(workflow_sha='a'*40,requested_site_sha='b'*40,
            id='123',attempt=1,actor='JSMJapan',triggering_actor='JSMJapan'),'control_sha':'c'*40}
        self.assertEqual(len(context_digest(context)),64)
        context['scope']['repository']='JSMJapan/jsm-release-control'
        with self.assertRaisesRegex(Rejected,'^CONTEXT_REQUIRED$'):context_digest(context)

    def test_real_php_codec_and_syntax(self):
        php=shutil.which('php')
        if not php:
            if sys.platform.startswith('linux'):self.fail('CI PHP runtime is required for this profile')
            self.skipTest('PHP is unavailable on this local platform; Linux CI must execute it')
        probe=ROOT/'scripts/test_db_runtime_probe.php'
        self.assertEqual(subprocess.run([php,'-l',str(probe)],capture_output=True).returncode,0)
        payload={'stage':'TARGET','same_db':True,'host':'127.0.0.1','port':3306,'schema':'stand'}
        raw=encode(self.nonce,self.digest,'PHP',1,payload)
        code='require $argv[1]; echo \\JsmTestDbRuntime2760\\frame($argv[2],$argv[3],"PHP",1,["stage"=>"TARGET","same_db"=>true,"host"=>"127.0.0.1","port"=>3306,"schema"=>"stand"]);'
        result=subprocess.run([php,'-r',code,str(probe),self.nonce,self.digest],capture_output=True)
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout,raw)


if __name__ == '__main__':unittest.main()
