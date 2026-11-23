"""Actual root coordinator and FastCGI framing, synthetic peers only."""
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import test_db_runtime_producer as producer
from test_db_runtime_protocol import Rejected
from test_db_runtime_fastcgi import FastCGI, record, SCRIPT


class Wire:
    def __init__(self,fail=None):self.sent=[];self.fail=fail
    def send(self,role,seq,value):self.sent.append((seq,value))
    def receive(self,role,seq):
        if self.fail==seq:raise Rejected('FRAME_REFUSED')
        return {1:dict(stage='TARGET',host='127.0.0.1',port=3306,schema='stand',same_db=True),
                3:dict(stage='CONNECTED',native_pdo=True),
                5:dict(stage='RESULT',schema_matches=True,principal_kind='OTHER',version_family='MYSQL_5_7',server_read_only=False,query_count=1)}[seq]

class Kernel:
    def __init__(self,fail=None):self.fail=fail;self.calls=0
    def before(self,p):
        if self.fail=='before':raise Rejected('LOCAL_LISTENER_REFUSED')
        return p
    def peer(self,worker,witness):
        self.calls+=1
        if self.fail==self.calls:raise Rejected('DB_PEER_REFUSED')
        return 'a'*64 if self.fail!='drift' or self.calls==1 else 'b'*64

class ProducerTests(unittest.TestCase):
    def test_actual_dialogue_select_only_after_local_and_actual_peer_proof(self):
        for failure,expected in [(None,True),('before',False),(1,False),(2,True),('drift',True)]:
            wire=Wire();kernel=Kernel(failure);receipt=producer.closed()
            if failure is None:producer.dialogue(wire,kernel,40,1000,receipt)
            else:
                with self.assertRaises(Rejected):producer.dialogue(wire,kernel,40,1000,receipt)
            self.assertEqual(any(v.get('stage')=='SELECT' for _,v in wire.sent),expected)
            if failure is None:
                self.assertEqual(receipt['sql'],'ONE_METADATA_SELECT_OBSERVED')
                self.assertEqual(receipt['grants'],'UNKNOWN')
            else:self.assertIsNone(receipt['metadata'])

    def test_bad_nonce_startup_or_connect_never_authorize_query(self):
        for seq in (1,3):
            wire=Wire(seq)
            with self.assertRaises(Rejected):producer.dialogue(wire,Kernel(),40,1000,producer.closed())
            self.assertFalse(any(v.get('stage')=='SELECT' for _,v in wire.sent))
        wire=Wire();wire.receive=lambda role,seq:dict(stage='REFUSED',reason='CONFIG_SHAPE_REFUSED')
        with self.assertRaisesRegex(Rejected,'CONFIG_SHAPE_REFUSED'):producer.dialogue(wire,Kernel(),40,1000,producer.closed())
        self.assertEqual(len(wire.sent),1)

    def test_failure_is_closed_and_no_runtime_on_bad_context(self):
        with patch.object(producer,'Kernel',side_effect=AssertionError('must not read')):
            result=producer.collect({})
        self.assertEqual(result['reason'],'CONTEXT_REQUIRED');self.assertEqual(result['sql'],'NOT_ATTEMPTED')
        for error in (ValueError('PRIVATE'),Rejected('PRIVATE'),Rejected('DEADLINE','PRIVATE')):
            self.assertEqual(producer.reason(error),'INTERNAL_REFUSED')
        self.assertNotIn('PRIVATE',str(result))

    def test_worker_publisher_root_unknown_or_changed_rejected_before_hello(self):
        identity=(1,10,('net:[1]','mnt:[2]','pid:[1]'),(1,1))
        snapshot=({},None,None,((40,identity,(33,33,33,33)),),(1000,1000))
        kernel=type('K',(),{'ns':{'_php_endpoint_identity':lambda p,d:identity,
            '_manifest_worker_uid':lambda p,o,d:(33,33,33,33)}})()
        self.assertEqual(producer.worker_from_peer(snapshot,(40,33,33),kernel,1),40)
        for credentials in ((40,0,0),(40,1000,1000),(41,33,33),(40,34,34)):
            with self.assertRaises(Rejected):producer.worker_from_peer(snapshot,credentials,kernel,1)

    def test_actual_fastcgi_request_fixed_script_no_body_and_bounded_drain(self):
        root,php=socket.socketpair();observed=[]
        def peer():
            with php:
                data=php.recv(8192);observed.append(data)
                php.sendall(record(6,b'Content-type: text/html\r\n\r\n')+record(3,b'\0'*8))
        thread=threading.Thread(target=peer);thread.start()
        request=FastCGI('a'*32,'b'*64,'c'*32,time.monotonic()+3,stream=root)
        try:request.finish()
        finally:request.close();thread.join()
        self.assertIn(SCRIPT.encode(),observed[0]);self.assertNotIn(b'PHP_VALUE',observed[0])
        self.assertTrue(observed[0].endswith(record(5)))

    def test_fastcgi_stderr_oversize_and_peer_check_fail_closed(self):
        for packet in (record(7,b'PRIVATE'),record(6,b'x'*16385),record(3,b'\0'*7+b'\1')):
            root,php=socket.socketpair()
            def peer():
                with php:
                    php.recv(8192)
                    try:php.sendall(packet)
                    except OSError:pass
            thread=threading.Thread(target=peer);thread.start()
            request=FastCGI('a'*32,'b'*64,'c'*32,time.monotonic()+3,stream=root)
            try:
                with self.assertRaisesRegex(Rejected,'^FASTCGI_REFUSED$'):request.finish()
                self.assertNotIn('PRIVATE',str(request.error))
            finally:request.close();thread.join()
        root,php=socket.socketpair()
        with php:
            with self.assertRaises(Rejected):FastCGI('a'*32,'b'*64,'c'*32,time.monotonic()+3,stream=root,peer_check=lambda s:(_ for _ in ()).throw(Rejected('FPM_REFUSED')))
            self.assertEqual(php.recv(1),b'')

if __name__=='__main__':unittest.main()
