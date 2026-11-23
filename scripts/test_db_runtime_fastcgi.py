"""One fixed local FPM request with bounded private response draining."""
import re
import socket
import struct
import threading
import time
from test_db_runtime_protocol import Rejected, IO_SECONDS, VERSION

SOCKET = '/run/php/php7.4-fpm.sock'
ENTRY_NAME = 'test_db_runtime_entry.php'
MAX_RESPONSE = 16384


def record(kind, body=b''):
    if len(body)>65535:raise Rejected('FASTCGI_REFUSED')
    return struct.pack('!BBHHBB',1,kind,1,len(body),0,0)+body


def params(values):
    result=b''
    for key,value in values.items():
        key,value=key.encode('ascii'),value.encode('ascii')
        if len(key)>127 or len(value)>127:raise Rejected('FASTCGI_REFUSED')
        result+=bytes((len(key),len(value)))+key+value
    return result


def request_params(nonce,digest,channel,staging):
    path=staging.get('path') if type(staging) is dict else None
    if type(path) is not str or re.fullmatch('/run/jsm-db-2760-[0-9a-f]{32}',path) is None:raise Rejected('STAGING_VIEW_REFUSED')
    script=path+'/'+ENTRY_NAME
    return {'SCRIPT_FILENAME':script,'SCRIPT_NAME':'/test_db_runtime_entry.php','PHP_SELF':'/test_db_runtime_entry.php',
                    'DOCUMENT_ROOT':path,'REQUEST_URI':'/test_db_runtime_entry.php','REQUEST_METHOD':'POST','CONTENT_LENGTH':'0','QUERY_STRING':'',
                    'SERVER_NAME':'develop.jsmjapan.com','SERVER_PROTOCOL':'HTTP/1.1','GATEWAY_INTERFACE':'CGI/1.1',
                    'JSM_DB_PROBE':VERSION,'JSM_DB_NONCE':nonce,'JSM_DB_CONTEXT':digest,'JSM_DB_CHANNEL':channel}



class FastCGI:
    """Only synthetic tests may supply a preconnected stream; no target input."""
    def __init__(self, nonce, digest, channel, deadline, staging, stream=None, peer_check=None, on_send=None):
        self.deadline=deadline
        self.stream=stream or socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.error=None;self.done=False
        try:
            self._timeout()
            if stream is None:self.stream.connect(SOCKET)
            if peer_check is not None:peer_check(self.stream)
            values=request_params(nonce,digest,channel,staging)
            packet=record(1,struct.pack('!HB5x',1,0))+record(4,params(values))+record(4)+record(5)
            if on_send is not None:on_send()
            self.stream.sendall(packet)
            self.thread=threading.Thread(target=self._drain,daemon=True);self.thread.start()
        except Exception:
            self.stream.close();raise Rejected('FASTCGI_REFUSED') from None

    def _timeout(self):
        left=self.deadline-time.monotonic()
        if left<=0:raise Rejected('DEADLINE')
        self.stream.settimeout(min(IO_SECONDS,left))

    def _read(self,size):
        raw=b''
        while len(raw)<size:
            self._timeout();chunk=self.stream.recv(size-len(raw))
            if not chunk:raise Rejected('FASTCGI_REFUSED')
            raw+=chunk
        return raw

    def _drain(self):
        try:
            seen=0
            for _ in range(64):
                version,kind,request,length,padding,reserved=struct.unpack('!BBHHBB',self._read(8))
                if version!=1 or request!=1 or reserved!=0 or kind not in (3,6,7):raise Rejected('FASTCGI_REFUSED')
                seen+=length+padding
                if seen>MAX_RESPONSE:raise Rejected('FASTCGI_REFUSED')
                content=self._read(length);self._read(padding)
                if kind==7 and content:self.error='FASTCGI_REFUSED'
                if kind==3:
                    if content!=b'\0'*8:raise Rejected('FASTCGI_REFUSED')
                    self.done=True;return
            raise Rejected('FASTCGI_REFUSED')
        except Exception:self.error='FASTCGI_REFUSED'

    def finish(self):
        self.thread.join(max(0,self.deadline-time.monotonic()))
        if self.thread.is_alive() or not self.done or self.error:raise Rejected('FASTCGI_REFUSED')

    def close(self):
        try:self.stream.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.stream.close()
        if hasattr(self,'thread'):self.thread.join(max(0,min(.05,self.deadline-time.monotonic())))
