"""Authenticated metadata and native HTTP framing fixtures, no network services."""
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import article_test_actions as a
from article_test_artifact import Build


class Api:
    def __init__(self,rows):self.rows=rows;self.calls=[]
    def get_json(self,path):self.calls.append(path);return self.rows[path]


def artifact_api(build,size):
    repo=dict(id=100,full_name=a.SOURCE_REPO,private=True,owner={'login':'JSMJapan','id':a.OWNER_ID})
    run=dict(id=int(build.run_id),head_sha=build.sha,path=a.PACKAGE_WORKFLOW,event='pull_request',
        status='completed',conclusion='success',run_attempt=1,repository=repo,head_repository=repo)
    names=('Check out the reviewed package source','Check out the fixed article candidate',
        'Prepare reviewed sources and separate schema and seed','Build only the disposable article image',
        'Run native MySQL and article HTTP acceptance without external networking',
        'Create a checksummed offline deployment artifact','Upload the verified isolated package to private GitHub Actions')
    job=dict(name='package',status='completed',conclusion='success',head_sha=build.sha,run_id=int(build.run_id),
        steps=[dict(name=name,number=n,status='completed',conclusion='success') for n,name in enumerate(names,1)])
    item=dict(id=int(build.artifact_id),name=build.artifact_name,expired=False,digest='sha256:'+build.archive_sha256,
        size_in_bytes=size,workflow_run={'id':int(build.run_id),'head_sha':build.sha})
    return Api(dict(zip(a.artifact_paths(build),(repo,run,{'total_count':1,'artifacts':[item]}, {'total_count':1,'jobs':[job]},item))))


class Response:
    def __init__(self,status,headers,body=b''):self.status=status;self.rows=headers;self.body=BytesIO(body)
    def getheaders(self):return self.rows
    def read1(self,n):return self.body.read(n)
    def close(self):pass


class ActionsTests(unittest.TestCase):
    def test_actual_run_job_native_step_and_artifact_boundaries(self):
        build=Build('a'*40,'123','456','b'*64);api=artifact_api(build,10)
        self.assertEqual(a.authorize_artifact(api,build),10)
        self.assertEqual(api.calls,list(a.artifact_paths(build)))
        for mutation in ('head','job','native','expired','digest','duplicate'):
            api=artifact_api(build,10);paths=a.artifact_paths(build)
            if mutation=='head':api.rows[paths[1]]['head_sha']='c'*40
            if mutation=='job':api.rows[paths[3]]['jobs'][0]['conclusion']='skipped'
            if mutation=='native':api.rows[paths[3]]['jobs'][0]['steps'][4]['conclusion']='skipped'
            if mutation=='expired':api.rows[paths[4]]['expired']=True
            if mutation=='digest':api.rows[paths[4]]['digest']='sha256:'+'c'*64
            if mutation=='duplicate':api.rows[paths[2]]['artifacts']*=2;api.rows[paths[2]]['total_count']=2
            with self.assertRaises(a.ActionsRefused):a.authorize_artifact(api,build)

    def connections(self,responses):
        calls=[]
        class Connection:
            def __init__(self,host,**kwargs):self.host=host;self.sock=None;self.response=responses.pop(0)
            def request(self,method,path,headers):calls.append((self.host,method,path,headers))
            def getresponse(self):return self.response
            def close(self):pass
        return Connection,calls

    def test_token_only_api_not_signed_storage_and_exact_digest(self):
        payload=b'synthetic artifact';build=Build('a'*40,'123','456',sha256(payload).hexdigest())
        responses=[Response(302,[('Location','https://productionresultssa1.blob.core.windows.net/archive?sig=CANARY-SIGNED-TOKEN')]),
                   Response(200,[('Content-Length',str(len(payload)))],payload)]
        connection,calls=self.connections(responses)
        with tempfile.TemporaryDirectory() as directory:
            destination=Path(directory)/'artifact.zip'
            a.download(build,'synthetic-token',destination,len(payload),time.monotonic()+1,connection)
            self.assertEqual(destination.read_bytes(),payload)
        self.assertEqual(calls[0][0],'api.github.com');self.assertEqual(calls[0][3]['Authorization'],'Bearer synthetic-token')
        self.assertNotIn('Authorization',calls[1][3]);self.assertEqual(calls[1][0],'productionresultssa1.blob.core.windows.net')

    def test_bad_redirect_duplicate_length_encoding_and_hash_are_closed(self):
        payload=b'fixture';build=Build('a'*40,'123','456',sha256(payload).hexdigest())
        for location in ('http://productionresultssa1.blob.core.windows.net/x',
                         'https://CANARY-SIGNED-TOKEN@example.invalid/x','https://example.invalid/?sig=CANARY-SIGNED-TOKEN'):
            connection,_=self.connections([Response(302,[('Location',location)])])
            with tempfile.TemporaryDirectory() as directory:
                try:a.download(build,'synthetic-token',Path(directory)/'a',len(payload),time.monotonic()+1,connection)
                except a.ActionsRefused as error:self.assertNotIn('CANARY-SIGNED-TOKEN',str(error))
                else:self.fail('REDIRECT_NOT_REFUSED')
        for headers,body,status in [([('Content-Length','7'),('Content-Length','7')],payload,200),
                ([('Content-Length','7'),('Content-Encoding','gzip')],payload,200),
                ([('Content-Length','7')],b'changed',200),([('Location','/another')],b'',302)]:
            connection,_=self.connections([Response(302,[('Location','https://productionresultssa1.blob.core.windows.net/x')]),Response(status,headers,body)])
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(a.ActionsRefused):a.download(build,'synthetic-token',Path(directory)/'a',len(payload),time.monotonic()+1,connection)

    def test_native_slow_header_obeys_absolute_deadline_not_inactivity(self):
        client,server=socket.socketpair()
        def writer():
            with server:
                try:
                    server.sendall(b'HTTP/1.1 200 OK\r\nX-Canary: ')
                    for _ in range(20):server.sendall(b'x');time.sleep(.01)
                except OSError:pass
        thread=threading.Thread(target=writer);thread.start();started=time.monotonic()
        response=a.HeaderResponse(client,deadline=started+.05)
        try:
            with self.assertRaises((a.ActionsRefused,TimeoutError)):response.begin()
            self.assertLess(time.monotonic()-started,.5)
        finally:response.close();client.close();thread.join()

if __name__=='__main__':unittest.main()
