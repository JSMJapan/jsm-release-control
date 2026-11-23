"""Owned-tag cleanup must not delete a prior dangling image or prune its parents."""
from pathlib import Path
import sys
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from article_test_docker import Docker
from article_test_host import HostRefused,cleanup
import test_article_test_host as host_fixture
Engine=host_fixture.Engine
fixture_cleanup=host_fixture.fixture_cleanup


class ExistingImagesTests(unittest.TestCase):
    def test_preexisting_dangling_native_or_config_is_refused_before_load(self):
        for form in ('native','config'):
            with self.subTest(form=form):
                core=host_fixture.HostTests();self.addCleanup(core.doCleanups)
                class PriorImage(Engine):
                    def __init__(self,*args):
                        super().__init__(*args);self.prior=self.runtime_images[1];self.cache={self.prior};self.loaded=False
                    def image_present(self,identity):return identity in self.cache
                    def absent(self,run,tags,*aliases):
                        self.tags={tag:None for tag in tags};return Docker.absent(self,run,tags,*aliases)
                    def run(self,args,**kwargs):
                        if args[0]=='load':self.loaded=True
                        return super().run(args,**kwargs)
                with self.assertRaises((HostRefused,ValueError)):
                    core.scenario(engine_type=PriorImage,manifest_ids=True,tag_mode=form)
                self.assertFalse(Engine.latest.loaded);self.assertIn(Engine.latest.prior,Engine.latest.cache)
                self.assertFalse(any(call[0]=='sql' for call in Engine.latest.calls))

    def test_cleanup_never_prunes_a_preexisting_dangling_parent(self):
        core=host_fixture.HostTests();self.addCleanup(core.doCleanups)
        class ParentStore(Engine):
            def __init__(self,*args):super().__init__(*args);self.parent_preserved=True
            def run(self,args,**kwargs):
                if args[:2]==('image','rm') and '--no-prune' not in args:self.parent_preserved=False
                return super().run(args,**kwargs)
        store,_=core.scenario(engine_type=ParentStore);state=store.read()
        with fixture_cleanup():self.assertEqual(cleanup(store,state,Engine.latest,time.monotonic()+2)['status'],'CLEANED')
        self.assertTrue(Engine.latest.parent_preserved)
        self.assertTrue(all('--no-prune' in args for args in Engine.latest.calls if args[:2]==('image','rm')))


class PresenceProtocolTests(unittest.TestCase):
    def reply(self,status,body,extra=(),declared=None):
        import socket
        import article_test_docker as boundary
        client,server=socket.socketpair();self.addCleanup(client.close)
        headers=[('Content-Length',str(len(body) if declared is None else declared)),('Content-Type','application/json'),*extra]
        raw=('HTTP/1.1 '+str(status)+' Result\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers)+'\r\n').encode()
        server.sendall(raw+body);server.close()
        return client,boundary

    def test_existing_image_200_never_reads_metadata_body(self):
        body=b'{"Config":{"Env":["CANARY_PRIVATE_VALUE"]}}';client,boundary=self.reply(200,body)
        self.assertIs(boundary.image_presence_reply(client,'sha256:'+'a'*64,time.monotonic()+1),True)
        client.settimeout(.1);self.assertEqual(client.recv(len(body)+1),body)

    def test_only_exact_complete_404_is_absence(self):
        import json
        identity='sha256:'+'a'*64
        body=json.dumps({'message':'No such image: '+identity}).encode()
        client,boundary=self.reply(404,body)
        self.assertIs(boundary.image_presence_reply(client,identity,time.monotonic()+1),False)
        for status,raw,extra in ((500,b'CANARY_PRIVATE_VALUE',()),(403,b'CANARY_PRIVATE_VALUE',()),
                (404,b'{"message":"other"}',()),(404,b'{"message":"No such image: wrong"}',()),
                (404,b'{"message":"CANARY_PRIVATE_VALUE","message":"other"}',()),
                (404,body,(('Content-Length',str(len(body))),)),(404,body,(('Transfer-Encoding','chunked'),))):
            client,boundary=self.reply(status,raw,extra)
            with self.assertRaises(Exception) as caught:boundary.image_presence_reply(client,identity,time.monotonic()+1)
            self.assertNotIn('CANARY_PRIVATE_VALUE',str(caught.exception))
        client,boundary=self.reply(404,body[:-1],declared=len(body))
        with self.assertRaises(Exception):boundary.image_presence_reply(client,identity,time.monotonic()+1)
        client,boundary=self.reply(404,body)
        with self.assertRaises(Exception):boundary.image_presence_reply(client,identity,time.monotonic()-1)

    def test_all_proved_aliases_checked_and_io_error_cannot_be_absence(self):
        from article_test_docker import DockerRefused
        aliases=(('sha256:'+'a'*64,'sha256:'+'b'*64),('sha256:'+'c'*64,'sha256:'+'d'*64))
        class Boundary:
            def __init__(self):self.read=[]
            def image_id(self,tag):return None
            def image_present(self,identity):self.read.append(identity);return False
            def run(self,*args,**kwargs):return b''
        subject=Boundary();Docker.absent(subject,'e'*12,('first','second'),aliases)
        self.assertEqual(subject.read,[item for pair in aliases for item in pair])
        def broken(identity):raise DockerRefused('ARTICLE_IMAGE_PRESENCE_UNCONFIRMED')
        subject.image_present=broken
        with self.assertRaises(DockerRefused):Docker.absent(subject,'e'*12,('first','second'),aliases)


class NativeDockerPresenceTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux' and __import__('os').environ.get('GITHUB_ACTIONS')=='true',
        'Native Docker fixture requires disposable Linux GitHub runner; local NOT_TESTED')
    def test_real_dangling_image_200_404_refusal_and_no_prune_command(self):
        import io,os,secrets,shutil,subprocess,tarfile,tempfile
        from article_test_docker import DockerRefused
        self.assertEqual(os.environ.get('RUNNER_ENVIRONMENT'),'github-hosted')
        self.assertTrue(Path('/usr/bin/docker').is_file(),'NATIVE_DOCKER_REQUIRED')
        context=tempfile.TemporaryDirectory();self.addCleanup(context.cleanup)
        runner=Docker(Path(context.name),time.monotonic()+45)
        payload=io.BytesIO()
        with tarfile.open(fileobj=payload,mode='w') as archive:
            item=tarfile.TarInfo('synthetic-only.txt');item.size=11;archive.addfile(item,io.BytesIO(b'synthetic!\n'))
        def cli(args,data=None):
            result=subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock','--config',str(runner.config),*args],
                input=data,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'},timeout=15,check=False)
            self.assertEqual(result.returncode,0,'NATIVE_DOCKER_COMMAND_REFUSED');self.assertLessEqual(len(result.stdout),32768)
            return result.stdout.decode('ascii').strip()
        identity=None;own_tag='jsm-article-test:'+secrets.token_hex(20)
        try:
            # Import with no repository argument creates only a new, untagged scratch image.
            identity=cli(('image','import','-'),payload.getvalue())
            self.assertRegex(identity,r'^sha256:[0-9a-f]{64}$')
            self.assertIs(runner.image_present(identity),True)
            missing='sha256:'+secrets.token_hex(32);self.assertIs(runner.image_present(missing),False)
            other_tag='jsm-article-mysql:'+secrets.token_hex(20)
            with self.assertRaisesRegex(DockerRefused,'ARTICLE_EXISTING_IMAGE_REFUSED'):
                runner.absent(secrets.token_hex(6),(own_tag,other_tag),((missing,),(identity,)))
            self.assertIs(runner.image_present(identity),True)
            # This fixture owns the scratch image; demonstrate the exact no-prune removal option.
            cli(('image','tag',identity,own_tag))
            runner.run(('image','rm','--no-prune',own_tag),seconds=10,limit=4096)
            self.assertIs(runner.image_present(identity),False)
            print('NATIVE_SYNTHETIC_IMAGE_GUARD_PASS')
        finally:
            if identity is not None:
                # Exact fixture-created ID/tag only; no global prune/foreign resources.
                for target in (own_tag,identity):
                    subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock','--config',str(runner.config),
                        'image','rm','--no-prune',target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                        env={'PATH':'/usr/bin:/bin','LANG':'C'},timeout=10,check=False)

if __name__=='__main__':unittest.main()
