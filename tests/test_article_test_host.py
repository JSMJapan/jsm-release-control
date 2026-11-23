"""Whole finite lifecycle with real ZIP/TAR validation and a simulated local Engine."""
from copy import deepcopy
from contextlib import contextmanager
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import article_test_host as h
import article_test_state as s
import article_test_smoke as smoke
from article_test_docker import DockerRefused
from test_article_test_images import envelope


class Engine:
    latest=None
    def __init__(self,path,deadline):
        self.path=path;self.deadline=deadline;self.rows={};self.tags={};self.calls=[];self.created=[];Engine.latest=self
    def absent(self,run,tags):self.tags={tag:None for tag in tags}
    def image_id(self,tag):return self.tags.get(tag)
    def create(self,args):
        self.calls.append(('create',args));role='db' if '--read-only' not in args else 'app'
        identity=('d' if role=='db' else 'e')*64;self.created.append(role)
        run=args[args.index('--label')+1].split('=')[1];image=next(x for x in args if x.startswith('sha256:'))
        self.rows[identity]=dict(id=identity,image=image,run=run,pid=101 if role=='db' else 102,
            network='none' if role=='db' else 'container:'+'d'*64,memory=h.MEMORY,swap=h.MEMORY,cpu=500000000,
            pids=128,privileged=False,readonly=role=='app',restart='no',capdrop=['CAP_NET_RAW'] if role=='db' else ['CAP_ALL'],
            security=None if role=='db' else ['no-new-privileges'],ports=None,hosts=None,pidmode='',ipcmode='private',
            log={'Type':'json-file','Config':{'max-size':'2m','max-file':'1'}},mounts=[],
            tmpfs={'/var/lib/mysql':'rw,noexec,nosuid,nodev,size=512m'} if role=='db' else {'/tmp':'rw,noexec,nosuid,nodev,size=64m,mode=1777'})
        for index,arg in enumerate(args):
            if arg=='--mount':
                parts=args[index+1].split(',');values=dict(x.split('=',1) for x in parts if '=' in x)
                self.rows[identity]['mounts'].append(dict(Type='bind',Source=values['source'],Destination=values['target'],RW='readonly' not in parts,Propagation='rprivate'))
            if arg=='--tmpfs':self.rows[identity]['mounts'].append(dict(Type='tmpfs',Destination=args[index+1].split(':')[0],RW=True))
        return identity
    def observe(self,identity,run,image):
        row=self.rows[identity];h.require(row['run']==run and row['image']==image);return deepcopy(row)
    def start(self,identity):self.calls.append(('start',identity))
    def run(self,args,**kwargs):
        self.calls.append(args)
        if args[0]=='load':
            source=kwargs['stream'];size=0
            while True:
                raw=source.read(1024)
                if not raw:break
                size+=len(raw)
            h.require(size==kwargs['input_limit'])
            self.tags={tag:identity for tag,identity in zip(self.tags,self.images)};return b''
        if args[0]=='rm':del self.rows[args[-1]];return b''
        if args[:2]==('image','rm'):self.tags[args[-1]]=None;return b''
        if args[:2]==('container','ls'):
            if args[-1].startswith('id='):return args[-1][3:].encode() if args[-1][3:] in self.rows else b''
            role='app' if '-app-' in args[-1] else 'db';key=('e' if role=='app' else 'd')*64
            return key.encode() if key in self.rows else b''
        if args[-1]=='/proc/net/dev':return b'Inter-|\n lo: 0\n'
        if args[-1]=='/proc/net/route':return b'Iface Destination\n'
        raise AssertionError('UNEXPECTED_ENGINE_CALL')
    def sql(self,identity,raw):
        self.calls.append(('sql',identity))
        if raw==b'SELECT 1;':return b'1\n'
        if b'SHOW GRANTS' in raw:
            run=self.rows[identity]['run'];reader='reader_'+run;schema='article_'+run
            return ('\n'.join((f'GRANT USAGE ON *.* TO `{reader}`@`127.0.0.1`',
                f'GRANT SELECT ON `{schema}`.`tnk_blogs` TO `{reader}`@`127.0.0.1`',
                f'GRANT SELECT ON `{schema}`.`tnk_blogs_products` TO `{reader}`@`127.0.0.1`'))+'\n').encode()
        if b'SELECT slug' in raw:return ('\n'.join(sorted(h.SLUGS))+'\n').encode()
        if b'COUNT(*)' in raw:return b'0\n' if b'products' in raw else b'5\n'
        return b''


@contextmanager
def fixture_cleanup():
    with patch.object(h,'command',return_value=b'') as commands,patch.object(h,'owned_directory',return_value=True),\
         patch.object(h,'owned_file',side_effect=lambda info:info.st_uid==os.getuid() and info.st_nlink==1 and not info.st_mode&0o022):
        yield commands


class HostTests(unittest.TestCase):
    def scenario(self,mutate=None,smoke_failure=False,engine_type=None):
        raw,build=envelope();temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        owner=patch.object(s,'ROOT_UID',os.getuid());owner.start();self.addCleanup(owner.stop)
        store=s.Store('a'*12,Path(temporary.name)/'state',create=True);self.last_store=store;self.addCleanup(store.close)
        store.write('artifact.zip',raw)
        inspected=h.inspect_archive(store.path/'artifact.zip',build)
        Engine.images=(inspected.app_image,inspected.mysql_image)
        def arm(store,state,deadline):state['timer_armed']=True;store.save(state)
        ns=lambda pid:'net:[20]' if pid in (101,102) else 'net:[10]'
        engine=engine_type or Engine
        if mutate:
            class Bad(Engine):
                def observe(self,*args):return mutate(super().observe(*args))
            engine=Bad
        actual_cleanup=h.cleanup
        def recover(*args):
            with fixture_cleanup():return actual_cleanup(*args)
        with patch.object(h,'cleanup',side_effect=recover),patch.object(h.os,'geteuid',return_value=0),patch.object(h.os,'chown'),patch.object(h,'resource_admission'),\
             patch.object(h,'timer',side_effect=arm),patch.object(h,'namespace',side_effect=ns),\
             patch.object(h,'command',return_value=b''),patch.object(smoke,'verify',side_effect=RuntimeError('PRIVATE-CANARY') if smoke_failure else None,return_value={'articles':5}):
            h.prepare(store,build,'f'*40,b'synthetic-public-code',time.monotonic()+2)
            result=h.stage(store,build,'f'*40,b'synthetic-public-code',time.monotonic()+2,engine)
        return store,result

    def test_real_archive_tar_to_new_synthetic_db_app_and_closed_stage(self):
        store,result=self.scenario()
        self.assertEqual(result['status'],'STAGED_LOCAL_ONLY');self.assertEqual(result['qa'],'NOT_TESTED')
        engine=Engine.latest;self.assertEqual(engine.created,['db','app'])
        self.assertTrue(any(call[0]=='sql' for call in engine.calls))
        self.assertEqual(store.read()['containers'],{'db':'d'*64,'app':'e'*64})
        # Every SQL target is the one created owned container; never a host DB.
        self.assertTrue(all(call[1]=='d'*64 for call in engine.calls if call[0]=='sql'))

    def test_wrong_network_stops_before_sql_and_cleans_only_owned(self):
        def wrong(row):row['network']='host';return row
        with self.assertRaises(h.HostRefused):self.scenario(wrong)
        self.assertFalse(any(call[0]=='sql' for call in Engine.latest.calls))
        self.assertEqual(Engine.latest.rows,{})

    def test_cleanup_recovery_resolves_intent_name_before_lost_id_save(self):
        store,_=self.scenario();state=store.read();state['containers']['app']=None;store.save(state)
        engine=Engine.latest
        with fixture_cleanup():result=h.cleanup(store,state,engine,time.monotonic()+2)
        self.assertEqual(result['status'],'CLEANED');self.assertFalse(store.path.exists())
        self.assertEqual(engine.rows,{})

    def test_no_create_intent_never_resolves_or_deletes_preexisting_container(self):
        store,_=self.scenario();engine=Engine.latest;state=store.read()
        state['containers']={'db':None,'app':None};state['create_attempted']={'db':False,'app':False}
        state['import_started']=False;state['import_complete']=False;store.save(state)
        before=len(engine.calls)
        with fixture_cleanup():h.cleanup(store,state,engine,time.monotonic()+2)
        self.assertEqual(set(engine.rows),{'d'*64,'e'*64})
        self.assertFalse(any(call[0] in ('rm','container') for call in engine.calls[before:]))

    def test_rm_before_state_save_crash_is_idempotently_absent(self):
        store,_=self.scenario();engine=Engine.latest;state=store.read();engine.rows={}
        with fixture_cleanup():result=h.cleanup(store,state,engine,time.monotonic()+2)
        self.assertEqual(result['status'],'CLEANED')

    def test_cleanup_preflight_keeps_state_bundle_and_timer_on_unknown_content(self):
        store,_=self.scenario();state=store.read();config=store.path/'docker-config';config.mkdir(mode=0o700)
        (config/'unexpected').write_bytes(b'CANARY-PRIVATE')
        with fixture_cleanup() as commands:
            with self.assertRaises(h.HostRefused):h.cleanup(store,state,Engine.latest,time.monotonic()+2)
            self.assertFalse(commands.called)
        self.assertTrue((store.path/'state.json').exists());self.assertTrue((store.path/'bundle.pyz').exists())
        self.assertTrue((store.path/'root.password').exists());self.assertTrue(store.read()['timer_armed'])

    def test_constructor_refusal_cleans_pre_resource_directory(self):
        class Broken(Engine):
            def __init__(self,*args):raise h.HostRefused('ARTICLE_DOCKER_REFUSED')
        with self.assertRaisesRegex(h.HostRefused,'ARTICLE_DOCKER_REFUSED'):self.scenario(engine_type=Broken)
        self.assertFalse(self.last_store.path.exists())

    def test_expired_stage_runner_uses_independent_cleanup_budget(self):
        class Expired(Engine):
            def create(self,args):
                if '--read-only' in args:
                    self.deadline=time.monotonic()-1;raise DockerRefused('ARTICLE_STAGE_DEADLINE')
                return super().create(args)
            def run(self,args,**kwargs):
                h.until(self.deadline);return super().run(args,**kwargs)
        with self.assertRaisesRegex(DockerRefused,'ARTICLE_STAGE_DEADLINE'):self.scenario(engine_type=Expired)
        self.assertEqual(Engine.latest.rows,{})

    def test_partial_import_absent_tags_retains_recovery_and_never_claims_cleaned(self):
        store,_=self.scenario();state=store.read();state['import_complete']=False;store.save(state)
        engine=Engine.latest;engine.tags={tag:None for tag in state['tags']}
        with fixture_cleanup() as commands:
            with self.assertRaisesRegex(h.HostRefused,'ARTICLE_CLEANUP_UNCONFIRMED'):
                h.cleanup(store,state,engine,time.monotonic()+2)
            self.assertFalse(commands.called)
        self.assertEqual(engine.rows,{})
        self.assertTrue((store.path/'bundle.pyz').exists());self.assertTrue((store.path/'state.json').exists())
        self.assertFalse(store.read()['import_complete'])

    def test_stale_atomic_temp_does_not_prevent_whole_cleanup(self):
        store,_=self.scenario();state=store.read();(store.path/'state.tmp').write_bytes(b'{"partial":')
        with fixture_cleanup():result=h.cleanup(store,state,Engine.latest,time.monotonic()+2)
        self.assertEqual(result['status'],'CLEANED');self.assertFalse(store.path.exists())

if __name__=='__main__':unittest.main()
