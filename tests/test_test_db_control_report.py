import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import test_db_control_report as control
import test_db_runtime_control_entry as entry
from apache_parity_bridge import Refused


SHA = 'a' * 40
NONCE = 'b' * 32
RUN_ID = '12345'
OWNER = {'login':'JSMJapan', 'id':327623967}
REPO = {'full_name':'JSMJapan/jsm-release-control','id':1427965640,'private':False}
ENV = dict(name='test-api-readonly-access', id=26702164832)
PRODUCER_SOURCE = 'test_db_runtime_producer.py'


def write_fixture_sources(root):
    for source in control.PYTHON_FILES + control.PHP_FILES:
        (root / source).write_text('# ' + source + '\n')
    (root / PRODUCER_SOURCE).write_text('def collect_control(context):\n    return {}\n')


class Api:
    def __init__(self):
        self.paths=[]
        self.responses={
            control.GH_REPO:dict(REPO,owner=OWNER),
            control.MAIN:dict(name='main', protected=True, commit={'sha':SHA}),
            control.WORKFLOW_ENDPOINT:dict(id=123, path=control.WORKFLOW, state='active'),
            control.run_endpoint(RUN_ID):dict(id=int(RUN_ID),event='workflow_dispatch',
                head_sha=SHA,head_branch='main',workflow_id=123,path=control.WORKFLOW,run_attempt=1,
                status='in_progress',actor=OWNER,triggering_actor=OWNER,repository=REPO,head_repository=REPO),
            control.run_endpoint(RUN_ID)+'/approvals':[
                dict(state='approved',user=OWNER,environments=[ENV])],
            control.GH_ENV:dict(ENV,can_admins_bypass=False,
                deployment_branch_policy={'custom_branch_policies':True,'protected_branches':False},
                protection_rules=[dict(type='required_reviewers',prevent_self_review=False,
                    reviewers=[dict(type='User',reviewer=OWNER)]),{'type':'branch_policy'}]),
            control.GH_ENV+'/deployment-branch-policies':{
                'total_count':1,'branch_policies':[dict(name='main',type='branch')]},
        }

    def get_json(self,path):
        self.paths.append(path)
        return self.responses[path]


class ControlLaunchTests(unittest.TestCase):
    def setUp(self):
        self.env=dict(control.FIXED_ENV,GITHUB_SHA=SHA,GITHUB_WORKFLOW_SHA=SHA,
                      APPROVED_SHA=SHA,GITHUB_RUN_ID=RUN_ID)

    def test_actual_owner_approval_builds_a_distinct_control_scope(self):
        api=Api()
        context=control.authorize(api,self.env)
        self.assertEqual(context['scope']['repository'],'JSMJapan/jsm-release-control')
        self.assertEqual(context['scope']['workflow'],control.WORKFLOW)
        self.assertEqual(context['scope']['deployment_environment'],'test-api-readonly-access')
        self.assertEqual(context['run']['id'],RUN_ID)
        self.assertEqual(set(api.paths),set(control.api_paths(RUN_ID)))

    def test_scope_sha_run_branch_and_owner_reject_before_transport(self):
        for key in ('GITHUB_ACTOR','GITHUB_REF','APPROVED_SHA','GITHUB_RUN_ATTEMPT'):
            api=Api()
            with self.assertRaises(Refused):
                control.authorize(api,dict(self.env,**{key:'changed'}))
            self.assertEqual(api.paths,[])
        for field,value in (
            ('run_attempt',2),('head_sha','a'*39+'b'),('repository',{'id':1}),
            ('triggering_actor',{'id':2,'login':'JSMJapan'}),('path','.github/workflows/sandbox-publish.yml'),
        ):
            api=Api()
            api.responses[control.run_endpoint(RUN_ID)][field]=value
            with self.assertRaises(Refused):
                control.authorize(api,self.env)

    def test_environment_drift_fails_before_run_lookup(self):
        for field, value in (('id', 1), ('can_admins_bypass', True), ('name', 'sandbox')):
            api = Api()
            api.responses[control.GH_ENV][field] = value
            with self.assertRaisesRegex(Refused, 'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED'):
                control.authorize(api, self.env)
            self.assertNotIn(control.run_endpoint(RUN_ID), api.paths)

    def test_rejected_ambiguous_or_unrelated_approval_never_admits(self):
        api=Api()
        endpoint=control.run_endpoint(RUN_ID)+'/approvals'
        wrong_variants=([],[dict(state='approved',user=OWNER,environments=[{'id':1,'name':ENV['name']}])],
                        [dict(state='rejected',user=OWNER,environments=[ENV])],
                        [dict(state='approved',user={'login':'JSMJapan','id':1},environments=[ENV])])
        for rows in wrong_variants:
            api.responses[endpoint]=rows
            with self.assertRaises(Refused):
                control.authorize(api,self.env)

    def test_missing_reviewed_bundle_fails_before_opening_vm_transport(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(control,'_receive') as receiver:
            with self.assertRaisesRegex(Refused,'SOURCE_BUNDLE_NOT_READY'):
                control.collect(Api(),self.env,Path(directory))
            receiver.assert_not_called()

    def test_package_is_deterministic_and_declares_exact_php_and_archive_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            write_fixture_sources(root)
            a=control.build_package(root)
            b=control.build_package(root)
            self.assertEqual(a,b)
            self.assertEqual(len(a.pins),1+len(control.PHP_FILES))
            self.assertTrue(all(path.startswith('/usr/local/libexec/') for path,_,_ in a.pins))
            self.assertIn(('__main__.py','test_db_runtime_control_entry.py'),control.ZIP_RECIPE)
            (root / PRODUCER_SOURCE).write_text('def collect(context):\n    return {}\n')
            with self.assertRaisesRegex(Refused, 'SOURCE_BUNDLE_NOT_READY'):
                control.build_package(root)
            write_fixture_sources(root)
            (root/control.PHP_FILES[0]).unlink()
            with self.assertRaises(Refused):
                control.build_package(root)

    def test_archive_executes_from_inherited_fd_with_isolated_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture_sources(root)
            (root / control.PYTHON_FILES[0]).write_text('import test_db_runtime_producer\nprint("fixture")\n')
            with tempfile.TemporaryFile() as archive:
                archive.write(control.build_package(root).archive)
                archive.seek(0)
                prefix = '/proc/self/fd/' if sys.platform == 'linux' else '/dev/fd/'
                child = subprocess.run([sys.executable, '-I', '-B', '-S', prefix + str(archive.fileno())],
                                       pass_fds=(archive.fileno(),), capture_output=True, timeout=3)
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertEqual(child.stdout, b'fixture\n')

    def test_root_capsule_is_valid_python_and_refuses_missing_installed_bundle(self):
        context = control.authorize(Api(), self.env)
        program = control.root_program(NONCE, context, ((control.ARCHIVE_PATH, 1, '0' * 64),))
        compile(program, '<synthetic TEST capsule>', 'exec')
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(control.guard, 'LOCK', str(Path(directory) / 'absent')):
                program = control.root_program(NONCE, context, ((control.ARCHIVE_PATH, 1, '0' * 64),))
            child = subprocess.run([sys.executable, '-I', '-B', '-S', '-c', program],
                                   capture_output=True, timeout=3, check=True)
        payload = json.loads(child.stdout)
        self.assertEqual(payload['context_sha256'], control.digest(context))
        self.assertIsNone(payload['report'])

    def test_entry_uses_control_method_and_refuses_private_context_before_calling_it(self):
        import io
        from unittest.mock import Mock

        context = control.authorize(Api(), self.env)
        private = dict(context, scope=dict(context['scope'], repository='JSMJapan/jsm-storefront'))
        producer = types.ModuleType('test_db_runtime_producer')
        result = dict(status='BLOCKED', local_peer='NOT_ESTABLISHED', configured_runtime='NOT_ESTABLISHED',
                      sql='NOT_ATTEMPTED', metadata=None)
        producer.collect_control = Mock(return_value=dict(result, internal_note='discarded'))
        output = io.BytesIO()
        with patch.dict(sys.modules, {producer.__name__: producer}):
            for value, expected in ((private, 1), (context, 0)):
                runtime = types.SimpleNamespace(platform='linux', argv=['report.pyz'],
                                                stdin=types.SimpleNamespace(buffer=io.BytesIO(control.canonical(value))),
                                                stdout=types.SimpleNamespace(buffer=output))
                with patch.object(entry, 'sys', runtime), patch.object(entry.os, 'geteuid', return_value=0):
                    self.assertEqual(entry.main(), expected)
        producer.collect_control.assert_called_once_with(context)
        self.assertEqual(json.loads(output.getvalue()), result)

    def test_remote_result_is_correlated_and_has_a_closed_schema(self):
        context=control.authorize(Api(),self.env)
        payload=dict(version=control.VERSION,nonce=NONCE,euid=0,context_sha256=control.digest(context),
                     report=dict(status='BLOCKED',configured_runtime='NOT_ESTABLISHED',
                                 local_peer='NOT_ESTABLISHED',sql='NOT_ATTEMPTED',metadata=None))
        envelope=dict(version='jsm-test-installed-route-outer-v2',nonce=NONCE,principal='marinagurina',euid=1000,
                      root_diagnostic=payload)
        good=json.dumps(envelope).encode()
        receipt=control.project_remote(good,NONCE,context)
        self.assertEqual(receipt['db_isolation'],'NOT_ESTABLISHED')
        self.assertEqual(receipt['scope'],context['scope'])
        for key,value in (('nonce','c'*32),('context_sha256','d'*64),('euid',1000)):
            forged=copy.deepcopy(envelope)
            forged['root_diagnostic'][key]=value
            with self.assertRaises(Refused):
                control.project_remote(json.dumps(forged).encode(),NONCE,context)
        payload['report']['unexpected']='private content'
        with self.assertRaises(Refused):
            control.project_remote(json.dumps(envelope).encode(),NONCE,context)
