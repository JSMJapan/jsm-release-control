import base64
import bz2
from contextlib import ExitStack, contextmanager
import copy
from hashlib import sha256
import io
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

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
    (root / PRODUCER_SOURCE).write_text('def collect_control(context, staging, deadline_ns):\n    return {}\n')



def blocked_report(state='NOT_SENT'):
    return dict(status='BLOCKED', stage='CONTEXT', reason='CONTEXT_REQUIRED',
                local_peer='NOT_ESTABLISHED', configured_runtime='NOT_ESTABLISHED',
                sql='NOT_ATTEMPTED', metadata=None, fastcgi_state=state,
                pre_entry='NOT_ESTABLISHED',effective_ini_selection='NOT_ATTESTED',worker_memory='NOT_ATTESTED',
                dependency_trust='INSTALLED_PHP_AND_VENDOR_NOT_ATTESTED',synthetic_provenance='UNKNOWN',
                grants='UNKNOWN',egress_isolation='UNKNOWN',arbitrary_request_binding='NOT_ESTABLISHED')


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
            self.assertEqual(tuple(path for path, _, _ in a.pins), tuple(path for path, _ in control.ZIP_RECIPE))
            self.assertEqual({path[4:] for path, _, _ in a.pins if path.startswith('php/')}, set(control.PHP_FILES))
            self.assertIn(('__main__.py','test_db_runtime_control_entry.py'),control.ZIP_RECIPE)
            (root / PRODUCER_SOURCE).write_text('def collect_control(context):\n    return {}\n')
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

    def test_package_decoder_rejects_wrong_hash_and_trailing_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture_sources(root)
            package = control.build_package(root)
        raw = package.archive
        compressed = bz2.compress(raw)
        pin = sha256(raw).hexdigest()
        archive, php = control.capsule.decode_package(base64.b64encode(compressed), len(raw), pin, package.pins)
        self.assertEqual(archive, raw)
        self.assertEqual(set(php), set(control.PHP_FILES))
        for invalid, expected in ((compressed + bz2.compress(b'x'), pin), (compressed, '0' * 64)):
            with self.assertRaises(control.capsule.PackageRefused):
                control.capsule.decode_package(base64.b64encode(invalid), len(raw), expected, package.pins)
        for altered in (package.pins[:-1], package.pins + (('extra.py', 1, '0' * 64),)):
            with self.assertRaises(control.capsule.PackageRefused):
                control.capsule.decode_package(base64.b64encode(compressed), len(raw), pin, altered)

    def test_root_capsule_compiles_and_rejects_oversized_final_argument(self):
        context = control.authorize(Api(), self.env)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture_sources(root)
            fixture = control.build_package(root)
        program = control.root_program(NONCE, context, fixture)
        compile(program, '<synthetic TEST capsule>', 'exec')
        self.assertLessEqual(len(program.encode('ascii')) + 1, 131072)
        with patch.object(control, 'MAX_CHILD', len(program)-1):
            with self.assertRaisesRegex(Refused, 'SOURCE_BUNDLE_NOT_READY'):
                control.root_program(NONCE, context, fixture)

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'memfd_create'), 'Linux sealed memfd')
    def test_sealed_readonly_archive_runs_as_python_zipapp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture_sources(root)
            (root / control.PYTHON_FILES[0]).write_text('import test_db_runtime_producer\nprint("sealed")\n')
            package = control.build_package(root)
        with ExitStack() as resources:
            fd = control.capsule.archive_descriptor(resources, package.archive)
            with self.assertRaises(OSError):
                os.write(fd, b'forbidden')
            child = subprocess.run([sys.executable, '-I', '-B', '-S', '/proc/self/fd/' + str(fd)],
                                   pass_fds=(fd,), capture_output=True, check=True, timeout=3)
            self.assertEqual(child.stdout, b'sealed\n')

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'memfd_create'), 'Linux sealed memfd')
    def test_offline_smoke_imports_packed_dependencies_without_invoking_producer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture_sources(root)
            producer = root / PRODUCER_SOURCE
            valid = ('import test_db_runtime_preentry\n'
                     'def collect_control(context, staging, deadline_ns):\n    raise AssertionError("runtime invoked")\n')
            producer.write_text(valid)
            control.verify_package(root)
            producer.write_text('import missing_dependency_for_2760\n' + valid)
            with self.assertRaises(subprocess.CalledProcessError):
                control.verify_package(root)

    def test_root_timeout_after_spawning_refuses_cleanup_and_withholds_success(self):
        context = control.authorize(Api(), self.env)
        demo = control.Package(b'fixture', ())
        source = control.root_program(NONCE, context, demo).rsplit('\nprint(', 1)[0]
        box = {}
        exec(compile(source, '<synthetic capsule namespace>', 'exec'), box)
        effects = []

        @contextmanager
        def fake_staging(root, nonce, files):
            effects.append('staged')
            try:
                yield {'synthetic': True}
            except box['DeferCleanup']:
                effects.append('deferred')
                raise box['CleanupUnconfirmed']() from None

        box.update(os=types.SimpleNamespace(geteuid=lambda: 0), sys=types.SimpleNamespace(platform='linux'),
                   signal=types.SimpleNamespace(signal=lambda *_: None, SIGTERM=15),
                   decode_package=lambda *_: (b'fixture', {}), archive_descriptor=lambda *_: 10,
                   staged_php=fake_staging, run_producer=Mock(side_effect=TimeoutError()))
        result = box['root_receipt'](NONCE, context, b'', 0, '', ())
        self.assertEqual(effects, ['staged', 'deferred'])
        self.assertEqual(result['cleanup'], 'UNCONFIRMED')
        self.assertEqual(result['transport_reason'], 'STAGING_CLEANUP_UNCONFIRMED')
        self.assertIsNone(result['report'])

    def test_entry_uses_staging_and_absolute_deadline_and_refuses_bad_context(self):
        context = control.authorize(Api(), self.env)
        private = dict(context, scope=dict(context['scope'], repository='JSMJapan/jsm-storefront'))
        staging = dict(path='/run/jsm-db-2760-' + NONCE, device=1, inode=2,
                       files={name: dict(device=1, inode=index, size=3, sha256='a'*64)
                              for index, name in enumerate(control.PHP_FILES, 3)})
        producer = types.ModuleType('test_db_runtime_producer')
        result = blocked_report()
        producer.collect_control = Mock(return_value=dict(result, internal_note='discarded'))
        output = io.BytesIO()
        until = time.monotonic_ns() + 3_000_000_000
        cases = ((private, staging, until, 1), (context, dict(staging, path='/tmp/refused'), until, 1),
                 (context, staging, until - 4_000_000_000, 1), (context, staging, until, 0))
        with patch.dict(sys.modules, {producer.__name__: producer}):
            for value, files, deadline, expected in cases:
                payload = dict(context=value, staging=files, deadline_ns=deadline)
                runtime = types.SimpleNamespace(platform='linux', argv=['report.pyz'],
                                                stdin=types.SimpleNamespace(buffer=io.BytesIO(control.canonical(payload))),
                                                stdout=types.SimpleNamespace(buffer=output))
                with patch.object(entry, 'sys', runtime), patch.object(entry.os, 'geteuid', return_value=0):
                    self.assertEqual(entry.main(), expected)
        producer.collect_control.assert_called_once_with(context, staging, until)
        self.assertEqual(json.loads(output.getvalue()), result)

    def test_remote_result_is_correlated_and_has_a_closed_schema(self):
        context=control.authorize(Api(),self.env)
        payload=dict(version=control.VERSION,nonce=NONCE,euid=0,context_sha256=control.digest(context),
                     cleanup='VERIFIED', transport_reason=None, report=blocked_report())
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


    def test_unconfirmed_cleanup_never_returns_success(self):
        context = control.authorize(Api(), self.env)
        child = dict(version=control.VERSION, nonce=NONCE, euid=0, context_sha256=control.digest(context),
                     cleanup='UNCONFIRMED', transport_reason='STAGING_CLEANUP_UNCONFIRMED',
                     report=blocked_report('UNCONFIRMED'))
        envelope = dict(version='jsm-test-installed-route-outer-v2', nonce=NONCE,
                        principal='marinagurina', euid=1000, root_diagnostic=child)
        outcome = control.project_remote(control.canonical(envelope), NONCE, context)
        self.assertEqual((outcome['status'], outcome['cleanup']), ('BLOCKED', 'UNCONFIRMED'))
        self.assertEqual(outcome['reason'], 'CONTEXT_REQUIRED')
        child['transport_reason'] = None
        with self.assertRaises(Refused):
            control.project_remote(control.canonical(envelope), NONCE, context)
