"""Verify the protected GitHub launch and collect a closed TEST metadata receipt."""
import ast
import base64
import bz2
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
import inspect
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from zipfile import ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _GitHubGet, _read_regular, need, strict_json
from hostinger_preflight import policy_ready
from test_db_installer_receipt import _run
from test_db_runtime_control_contract import (
    ENVIRONMENT_NAME, FD_REASONS, PHP_FILES, REASONS, REFERENCE_SITE_SHA, REPORT_FIELDS, REPO, RUN_ACTOR,
    SCOPE, STAGES, VERSION, WORKFLOW, canonical, digest, report_valid,
)
from test_installer_capture_encrypted import GH_ENV, GH_REPO, OVERALL_SECONDS, _receive
import test_db_control_capsule as capsule
import test_db_control_staging as staging


WORKFLOW_ENDPOINT = GH_REPO + '/actions/workflows/' + WORKFLOW.rsplit('/', 1)[1]
MAIN = GH_REPO + '/branches/main'
OWNER = {'id': 327623967, 'login': RUN_ACTOR}
REPOSITORY = {'id': 1427965640, 'full_name': REPO, 'private': False}
ENVIRONMENT = {'id': 26702164832, 'name': ENVIRONMENT_NAME}
FIXED_ENV = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR=OWNER['login'], GITHUB_TRIGGERING_ACTOR=OWNER['login'],
                 GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                 GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                 GITHUB_JOB='report', GITHUB_WORKFLOW_REF=REPO + '/' + WORKFLOW + '@refs/heads/main')
PYTHON_FILES = (
    'test_db_runtime_control_entry.py', 'test_db_runtime_control_contract.py', 'test_db_runtime_producer.py', 'test_db_runtime_protocol.py',
    'test_db_runtime_fastcgi.py', 'test_db_runtime_kernel.py', 'test_db_runtime_proc.py', 'test_db_runtime_preentry.py',
    'test_db_installer_receipt.py', 'apache_parity_bridge.py', 'hostinger_preflight.py',
    'test_db_os_metadata.py', 'test_db_php_endpoint.py', 'test_db_docker_metadata.py',
    'test_db_docker_binding.py', 'test_php_manifest_readonly.py', 'test_installer_capture_encrypted.py',
    'test_installer_capture_capsule.py', 'test_api_installed_route_readonly.py', 'test_api_readonly_access.py',
)
ZIP_RECIPE = ((('__main__.py', PYTHON_FILES[0]),) + tuple((name, name) for name in PYTHON_FILES[1:])
              + tuple(('php/' + name, name) for name in PHP_FILES))
MAX_CHILD = 131_071  # Leave room for the terminating NUL in the Linux argument.
CAPSULE_FAILURES = ('CAPSULE_PACKAGE_REFUSED', 'STAGING_REFUSED', 'CAPSULE_DEADLINE',
                    'CAPSULE_PRODUCER_REFUSED', 'STAGING_CLEANUP_UNCONFIRMED')
CONTEXT_REFUSED = 'EXACT_CONTROL_WORKFLOW_CONTEXT_REQUIRED'
RUN_REFUSED = 'GITHUB_CONTROL_RUN_NOT_VERIFIED'
APPROVAL_REFUSED = 'OWNER_ENVIRONMENT_APPROVAL_NOT_VERIFIED'
BUNDLE_REFUSED = 'SOURCE_BUNDLE_NOT_READY'
RECEIPT_REFUSED = 'CONTROL_RECEIPT_REJECTED'


def run_endpoint(run_id):
    need(type(run_id) is str and re.fullmatch('[1-9][0-9]{0,14}', run_id), CONTEXT_REFUSED)
    return GH_REPO + '/actions/runs/' + run_id


def api_paths(run_id):
    run = run_endpoint(run_id)
    return (GH_REPO, GH_ENV, GH_ENV + '/deployment-branch-policies', MAIN, WORKFLOW_ENDPOINT, run, run + '/approvals')


def matches(value, expected):
    return type(value) is dict and all(type(value.get(key)) is type(item) and value[key] == item
                                       for key, item in expected.items())


def authorize(api, env):
    sha = env.get('GITHUB_SHA', '')
    need(all(env.get(key) == value for key, value in FIXED_ENV.items())
         and type(sha) is str and re.fullmatch('[0-9a-f]{40}', sha)
         and env.get('APPROVED_SHA') == sha and env.get('GITHUB_WORKFLOW_SHA') == sha, CONTEXT_REFUSED)
    run_id = env.get('GITHUB_RUN_ID', '')
    endpoint = run_endpoint(run_id)
    repository = api.get_json(GH_REPO)
    environment = api.get_json(GH_ENV)
    branches = api.get_json(GH_ENV + '/deployment-branch-policies')
    policy_code = 'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED'
    try:
        policy_ready(repository, environment, branches)
        reviewers = next(rule['reviewers'] for rule in environment['protection_rules']
                         if rule['type'] == 'required_reviewers')
        need(matches(repository, REPOSITORY) and matches(repository.get('owner'), OWNER)
             and matches(environment, ENVIRONMENT) and matches(reviewers[0]['reviewer'], OWNER)
             and matches(branches, {'total_count': 1}), policy_code)
    except (Refused, KeyError, TypeError, AttributeError, StopIteration):
        raise Refused(policy_code) from None
    branch = api.get_json(MAIN)
    workflow = api.get_json(WORKFLOW_ENDPOINT)
    run = api.get_json(endpoint)
    need(matches(branch, {'name': 'main', 'protected': True})
         and matches(branch.get('commit'), {'sha': sha})
         and matches(workflow, {'path': WORKFLOW, 'state': 'active'})
         and type(workflow.get('id')) is int and workflow['id'] > 0
         and matches(run, {'id': int(run_id), 'head_sha': sha, 'head_branch': 'main', 'path': WORKFLOW,
                           'workflow_id': workflow['id'], 'run_attempt': 1, 'event': 'workflow_dispatch',
                           'status': 'in_progress'})
         and all(matches(run.get(key), OWNER) for key in ('actor', 'triggering_actor'))
         and all(matches(run.get(key), REPOSITORY) for key in ('repository', 'head_repository')), RUN_REFUSED)
    approvals = api.get_json(endpoint + '/approvals')
    need(type(approvals) is list and len(approvals) == 1, APPROVAL_REFUSED)
    approval = approvals[0]
    need(matches(approval, {'state': 'approved'}) and matches(approval.get('user'), OWNER)
         and type(approval.get('environments')) is list and len(approval['environments']) == 1
         and matches(approval['environments'][0], ENVIRONMENT), APPROVAL_REFUSED)
    return dict(scope=dict(SCOPE), run=_run(sha, REFERENCE_SITE_SHA, run_id, 1, OWNER['login'], OWNER['login']),
                control_sha=sha)


@dataclass(frozen=True)
class Package:
    archive: bytes
    pins: tuple


def public_producer_ready(data):
    for node in ast.parse(data).body:
        if isinstance(node, ast.FunctionDef) and node.name == 'collect_control':
            args = node.args
            return ([arg.arg for arg in args.args] == ['context', 'staging', 'deadline_ns']
                    and not (args.posonlyargs or args.kwonlyargs or args.defaults or args.vararg or args.kwarg))
    return False


def build_package(root):
    try:
        stream, pins = io.BytesIO(), []
        with ZipFile(stream, 'w') as archive:
            for member, source in ZIP_RECIPE:
                data = _read_regular(root / source, 128 * 1024)
                need(data, BUNDLE_REFUSED)
                if source == 'test_db_runtime_producer.py':
                    need(public_producer_ready(data), BUNDLE_REFUSED)
                info = ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100444 << 16
                archive.writestr(info, data)
                pins.append((member, len(data), sha256(data).hexdigest()))
        bundle = stream.getvalue()
        need(0 < len(bundle) <= 512 * 1024, BUNDLE_REFUSED)
        return Package(bundle, tuple(pins))
    except (OSError, SyntaxError, Refused):
        raise Refused(BUNDLE_REFUSED) from None


def root_program(nonce, context, package):
    # The transport runs this fixed evaluator with the reviewed public inputs.
    encoded = base64.b64encode(bz2.compress(package.archive))
    schema = '\n'.join(f'{name}={value!r}' for name, value in dict(
        VERSION=VERSION, STAGES=STAGES, REASONS=REASONS, FD_REASONS=FD_REASONS, REPORT_FIELDS=REPORT_FIELDS,
    ).items())
    source = '\n'.join((inspect.getsource(staging), inspect.getsource(capsule), schema,
                        inspect.getsource(canonical), inspect.getsource(report_valid),
                        f'print(canonical(root_receipt({nonce!r},{context!r},{encoded!r},'
                        f'{len(package.archive)},{sha256(package.archive).hexdigest()!r},{package.pins!r})).decode("ascii"),end="")'))
    need(source.isascii() and len(source) <= MAX_CHILD, BUNDLE_REFUSED)
    return source


def verify_package(source_dir):
    """Import the complete producer from the sealed archive, without running it."""
    package = build_package(source_dir)
    context = dict(scope=SCOPE, control_sha='a' * 40,
                   run=_run('a' * 40, REFERENCE_SITE_SHA, '9' * 15, 1, RUN_ACTOR, RUN_ACTOR))
    root_program('0' * 32, context, package)
    with ExitStack() as resources:
        archive = capsule.archive_descriptor(resources, package.archive)
        smoke = ('import sys; sys.path.insert(0,sys.argv[1]); '
                 'from test_db_runtime_producer import collect_control; '
                 'import test_db_runtime_preentry; assert callable(collect_control)')
        subprocess.run(['/usr/bin/python3', '-I', '-B', '-S', '-c', smoke, '/proc/self/fd/' + str(archive)],
                       pass_fds=(archive,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=3, check=True)


def project_remote(raw, nonce, context):
    try:
        need(type(raw) is bytes and 0 < len(raw) <= 4096, RECEIPT_REFUSED)
        outer = strict_json(raw.decode('ascii'))
        need(matches(outer, {'version': 'jsm-test-installed-route-outer-v2', 'nonce': nonce, 'principal': 'marinagurina'})
             and set(outer) == {'version', 'nonce', 'principal', 'euid', 'root_diagnostic'}
             and type(outer['euid']) is int and outer['euid'] > 0, RECEIPT_REFUSED)
        child = outer['root_diagnostic']
        need(matches(child, {'version': VERSION, 'nonce': nonce, 'euid': 0, 'context_sha256': digest(context)})
             and set(child) == {'version', 'nonce', 'euid', 'context_sha256', 'report', 'cleanup', 'transport_reason'},
             RECEIPT_REFUSED)
        reason, report, cleanup = child['transport_reason'], child['report'], child['cleanup']
        if reason is None:
            need(cleanup == 'VERIFIED' and report_valid(report) and report['fastcgi_state'] != 'UNCONFIRMED',
                 RECEIPT_REFUSED)
            status = report['status']
        else:
            required_cleanup = ('UNCONFIRMED' if reason == 'STAGING_CLEANUP_UNCONFIRMED' else
                                'VERIFIED' if reason == 'CAPSULE_DEADLINE' else 'NOT_NEEDED')
            need(reason in CAPSULE_FAILURES and cleanup == required_cleanup
                 and (report is None or cleanup == 'UNCONFIRMED' and report_valid(report)), RECEIPT_REFUSED)
            status = 'BLOCKED'
            if report is None:
                report = dict(sql='UNKNOWN' if cleanup == 'UNCONFIRMED' else 'NOT_ATTEMPTED',
                              configured_runtime='NOT_ESTABLISHED', local_peer='NOT_ESTABLISHED')
        return dict(version=VERSION, scope=context['scope'], github_run=context['run']['id'], status=status,
                    reviewed_control_sha=context['control_sha'], reference_site_sha=REFERENCE_SITE_SHA,
                    db_isolation='NOT_ESTABLISHED', transport_reason=reason, cleanup=cleanup,
                    **{key: value for key, value in report.items() if key != 'status'})
    except (ValueError, TypeError, Refused):
        raise Refused(RECEIPT_REFUSED) from None


def collect(api, env, source_dir):
    deadline = time.monotonic() + OVERALL_SECONDS
    context = authorize(api, env)
    package = build_package(source_dir)
    root_program('0' * 32, context, package)  # Refuse oversize before transport.
    raw, nonce = _receive(env, deadline, lambda challenge: root_program(challenge, context, package))
    return project_remote(raw, nonce, context)


def main():
    source_dir = Path(__file__).resolve().parent
    if sys.argv[1:] == ['--verify-package']:
        try:
            verify_package(source_dir)
        except Exception:
            print(BUNDLE_REFUSED)
            return 1
        print('TEST_CONTROL_PACKAGE_VERIFIED')
        return 0
    try:
        need(len(sys.argv) == 1, CONTEXT_REFUSED)
        token = os.environ.pop('REPORT_GITHUB_TOKEN', '')
        need(re.fullmatch('[!-~]{1,4096}', token), CONTEXT_REFUSED)
        api = _GitHubGet(api_paths(os.environ.get('GITHUB_RUN_ID', '')), token)
        result = collect(api, os.environ, source_dir)
        print(canonical(result).decode('ascii'), end='')
        return int(result['status'] != 'OBSERVED')
    except Exception as error:
        public = (CONTEXT_REFUSED, RUN_REFUSED, APPROVAL_REFUSED, BUNDLE_REFUSED, RECEIPT_REFUSED,
                  'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED', 'GITHUB_GET_STATUS_REFUSED',
                  'TEST_SSH_KEY_NOT_CONFIGURED', 'EXACT_TEST_HOST_PIN_REQUIRED', 'SSH_TRANSPORT_NOT_CONFIRMED')
        reason = 'CONTROL_REPORT_REFUSED'
        if isinstance(error, Refused) and len(error.args) == 1 and error.args[0] in public:
            reason = error.args[0]
    print(canonical(dict(version=VERSION, status='BLOCKED', reason=reason,
                         db_isolation='NOT_ESTABLISHED')).decode('ascii'), end='')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
