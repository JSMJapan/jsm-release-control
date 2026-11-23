"""Verify the protected GitHub launch and collect a closed TEST metadata receipt."""
import ast
from dataclasses import dataclass
from hashlib import sha256
import inspect
import io
import os
from pathlib import Path
import re
import sys
import time
from zipfile import ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _GitHubGet, _read_regular, need, strict_json
from hostinger_preflight import policy_ready
from test_db_installer_receipt import _run
from test_db_runtime_control_contract import (
    ENVIRONMENT_NAME, REFERENCE_SITE_SHA, REPO, RUN_ACTOR, SCOPE, VERSION, WORKFLOW, canonical, digest, report_valid,
)
from test_installer_capture_encrypted import GH_ENV, GH_REPO, OVERALL_SECONDS, _receive
import test_installer_publisher_guard as guard


WORKFLOW_ENDPOINT = GH_REPO + '/actions/workflows/' + WORKFLOW.rsplit('/', 1)[1]
MAIN = GH_REPO + '/branches/main'
OWNER = {'id': 327623967, 'login': RUN_ACTOR}
REPOSITORY = {'id': 1427965640, 'full_name': REPO, 'private': False}
ENVIRONMENT = {'id': 26702164832, 'name': ENVIRONMENT_NAME}
FIXED_ENV = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR=OWNER['login'], GITHUB_TRIGGERING_ACTOR=OWNER['login'],
                 GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                 GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                 GITHUB_JOB='report', GITHUB_WORKFLOW_REF=REPO + '/' + WORKFLOW + '@refs/heads/main')
ARCHIVE_PATH = '/usr/local/libexec/jsm-test-db-control-report.pyz'
PYTHON_FILES = (
    'test_db_runtime_control_entry.py', 'test_db_runtime_control_contract.py', 'test_db_runtime_producer.py', 'test_db_runtime_protocol.py',
    'test_db_runtime_fastcgi.py', 'test_db_runtime_kernel.py', 'test_db_runtime_proc.py',
    'test_db_installer_receipt.py', 'apache_parity_bridge.py', 'hostinger_preflight.py',
    'test_db_os_metadata.py', 'test_db_php_endpoint.py', 'test_db_docker_metadata.py',
    'test_db_docker_binding.py', 'test_php_manifest_readonly.py', 'test_installer_capture_encrypted.py',
    'test_installer_capture_capsule.py', 'test_api_installed_route_readonly.py', 'test_api_readonly_access.py',
)
PHP_FILES = ('test_db_runtime_entry.php', 'test_db_runtime_probe.php', 'test_db_runtime_pdo.php',
             'test_db_runtime_php_channel.php', 'test_db_runtime_startup.php')
ZIP_RECIPE = (('__main__.py', PYTHON_FILES[0]),) + tuple((name, name) for name in PYTHON_FILES[1:])
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


def build_package(root):
    try:
        stream = io.BytesIO()
        with ZipFile(stream, 'w') as archive:
            for member, source in ZIP_RECIPE:
                data = _read_regular(root / source, 128 * 1024)
                need(data, BUNDLE_REFUSED)
                if source == 'test_db_runtime_producer.py':
                    functions = ast.parse(data).body
                    need(any(isinstance(node, ast.FunctionDef) and node.name == 'collect_control'
                             for node in functions), BUNDLE_REFUSED)
                info = ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100444 << 16
                archive.writestr(info, data)
        bundle = stream.getvalue()
        pins = [(ARCHIVE_PATH, len(bundle), sha256(bundle).hexdigest())]
        for name in PHP_FILES:
            data = _read_regular(root / name, 128 * 1024)
            need(data, BUNDLE_REFUSED)
            pins.append(('/usr/local/libexec/' + name, len(data), sha256(data).hexdigest()))
        return Package(bundle, tuple(pins))
    except (OSError, SyntaxError, Refused):
        raise Refused(BUNDLE_REFUSED) from None


def root_program(nonce, context, pins):
    """Read the fixed root-owned payload under the deploy lock and run its validated inode."""
    header = ('import fcntl,json,os,selectors,stat,subprocess,sys,time\n'
              'from contextlib import contextmanager,ExitStack\nfrom hashlib import sha256\n')
    guard_code = '\n'.join(inspect.getsource(item) for item in (
        guard.GuardRefused, guard.stamp, guard.trusted, guard.open_trusted_file, guard.fingerprint, report_valid,
    ))
    constants = f'\nlock_path={guard.LOCK!r}\npins={pins!r}\ncontext={canonical(context)!r}\nnonce={nonce!r}\nversion={VERSION!r}\n'
    return header + guard_code + constants + r'''
def pairs(rows):
    result = dict(rows)
    if len(result) != len(rows):
        raise ValueError()
    return result

def run():
    if os.geteuid() != 0:
        raise GuardRefused()
    deadline = time.monotonic() + 3.6
    with ExitStack() as stack:
        lock, check = stack.enter_context(open_trusted_file(lock_path))
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        files = [stack.enter_context(open_trusted_file(path, size=size)) for path, size, _ in pins]
        for (file, _), (_, size, expected) in zip(files, pins):
            if fingerprint(file, size) != expected:
                raise GuardRefused()
        check()
        for _, verify in files:
            verify()
        archive = files[0][0]
        with subprocess.Popen(['/usr/bin/python3','-I','-B','-S','/proc/self/fd/'+str(archive)],
                              pass_fds=(archive,), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env={'PATH':'/usr/bin:/bin','LANG':'C'}) as process:
            try:
                process.stdin.write(context)
                process.stdin.close()
                raw = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        left = deadline - time.monotonic()
                        if left <= 0 or not selector.select(left):
                            raise GuardRefused()
                        data = os.read(process.stdout.fileno(), 4097-len(raw))
                        if not data:
                            break
                        raw.extend(data)
                        if len(raw) > 4096:
                            raise GuardRefused()
                if process.wait(timeout=max(0, deadline-time.monotonic())) != 0:
                    raise GuardRefused()
            finally:
                if process.poll() is None:
                    process.kill()
        report = json.loads(raw.decode('ascii'), object_pairs_hook=pairs)
        if not report_valid(report):
            raise GuardRefused()
        return report

try:
    report = run()
except Exception:
    report = None
print(json.dumps(dict(version=version, nonce=nonce, euid=os.geteuid(),
                      context_sha256=sha256(context).hexdigest(), report=report), sort_keys=True))
'''


def project_remote(raw, nonce, context):
    try:
        need(type(raw) is bytes and 0 < len(raw) <= 4096, RECEIPT_REFUSED)
        outer = strict_json(raw.decode('ascii'))
        need(matches(outer, {'version': 'jsm-test-installed-route-outer-v2', 'nonce': nonce, 'principal': 'marinagurina'})
             and set(outer) == {'version', 'nonce', 'principal', 'euid', 'root_diagnostic'}
             and type(outer['euid']) is int and outer['euid'] > 0, RECEIPT_REFUSED)
        child = outer['root_diagnostic']
        need(matches(child, {'version': VERSION, 'nonce': nonce, 'euid': 0, 'context_sha256': digest(context)})
             and set(child) == {'version', 'nonce', 'euid', 'context_sha256', 'report'}
             and report_valid(child['report']), RECEIPT_REFUSED)
        return dict(version=VERSION, scope=context['scope'], github_run=context['run']['id'],
                    reviewed_control_sha=context['control_sha'], reference_site_sha=REFERENCE_SITE_SHA,
                    db_isolation='NOT_ESTABLISHED', **child['report'])
    except (ValueError, TypeError, Refused):
        raise Refused(RECEIPT_REFUSED) from None


def collect(api, env, source_dir):
    deadline = time.monotonic() + OVERALL_SECONDS
    context = authorize(api, env)
    package = build_package(source_dir)
    raw, nonce = _receive(env, deadline, lambda challenge: root_program(challenge, context, package.pins))
    return project_remote(raw, nonce, context)


def main():
    try:
        need(len(sys.argv) == 1, CONTEXT_REFUSED)
        token = os.environ.pop('REPORT_GITHUB_TOKEN', '')
        need(re.fullmatch('[!-~]{1,4096}', token), CONTEXT_REFUSED)
        api = _GitHubGet(api_paths(os.environ.get('GITHUB_RUN_ID', '')), token)
        result = collect(api, os.environ, Path(__file__).resolve().parent)
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
