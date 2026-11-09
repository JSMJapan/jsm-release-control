#!/usr/bin/env python3
"""Fixed GitHub-only TEST SSH/sudo identity observation; no application probe.

Provider metadata binds this IP to VM150919059249400713 in dark-berm-508215-d2,
asia-northeast1-a. The host pin preserves the existing GitHub trust anchor; it
does not establish new out-of-band trust. Only an existing approved key is used.
OS account lookup and SSH/sudo audit bookkeeping may occur. Application/config,
environment, database and customer-data files are not inspected or modified.
Successful identity observation does not establish API/deployment acceptance.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _GitHubGet, _bounded, strict_json
from hostinger_preflight import policy_ready

REPO = 'JSMJapan/jsm-release-control'
ENVIRONMENT = 'test-api-readonly-access'
GH_REPO = '/repos/' + REPO
GH_ENV = GH_REPO + '/environments/' + ENVIRONMENT
GH_PATHS = frozenset((GH_REPO, GH_ENV, GH_ENV + '/deployment-branch-policies'))
PIN_SHA256 = '6a5628d0d920e05409ac9f28e8280fbfc46cf914d7f40b4a4265a7e25981cb3d'
VERSION = 'jsm-test-access-v1'
CHILD_VERSION = 'jsm-test-sudo-identity-v1'
MAX_OUTPUT = 4096
OVERALL_SECONDS = 60
SAFE_REASONS = frozenset(('OWNER_MANUAL_MAIN_TEST_WORKFLOW_REQUIRED', 'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED',
    'TEST_SSH_KEY_NOT_CONFIGURED', 'EXACT_TEST_HOST_PIN_REQUIRED', 'NONCE_REQUIRED',
    'SSH_TRANSPORT_NOT_CONFIRMED', 'REMOTE_IDENTITY_SCHEMA_REJECTED', 'OVERALL_DEADLINE',
    'NO_ARGUMENTS_OR_INPUTS_ACCEPTED', 'SUDO_ROOT_IDENTITY_NOT_CONFIRMED',
    'FIXED_GITHUB_GET_SCOPE_REQUIRED', 'GITHUB_READ_DEADLINE', 'GITHUB_SOCKET_REQUIRED',
    'GITHUB_GET_STATUS_REFUSED', 'GITHUB_JSON_CONTENT_TYPE_REQUIRED', 'GITHUB_ENCODING_REFUSED',
    'GITHUB_RESPONSE_LIMIT', 'GITHUB_RESPONSE_LENGTH_MISMATCH', 'GITHUB_TRANSPORT_OR_SCHEMA_REFUSED',
    'DUPLICATE_JSON_FIELD', 'JSON_CONSTANT_REFUSED', 'JSON_RESPONSE_REFUSED',
    'PRIVATE_PROCESS_DEADLINE', 'PRIVATE_PROCESS_OUTPUT_LIMIT'))
FAILURE_STAGES = frozenset(('policy_repository', 'policy_environment', 'policy_branches',
                           'credentials', 'host_pin', 'ssh_transport', 'remote_identity', 'unknown'))
REASON_STAGES = {'TEST_SSH_KEY_NOT_CONFIGURED': 'credentials', 'EXACT_TEST_HOST_PIN_REQUIRED': 'host_pin',
                 'SSH_TRANSPORT_NOT_CONFIRMED': 'ssh_transport', 'REMOTE_IDENTITY_SCHEMA_REJECTED': 'remote_identity'}


def _safe_reason(error):
    code = error.args[0] if isinstance(error, Refused) and len(error.args) == 1 else None
    return code if type(code) is str and code in SAFE_REASONS else 'TEST_ACCESS_PROBE_REJECTED'


class _ProbeFailure(Refused):
    def __init__(self, stage, error):
        super().__init__(_safe_reason(error))
        self.failure_stage = stage if stage in FAILURE_STAGES else 'unknown'


def _at_stage(stage, operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except Exception as error:
        raise _ProbeFailure(stage, error) from None


def _python_version():
    value = '.'.join(str(part) for part in sys.version_info[:3])
    return value if re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', value) else 'unknown'


def need(condition, code):
    if not condition:
        raise Refused(code)


def context_ready(env):
    fixed = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
                 GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                 GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                 GITHUB_WORKFLOW_REF=REPO + '/.github/workflows/test-api-readonly-access.yml@refs/heads/main')
    need(all(env.get(name) == value for name, value in fixed.items())
         and type(env.get('GITHUB_SHA')) is str and re.fullmatch('[0-9a-f]{40}', env['GITHUB_SHA'])
         and env.get('GITHUB_WORKFLOW_SHA') == env['GITHUB_SHA']
         and type(env.get('GITHUB_RUN_ID')) is str and re.fullmatch('[0-9]{1,15}', env['GITHUB_RUN_ID']),
         'OWNER_MANUAL_MAIN_TEST_WORKFLOW_REQUIRED')


class TestPolicyApi(_GitHubGet):
    def __init__(self):
        super().__init__(GH_PATHS)  # Exactly three public policy GETs, no auth or provider origin.


def _nonce_ready(nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'NONCE_REQUIRED')


def remote_program(nonce):
    _nonce_ready(nonce)
    # A root-owned GNU timeout bounds the tiny root child's lifetime even when
    # the unprivileged outer process cannot signal it. No shell/fallback exists.
    child = "import json,os;print(json.dumps(dict(version='jsm-test-sudo-identity-v1',nonce='" + nonce + "',euid=os.geteuid()),sort_keys=True))"
    program = r'''
import json,os,pwd,selectors,signal,subprocess,time
nonce='@NONCE@'
def pairs(rows):
    result={}
    for key,value in rows:
        if key in result: raise ValueError()
        result[key]=value
    return result
def invalid(value): raise ValueError()
euid=os.geteuid()
principal=pwd.getpwuid(euid).pw_name
identity=None
process=None
deadline=time.monotonic()+5
try:
    process=subprocess.Popen(['/usr/bin/sudo','-n','/usr/bin/timeout','--signal=TERM','--kill-after=1','4',
        '/usr/bin/python3','-I','-B','-S','-c',@CHILD@],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,start_new_session=True,env={'PATH':'/usr/bin:/bin','LANG':'C'})
    output=bytearray()
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout,selectors.EVENT_READ)
        while True:
            remaining=deadline-time.monotonic()-.1
            if remaining<=0: raise ValueError()
            for key,_ in ready.select(min(.1,remaining)):
                chunk=os.read(key.fileobj.fileno(),min(512+1-len(output),512))
                if not chunk:
                    remaining=deadline-time.monotonic()-.1
                    if remaining<=0 or process.wait(timeout=remaining)!=0: raise ValueError()
                    value=json.loads(output.decode('ascii'),object_pairs_hook=pairs,parse_constant=invalid)
                    if (type(value) is not dict or set(value)!={'version','nonce','euid'}
                        or value['version']!='jsm-test-sudo-identity-v1' or value['nonce']!=nonce
                        or type(value['euid']) is not int or not 0<=value['euid']<=4294967295): raise ValueError()
                    identity=value
                    break
                output.extend(chunk)
                if len(output)>512: raise ValueError()
            else: continue
            break
except Exception:
    identity=None
finally:
    if process is not None:
        if process.poll() is None:
            try: os.killpg(process.pid,signal.SIGKILL)
            except OSError: pass
            remaining=deadline-time.monotonic()
            if remaining>0:
                try: process.wait(timeout=remaining)
                except subprocess.TimeoutExpired: pass
        process.stdout.close()
print(json.dumps(dict(version='jsm-test-access-v1',nonce=nonce,principal=principal,euid=euid,sudo_identity=identity),sort_keys=True))
'''
    return program.replace('@NONCE@', nonce).replace('@CHILD@', repr(child)).encode('ascii')


def project_remote(raw, nonce):
    _nonce_ready(nonce)
    try:
        need(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT, 'REMOTE_IDENTITY_SCHEMA_REJECTED')
        value = strict_json(raw.decode('ascii'))
        need(type(value) is dict and set(value) == {'version', 'nonce', 'principal', 'euid', 'sudo_identity'}
             and value['version'] == VERSION and value['nonce'] == nonce and value['principal'] == 'marinagurina'
             and type(value['euid']) is int and 0 <= value['euid'] <= 4294967295, 'REMOTE_IDENTITY_SCHEMA_REJECTED')
        child = value['sudo_identity']
        child_valid = (type(child) is dict and set(child) == {'version', 'nonce', 'euid'}
                       and child['version'] == CHILD_VERSION and child['nonce'] == nonce
                       and type(child['euid']) is int and 0 <= child['euid'] <= 4294967295)
        return dict(ssh_identity=True, ssh_principal='marinagurina', ssh_euid=value['euid'],
                    sudo_root_identity=child['euid'] == 0 if child_valid else None)
    except Exception:
        raise Refused('REMOTE_IDENTITY_SCHEMA_REJECTED') from None


def private_file(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        output.write(value)


def collect(api, env):
    deadline = time.monotonic() + OVERALL_SECONDS
    context_ready(env)  # Before all network/credential access.
    repo = _at_stage('policy_repository', api.get_json, GH_REPO)
    environment = _at_stage('policy_environment', api.get_json, GH_ENV)
    branches = _at_stage('policy_branches', api.get_json, GH_ENV + '/deployment-branch-policies')
    try:
        policy_ready(repo, environment, branches)  # Unchanged shared pure guard.
        reviewer = environment['protection_rules']
        reviewer = [row for row in reviewer if row.get('type') == 'required_reviewers'][0]['reviewers'][0]['reviewer']
        need(environment.get('name') == ENVIRONMENT and type(reviewer.get('id')) is int
             and reviewer['id'] == 327623967 and type(branches.get('total_count')) is int
             and branches['total_count'] == 1, 'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED')
    except Exception:
        raise _ProbeFailure('policy_environment', Refused('PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED')) from None
    key = env.get('TEST_API_ADMIN_SSH_KEY')
    known = env.get('TEST_API_KNOWN_HOSTS')
    need(type(key) is str and 0 < len(key) <= 16384 and '\x00' not in key, 'TEST_SSH_KEY_NOT_CONFIGURED')
    need(type(known) is str and len(known) <= 16384
         and hashlib.sha256(known.encode('utf-8')).hexdigest() == PIN_SHA256, 'EXACT_TEST_HOST_PIN_REQUIRED')
    nonce = secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='jsm-test-access-') as folder:
        os.chmod(folder, 0o700)
        identity, hosts = Path(folder) / 'identity', Path(folder) / 'known_hosts'
        private_file(identity, key.replace('\r\n', '\n').rstrip('\n') + '\n')
        private_file(hosts, known)  # Exact pin bytes; no keyscan, TOFU, DNS or alternate destination.
        command = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-i', str(identity), '-p', '22',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'UserKnownHostsFile=' + str(hosts), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=7', '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=3',
            '-o', 'ServerAliveCountMax=2', '-o', 'LogLevel=ERROR',
            'marinagurina@34.104.157.63', '/usr/bin/python3', '-I', '-B', '-S', '-']
        budget = min(15, deadline - time.monotonic() - 2)  # Shared deadline, bounded kill/reap and receipt reserve.
        need(budget > 0, 'OVERALL_DEADLINE')
        code, raw = _at_stage('ssh_transport', _bounded, command, data=remote_program(nonce), limit=MAX_OUTPUT, timeout=budget)
        need(code == 0, 'SSH_TRANSPORT_NOT_CONFIRMED')
        observed = _at_stage('remote_identity', project_remote, raw, nonce)
    confirmed = observed['sudo_root_identity'] is True
    return dict(observed, status='TEST_ACCESS_IDENTITY_CONFIRMED' if confirmed else 'BLOCKED',
        reason='FIXED_IDENTITY_CONFIRMED' if confirmed else 'SUDO_ROOT_IDENTITY_NOT_CONFIRMED',
        failure_stage=None if confirmed else 'remote_identity',
        resource='gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713',
        project='dark-berm-508215-d2', zone='asia-northeast1-a', vm_id='150919059249400713',
        ip='34.104.157.63', ssh_port=22, known_hosts_sha256=PIN_SHA256,
        source_sha=env['GITHUB_SHA'], workflow_run_url='https://github.com/' + REPO + '/actions/runs/' + env['GITHUB_RUN_ID'],
        application_config_data_access='NOT_PERFORMED', provider_mutations='NOT_PERFORMED',
        test_api_acceptance='NOT_ESTABLISHED')


def main():
    def expired(*_):
        raise Refused('OVERALL_DEADLINE')
    try:
        need(len(sys.argv) == 1, 'NO_ARGUMENTS_OR_INPUTS_ACCEPTED')
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS)  # Includes DNS, headers, files and subprocess.
        result = collect(TestPolicyApi(), os.environ)
        result['verified_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        result['python_version'] = _python_version()
        print(json.dumps(result, sort_keys=True))
        return 0 if result['status'] == 'TEST_ACCESS_IDENTITY_CONFIRMED' else 1
    except Exception as error:
        reason = _safe_reason(error)
        stage = getattr(error, 'failure_stage', REASON_STAGES.get(reason, 'unknown'))
        stage = stage if type(stage) is str and stage in FAILURE_STAGES else 'unknown'
        print(json.dumps(dict(status='BLOCKED', reason=reason, ssh_identity=None, ssh_principal=None,
            ssh_euid=None, sudo_root_identity=None, failure_stage=stage, python_version=_python_version(),
            application_config_data_access='NOT_PERFORMED',
            provider_mutations='NOT_PERFORMED', test_api_acceptance='NOT_ESTABLISHED'), sort_keys=True))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    raise SystemExit(main())
