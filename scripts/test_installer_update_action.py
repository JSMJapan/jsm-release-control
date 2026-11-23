#!/usr/bin/env python3
"""GitHub-only client for the dedicated TEST installer writer."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _bounded, _GitHubGet, strict_json
from hostinger_preflight import policy_ready
from test_api_readonly_access import PIN_SHA256, need, private_file
from test_installer_update_package import OPERATIONS, PROTOCOL, STATUSES

REPO = 'JSMJapan/jsm-release-control'
ENVIRONMENT = 'test-installer-write'
WORKFLOW = 'test-installer-update.yml'
REPO_ENDPOINT = '/repos/' + REPO
ENV_ENDPOINT = REPO_ENDPOINT + '/environments/' + ENVIRONMENT
BRANCH_ENDPOINT = ENV_ENDPOINT + '/deployment-branch-policies'
MAIN_ENDPOINT = REPO_ENDPOINT + '/branches/main'
TARGET = 'gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713'
RESULTS = {
    'CHECK': frozenset(('READY', 'ALREADY_APPLIED')),
    'APPLY': frozenset(('APPLIED', 'ALREADY_APPLIED')),
    'ROLLBACK': frozenset(('ROLLED_BACK', 'ALREADY_ORIGINAL')),
}
SUCCESSES = frozenset().union(*RESULTS.values())
SAFE_ERRORS = STATUSES | {
    'OWNER_MAIN_CONTEXT_REQUIRED', 'EXACT_OPERATION_APPROVAL_REQUIRED',
    'PROTECTED_WRITER_POLICY_REQUIRED', 'DEDICATED_WRITER_NOT_PROVISIONED',
    'EXACT_TEST_HOST_PIN_REQUIRED', 'WRITER_TRANSPORT_REFUSED', 'WRITER_RECEIPT_REFUSED',
}


def context(env):
    fixed = {
        'GITHUB_REPOSITORY': REPO,
        'GITHUB_ACTOR': 'JSMJapan',
        'GITHUB_TRIGGERING_ACTOR': 'JSMJapan',
        'GITHUB_REF': 'refs/heads/main',
        'GITHUB_EVENT_NAME': 'workflow_dispatch',
        'GITHUB_RUN_ATTEMPT': '1',
        'GITHUB_SERVER_URL': 'https://github.com',
        'GITHUB_API_URL': 'https://api.github.com',
        'GITHUB_WORKFLOW_REF': REPO + '/.github/workflows/' + WORKFLOW + '@refs/heads/main',
    }
    sha = env.get('GITHUB_SHA', '')
    run = env.get('GITHUB_RUN_ID', '')
    need(all(env.get(key) == value for key, value in fixed.items())
         and re.fullmatch('[0-9a-f]{40}', sha) and env.get('GITHUB_WORKFLOW_SHA') == sha
         and re.fullmatch('[1-9][0-9]{0,14}', run), 'OWNER_MAIN_CONTEXT_REQUIRED')
    operation = env.get('INSTALLER_OPERATION')
    need(env.get('APPROVED_WORKFLOW_SHA') == sha and operation in OPERATIONS,
         'EXACT_OPERATION_APPROVAL_REQUIRED')
    return operation


def require_protected_writer(api, approved_sha):
    try:
        repository = api.get_json(REPO_ENDPOINT)
        environment = api.get_json(ENV_ENDPOINT)
        branches = api.get_json(BRANCH_ENDPOINT)
        policy_ready(repository, environment, branches)
        main = api.get_json(MAIN_ENDPOINT)
        need(main.get('name') == 'main' and main.get('protected') is True
             and main['commit']['sha'] == approved_sha, 'PROTECTED_WRITER_POLICY_REQUIRED')
        rules = [r for r in environment['protection_rules'] if r.get('type') == 'required_reviewers']
        reviewers = rules[0]['reviewers']
        need(environment.get('name') == ENVIRONMENT
             and len(rules) == 1 and len(reviewers) == 1
             and type(reviewers[0]['reviewer']['id']) is int
             and reviewers[0]['reviewer']['id'] == 327623967,
             'PROTECTED_WRITER_POLICY_REQUIRED')
    except Exception:
        raise Refused('PROTECTED_WRITER_POLICY_REQUIRED') from None


def parse_receipt(code, raw, operation):
    try:
        need(type(code) is int and code in (0, 1) and type(raw) is bytes and 0 < len(raw) <= 512,
             'WRITER_RECEIPT_REFUSED')
        value = strict_json(raw.decode('ascii'))
        need(type(value) is dict and set(value) == {'version', 'status'} and value['version'] == PROTOCOL,
             'WRITER_RECEIPT_REFUSED')
        canonical = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        need(canonical == raw, 'WRITER_RECEIPT_REFUSED')
        state = value['status']
        need(type(state) is str and state in STATUSES and (code == 0) == (state in RESULTS[operation])
             and (code == 0 or state not in SUCCESSES), 'WRITER_RECEIPT_REFUSED')
        return state
    except Exception:
        raise Refused('WRITER_RECEIPT_REFUSED') from None


def run_writer(env, operation):
    key = env.get('TEST_INSTALLER_WRITE_SSH_KEY')
    known = env.get('TEST_INSTALLER_WRITE_KNOWN_HOSTS')
    need(type(key) is str and 0 < len(key) <= 16384 and '\0' not in key, 'DEDICATED_WRITER_NOT_PROVISIONED')
    need(type(known) is str and len(known) <= 16384 and hashlib.sha256(known.encode()).hexdigest() == PIN_SHA256,
         'EXACT_TEST_HOST_PIN_REQUIRED')
    request = (json.dumps({'version': PROTOCOL, 'operation': operation},
                          sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    with tempfile.TemporaryDirectory(prefix='jsm-test-installer-write-') as folder:
        identity, hosts = Path(folder) / 'identity', Path(folder) / 'known_hosts'
        private_file(identity, key.replace('\r\n', '\n').rstrip('\n') + '\n')
        private_file(hosts, known)
        command = [
            '/usr/bin/ssh', '-F', '/dev/null', '-T', '-i', str(identity), '-p', '22',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'UserKnownHostsFile=' + str(hosts), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=7', '-o', 'ConnectionAttempts=1', '-o', 'LogLevel=ERROR',
            'jsmtestinstall@34.104.157.63', PROTOCOL,
        ]
        try:
            code, raw = _bounded(command, data=request, limit=512, timeout=20)
        except Exception:
            raise Refused('WRITER_TRANSPORT_REFUSED') from None
    need(code in (0, 1), 'WRITER_TRANSPORT_REFUSED')
    return parse_receipt(code, raw, operation)


def collect(api, env):
    operation = context(env)
    require_protected_writer(api, env['GITHUB_SHA'])
    return operation, run_writer(env, operation)


def main():
    result = dict(version=PROTOCOL, target=TARGET, status='BLOCKED', report='NOT_VERIFIED',
                  db_isolation='NOT_ESTABLISHED')
    try:
        need(len(sys.argv) == 1, 'OWNER_MAIN_CONTEXT_REQUIRED')
        context(os.environ)
        result['workflow_sha'] = os.environ['GITHUB_SHA']
        operation, status = collect(_GitHubGet((REPO_ENDPOINT, ENV_ENDPOINT, BRANCH_ENDPOINT, MAIN_ENDPOINT)), os.environ)
        result.update(operation=operation, status=status)
        passed = status in RESULTS[operation]
    except Exception as error:
        code = error.args[0] if isinstance(error, Refused) and len(error.args) == 1 else None
        result['reason'] = code if type(code) is str and code in SAFE_ERRORS else 'WRITER_REFUSED'
        passed = False
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
