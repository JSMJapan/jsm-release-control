#!/usr/bin/env python3
"""Separate GitHub-only bootstrap for the restricted TEST writer."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _GitHubGet, _read_regular, strict_json
from test_installer_capture_encrypted import (
    GH_ENV, GH_REPO, OVERALL_SECONDS, REPO, TARGET, _receive, need, verify_policy,
)
from test_installer_update_action import (
    BRANCH_ENDPOINT, ENV_ENDPOINT, MAIN_ENDPOINT, require_protected_writer,
)
from test_installer_receiver_bootstrap_host import HOST_SOURCE

WORKFLOW = 'test-installer-receiver-bootstrap.yml'
VERSION = 'jsm-test-installer-bootstrap-v1'
SCOPE = 'INSTALL_SCOPED_TEST_WRITER'
PUBLIC_SHA256 = '96c9c617a2c306227515dd9f841278992beaf5229c96e26536c353c5633559b3'
FILES = {
    'receiver.py': 'test_installer_update_receiver.py',
    'package.py': 'test_installer_update_package.py',
    'forced_command.sh': 'test_installer_update_forced_command.sh',
}
STATUSES = frozenset((
    'BOOTSTRAPPED', 'TARGET_REFUSED', 'INPUT_REFUSED', 'PREEXISTING_REFUSED',
    'BOOTSTRAP_FAILED', 'STATE_UNCERTAIN',
))
REFUSALS = STATUSES | {
    'BOOTSTRAP_CONTEXT_REFUSED', 'BOOTSTRAP_APPROVAL_REFUSED',
    'BOOTSTRAP_PACKAGE_REFUSED', 'BOOTSTRAP_RECEIPT_REFUSED',
    'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED', 'PROTECTED_WRITER_POLICY_REQUIRED',
    'TEST_SSH_KEY_NOT_CONFIGURED', 'EXACT_TEST_HOST_PIN_REQUIRED', 'SSH_TRANSPORT_NOT_CONFIRMED',
    'OVERALL_DEADLINE',
}


def context(env):
    fixed = dict(
        GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
        GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
        GITHUB_WORKFLOW_REF=REPO + '/.github/workflows/' + WORKFLOW + '@refs/heads/main',
    )
    sha = env.get('GITHUB_SHA', '')
    need(all(env.get(k) == v for k, v in fixed.items())
         and re.fullmatch('[0-9a-f]{40}', sha) and env.get('GITHUB_WORKFLOW_SHA') == sha
         and re.fullmatch('[1-9][0-9]{0,14}', env.get('GITHUB_RUN_ID', '')), 'BOOTSTRAP_CONTEXT_REFUSED')
    need(env.get('APPROVED_BOOTSTRAP_SHA') == sha
         and env.get('APPROVED_PUBLIC_KEY_SHA256') == PUBLIC_SHA256
         and env.get('APPROVED_BOOTSTRAP_SCOPE') == SCOPE, 'BOOTSTRAP_APPROVAL_REFUSED')
    return sha


def package():
    try:
        parent = Path(__file__).resolve().parent
        public = _read_regular(parent / 'test_installer_bootstrap.pub', 256)
        need(hashlib.sha256(public).hexdigest() == PUBLIC_SHA256, 'BOOTSTRAP_PACKAGE_REFUSED')
        return public, {name: _read_regular(parent / filename, 32768) for name, filename in FILES.items()}
    except Exception:
        raise Refused('BOOTSTRAP_PACKAGE_REFUSED') from None


def child_program(nonce, public, files):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'BOOTSTRAP_PACKAGE_REFUSED')
    need(type(public) is bytes and hashlib.sha256(public).hexdigest() == PUBLIC_SHA256
         and type(files) is dict and set(files) == set(FILES)
         and all(type(raw) is bytes and 0 < len(raw) <= 32768 for raw in files.values()),
         'BOOTSTRAP_PACKAGE_REFUSED')
    source = ('_BOOT_NONCE=' + repr(nonce) + '\n_BOOT_PUBLIC_KEY=' + repr(public)
              + '\n_BOOT_FILES=' + repr(files) + '\n' + HOST_SOURCE)
    need(source.isascii() and len(source) < 65536, 'BOOTSTRAP_PACKAGE_REFUSED')
    compile(source, '<fixed TEST bootstrap>', 'exec')
    return source


def project(raw, nonce):
    try:
        need(type(raw) is bytes and 0 < len(raw) <= 4096, 'BOOTSTRAP_RECEIPT_REFUSED')
        outer = strict_json(raw.decode('ascii'))
        need(type(outer) is dict and set(outer) == {'version', 'nonce', 'principal', 'euid', 'root_diagnostic'}
             and outer['version'] == 'jsm-test-installed-route-outer-v2'
             and outer['nonce'] == nonce and outer['principal'] == 'marinagurina'
             and type(outer['euid']) is int and 0 < outer['euid'] <= 4294967295, 'BOOTSTRAP_RECEIPT_REFUSED')
        child = outer['root_diagnostic']
        need(type(child) is dict and set(child) == {'version', 'nonce', 'euid', 'status'}
             and child['version'] == VERSION and child['nonce'] == nonce
             and type(child['euid']) is int and child['euid'] == 0
             and type(child['status']) is str and child['status'] in STATUSES, 'BOOTSTRAP_RECEIPT_REFUSED')
        return child['status']
    except Exception:
        raise Refused('BOOTSTRAP_RECEIPT_REFUSED') from None


def collect(api, env):
    deadline = time.monotonic() + OVERALL_SECONDS
    sha = context(env)
    verify_policy(api)
    require_protected_writer(api, sha)
    public, files = package()
    raw, nonce = _receive(env, deadline, lambda challenge: child_program(challenge, public, files))
    return project(raw, nonce)


def main():
    receipt = dict(version=VERSION, target=TARGET, status='BLOCKED',
                   installer_report='NOT_VERIFIED', db_isolation='NOT_ESTABLISHED')
    try:
        need(len(sys.argv) == 1, 'BOOTSTRAP_CONTEXT_REFUSED')
        receipt['workflow_sha'] = context(os.environ)
        api = _GitHubGet((GH_REPO, GH_ENV, GH_ENV + '/deployment-branch-policies',
                          ENV_ENDPOINT, BRANCH_ENDPOINT, MAIN_ENDPOINT))
        receipt['status'] = collect(api, os.environ)
        receipt['writer_public_key_sha256'] = PUBLIC_SHA256
    except Exception as error:
        message = error.args[0] if isinstance(error, Refused) and len(error.args) == 1 else None
        receipt['reason'] = message if type(message) is str and message in REFUSALS else 'BOOTSTRAP_REFUSED'
    print(json.dumps(receipt, separators=(',', ':'), sort_keys=True))
    return 0 if receipt['status'] == 'BOOTSTRAPPED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
