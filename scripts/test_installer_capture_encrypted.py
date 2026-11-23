#!/usr/bin/env python3
"""#2760: one TEST installer, encrypted on the pinned VM before transport."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused, _bounded, _read_regular, strict_json
from hostinger_preflight import policy_ready
from test_api_installed_route_readonly import wrap_root_program
from test_api_readonly_access import (
    ENVIRONMENT, GH_ENV, GH_REPO, PIN_SHA256, REPO, TestPolicyApi, need, private_file,
)
from test_installer_capture_capsule import MAX_CIPHERTEXT_BYTES, STATUSES, render, validate_envelope

WORKFLOW = 'test-installer-capture-encrypted.yml'
CERTIFICATE = Path(__file__).with_name('test_installer_recipient.pem')
RECIPIENT_SHA256 = 'a42164ec5e3dcdae098ffe91d5bd97432c0bf5806efb9b29ee352cc329bf3466'
OUTER_LIMIT = 16384
OVERALL_SECONDS = 60
FILENAME = 'jsm-test-installer-2760.cms.der'
SOURCE = '/usr/local/sbin/jsm-sandbox-deploy'
TARGET = 'gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713'
REFUSALS = frozenset((
    'EXACT_OWNER_MAIN_CAPTURE_REQUIRED', 'EXACT_CAPTURE_APPROVAL_REQUIRED',
    'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED', 'RECIPIENT_NOT_CONFIRMED',
    'TEST_SSH_KEY_NOT_CONFIGURED', 'EXACT_TEST_HOST_PIN_REQUIRED', 'OVERALL_DEADLINE',
    'SSH_TRANSPORT_NOT_CONFIRMED', 'CAPTURE_RECEIPT_REJECTED', 'PREFLIGHT_REFUSED',
    'PATH_REFUSED', 'SOURCE_CHANGED', 'ENCRYPTION_REFUSED', 'ARTIFACT_WRITE_REFUSED',
))


def context_ready(env, *, workflow=WORKFLOW, recipient_sha256=RECIPIENT_SHA256):
    required = dict(
        GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
        GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
        GITHUB_WORKFLOW_REF=REPO + '/.github/workflows/' + workflow + '@refs/heads/main',
    )
    source_sha = env.get('GITHUB_SHA', '')
    run_id = env.get('GITHUB_RUN_ID', '')
    need(all(env.get(key) == value for key, value in required.items())
         and re.fullmatch('[0-9a-f]{40}', source_sha) and env.get('GITHUB_WORKFLOW_SHA') == source_sha
         and re.fullmatch('[0-9]{1,15}', run_id), 'EXACT_OWNER_MAIN_CAPTURE_REQUIRED')
    need(env.get('APPROVED_CAPTURE_SHA') == source_sha
         and env.get('APPROVED_RECIPIENT_SHA256') == recipient_sha256,
         'EXACT_CAPTURE_APPROVAL_REQUIRED')


def verify_policy(api):
    try:
        repository = api.get_json(GH_REPO)
        environment = api.get_json(GH_ENV)
        branches = api.get_json(GH_ENV + '/deployment-branch-policies')
        policy_ready(repository, environment, branches)
        rule = next(row for row in environment['protection_rules'] if row.get('type') == 'required_reviewers')
        reviewer_id = rule['reviewers'][0]['reviewer']['id']
        need(environment.get('name') == ENVIRONMENT and type(reviewer_id) is int
             and reviewer_id == 327623967 and type(branches['total_count']) is int,
             'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED')
    except Exception:
        raise Refused('PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED') from None


def recipient(*, certificate=CERTIFICATE, recipient_sha256=RECIPIENT_SHA256):
    try:
        pem = _read_regular(certificate, 2048)
        need(hashlib.sha256(pem).hexdigest() == recipient_sha256, 'RECIPIENT_NOT_CONFIRMED')
        return pem
    except Exception:
        raise Refused('RECIPIENT_NOT_CONFIRMED') from None


def project_remote(raw, nonce, pem, *, version='jsm-test-installer-cms-v1', statuses=STATUSES):
    try:
        need(type(raw) is bytes and 0 < len(raw) <= OUTER_LIMIT, 'CAPTURE_RECEIPT_REJECTED')
        outer = strict_json(raw.decode('ascii'))
        need(type(outer) is dict and set(outer) == {'version', 'nonce', 'principal', 'euid', 'root_diagnostic'}
             and outer['version'] == 'jsm-test-installed-route-outer-v2' and outer['nonce'] == nonce
             and outer['principal'] == 'marinagurina' and type(outer['euid']) is int
             and 0 < outer['euid'] <= 4294967295, 'CAPTURE_RECEIPT_REJECTED')
        child = outer['root_diagnostic']
        need(type(child) is dict and set(child) == {'version', 'nonce', 'euid', 'status', 'ciphertext'}
             and child['version'] == version and child['nonce'] == nonce
             and type(child['euid']) is int and child['euid'] == 0, 'CAPTURE_RECEIPT_REJECTED')
        status = child['status']
        if (type(status) is str and status in statuses[1:]
                and child['ciphertext'] is None):
            return status, None

        encoded = child['ciphertext']
        need(status == 'CAPTURED' and type(encoded) is str
             and 0 < len(encoded) <= 4 * ((MAX_CIPHERTEXT_BYTES + 2) // 3), 'CAPTURE_RECEIPT_REJECTED')
        ciphertext = base64.b64decode(encoded, validate=True)
        need(0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES and base64.b64encode(ciphertext).decode('ascii') == encoded,
             'CAPTURE_RECEIPT_REJECTED')
        need(validate_envelope(ciphertext, pem), 'CAPTURE_RECEIPT_REJECTED')
        return status, ciphertext
    except Exception:
        raise Refused('CAPTURE_RECEIPT_REJECTED') from None


def _receive(env, deadline, render_program):
    key, known = env.get('TEST_API_ADMIN_SSH_KEY'), env.get('TEST_API_KNOWN_HOSTS')
    need(type(key) is str and 0 < len(key) <= 16384 and '\x00' not in key, 'TEST_SSH_KEY_NOT_CONFIGURED')
    need(type(known) is str and len(known) <= 16384 and hashlib.sha256(known.encode()).hexdigest() == PIN_SHA256,
         'EXACT_TEST_HOST_PIN_REQUIRED')
    nonce = secrets.token_hex(16)
    program = wrap_root_program(nonce, render_program(nonce))
    with tempfile.TemporaryDirectory(prefix='jsm-test-installer-ssh-') as folder:
        identity, hosts = Path(folder) / 'identity', Path(folder) / 'known_hosts'
        private_file(identity, key.replace('\r\n', '\n').rstrip('\n') + '\n')
        private_file(hosts, known)
        # Same fixed SSH principal, known_hosts bytes and command as the existing TEST observer.
        command = [
            '/usr/bin/ssh', '-F', '/dev/null', '-T', '-i', str(identity), '-p', '22',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'UserKnownHostsFile=' + str(hosts), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=7', '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=3',
            '-o', 'ServerAliveCountMax=2', '-o', 'LogLevel=ERROR',
            'marinagurina@34.104.157.63', '/usr/bin/python3', '-I', '-B', '-S', '-',
        ]
        budget = min(15, deadline - time.monotonic() - 2)
        need(budget > 0, 'OVERALL_DEADLINE')
        try:
            code, raw = _bounded(command, data=program, limit=OUTER_LIMIT, timeout=budget)
        except Exception:
            raise Refused('SSH_TRANSPORT_NOT_CONFIRMED') from None
        need(code == 0, 'SSH_TRANSPORT_NOT_CONFIRMED')
    return raw, nonce


def collect(api, env):
    deadline = time.monotonic() + OVERALL_SECONDS
    context_ready(env)
    verify_policy(api)
    pem = recipient()
    raw, nonce = _receive(env, deadline, lambda challenge: render(challenge, pem, RECIPIENT_SHA256))
    status, ciphertext = project_remote(raw, nonce, pem)
    need(status == 'CAPTURED', status)
    return ciphertext


def write_artifact(directory, ciphertext, *, filename=FILENAME):
    try:
        need(os.path.isabs(directory), 'ARTIFACT_WRITE_REFUSED')
        fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            output = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(output, 'wb') as file:
                    file.write(ciphertext)
            except Exception:
                os.unlink(filename, dir_fd=fd)
                raise
        finally:
            os.close(fd)
    except Exception:
        raise Refused('ARTIFACT_WRITE_REFUSED') from None


def _run_capture(verify_context, collect_source, *, source, version, filename, recipient_sha256, refusals):
    def expired(*_):
        raise Refused('OVERALL_DEADLINE')

    receipt = dict(
        version=version, status='BLOCKED',
        target=TARGET, source=source, sql='NOT_ATTEMPTED', db_isolation='NOT_ESTABLISHED',
    )
    try:
        need(len(sys.argv) == 1, 'EXACT_OWNER_MAIN_CAPTURE_REQUIRED')
        verify_context(os.environ)
        receipt['workflow_sha'] = os.environ['GITHUB_SHA']
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS)
        directory = os.environ.get('RUNNER_TEMP', '')
        need(os.path.isabs(directory), 'ARTIFACT_WRITE_REFUSED')
        ciphertext = collect_source(TestPolicyApi(), os.environ)
        write_artifact(directory, ciphertext, filename=filename)
        receipt.update(status='ENCRYPTED_ARTIFACT_STAGED', recipient_sha256=recipient_sha256,
                       ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest())
    except Exception as error:
        reason = error.args[0] if isinstance(error, Refused) and len(error.args) == 1 else None
        receipt['reason'] = reason if type(reason) is str and reason in refusals else 'CAPTURE_REFUSED'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(receipt, sort_keys=True, separators=(',', ':')))
    return 0 if receipt['status'] == 'ENCRYPTED_ARTIFACT_STAGED' else 1


def main():
    return _run_capture(context_ready, collect, source=SOURCE, version='jsm-test-installer-capture-2760-v1',
                        filename=FILENAME, recipient_sha256=RECIPIENT_SHA256, refusals=REFUSALS)


if __name__ == '__main__':
    raise SystemExit(main())
