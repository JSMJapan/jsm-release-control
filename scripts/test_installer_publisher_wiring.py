"""Pinned report-only entry and bounded publisher frames for #2760.

This module does not authenticate GitHub or discover a database. The publisher
and the root entry must obtain the independently authorized run/window before
using these primitives. No workflow or server command invokes this draft yet.
"""
from dataclasses import dataclass
from hashlib import sha256
import base64
import hmac
import json
import os
import re
import select
import time

from apache_parity_bridge import strict_json
from test_db_installer_receipt import _SCOPE, _valid_report, _valid_run
from test_installer_update_package import ORIGINAL_SHA256, ORIGINAL_SIZE, REPORTER

REQUEST_VERSION = 'jsm-test-publisher-report-request-v1'
RESPONSE_VERSION = 'jsm-test-publisher-report-response-v1'
INPUT_LIMIT = 2048
OUTPUT_LIMIT = 6200
REPORT_LIMIT = 4096
MAX_WINDOW_SECONDS = 45 * 60
WRAPPER_SIZE = 255
WRAPPER_SHA256 = '5f7e773ed2c8efc3808ff5d8481156d798d292e9cb2dca4142338564896ff10b'
FIXED_RUNNER = {
    'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'JSMJapan/jsm-storefront',
    'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_API_URL': 'https://api.github.com',
    'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_RUN_ATTEMPT': '1',
    'GITHUB_ACTOR': 'JSMJapan', 'GITHUB_TRIGGERING_ACTOR': 'JSMJapan', 'GITHUB_JOB': 'publish',
    'GITHUB_WORKFLOW_REF': 'JSMJapan/jsm-storefront/.github/workflows/sandbox-publish.yml@refs/heads/main',
}
GATE_COMMAND = (
    b'/usr/bin/env -i PATH=/usr/bin:/bin LANG=C '
    b'/usr/bin/timeout --signal=TERM --kill-after=1 12 '
    + REPORTER.encode('ascii') + b' --publisher-entry'
)
GATE = (
    b'# JSM TEST installer report-only entry (#2760)\n'
    b'if [[ "${1:-}" == jsm-test-db-report-v1:* ]]; then\n'
    b'  jsm_report_sha=${1#jsm-test-db-report-v1:}\n'
    b'  if [[ "$#" -ne 1 || ! "$jsm_report_sha" =~ ^[0-9a-f]{40}$ ]]; then exit 65; fi\n'
    b'  exec ' + GATE_COMMAND + b' "$jsm_report_sha"\n'
    b'fi\n'
)
WRAPPER_COMMAND = (
    b'/usr/bin/timeout --signal=TERM --kill-after=1 15 /usr/bin/python3 -I -B -S '
    b'/usr/local/libexec/jsm-test-db-publisher-guard.py'
)
WRAPPER_GATE = (
    b'# JSM TEST publisher report-only command (#2760)\n'
    b"jsm_report_pattern='^jsm-test-db-report-v1 ([0-9a-f]{40})$'\n"
    b'if [[ "${SSH_ORIGINAL_COMMAND:-}" =~ $jsm_report_pattern ]]; then\n'
    b'  exec ' + WRAPPER_COMMAND + b' "${BASH_REMATCH[1]}"\n'
    b'fi\n'
    b'unset jsm_report_pattern\n'
)


class WiringRefused(ValueError):
    """A closed protocol error. Private command output must stay private."""


@dataclass(frozen=True)
class PublisherRun:
    workflow_sha: str
    requested_site_sha: str
    run_id: str


@dataclass(frozen=True)
class ReportWindow:
    run: PublisherRun
    control_sha: str
    nonce: str
    opens_at: int
    closes_at: int


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
            + '\n').encode('ascii')


def _run(value):
    if type(value) is not PublisherRun:
        raise WiringRefused('RUN_REFUSED')
    result = dict(workflow_sha=value.workflow_sha, requested_site_sha=value.requested_site_sha, id=value.run_id,
                  attempt=1, actor='JSMJapan', triggering_actor='JSMJapan')
    if not _valid_run(result):
        raise WiringRefused('RUN_REFUSED')
    return result


def runner_context(env, approved_workflow_sha):
    if (any(env.get(name) != expected for name,expected in FIXED_RUNNER.items())
            or env.get('GITHUB_SHA') != approved_workflow_sha
            or env.get('GITHUB_WORKFLOW_SHA') != approved_workflow_sha):
        raise WiringRefused('RUN_REFUSED')
    run = PublisherRun(approved_workflow_sha, env.get('DEPLOY_SHA'), env.get('GITHUB_RUN_ID'))
    _run(run)
    return run


def _epoch(value):
    return type(value) is int and 0 < value <= 253402300799


def _window(value):
    if (type(value) is not ReportWindow or type(value.nonce) is not str
            or re.fullmatch('[0-9a-f]{64}', value.nonce) is None
            or type(value.control_sha) is not str or re.fullmatch('[0-9a-f]{40}', value.control_sha) is None
            or not _epoch(value.opens_at) or not _epoch(value.closes_at)
            or not 0 < value.closes_at-value.opens_at <= MAX_WINDOW_SECONDS):
        raise WiringRefused('WINDOW_REFUSED')
    return _run(value.run)


def request_frame(window):
    run = _window(window)
    raw = canonical(dict(version=REQUEST_VERSION, mode='REPORT_ONLY', nonce=window.nonce,
                         opens_at=window.opens_at, closes_at=window.closes_at,
                         context=dict(scope=dict(_SCOPE), run=run, control_sha=window.control_sha)))
    if len(raw)>INPUT_LIMIT:
        raise WiringRefused('REQUEST_REFUSED')
    return raw


def require_request(raw, expected_window, requested_site_sha, now):
    expected = request_frame(expected_window)
    if (type(raw) is not bytes or len(raw)>INPUT_LIMIT or raw!=expected
            or requested_site_sha!=expected_window.run.requested_site_sha
            or not _epoch(now) or not expected_window.opens_at<=now<=expected_window.closes_at):
        raise WiringRefused('REQUEST_REFUSED')


def read_request_fd(fd, deadline):
    """Read only to EOF, with one fixed size and monotonic time budget."""
    data = bytearray()
    while True:
        remaining = deadline-time.monotonic()
        if remaining<=0 or not select.select([fd], [], [], remaining)[0]:
            raise WiringRefused('REQUEST_REFUSED')
        part = os.read(fd, min(1024, INPUT_LIMIT+1-len(data)))
        if not part:
            break
        data.extend(part)
        if len(data)>INPUT_LIMIT:
            raise WiringRefused('REQUEST_REFUSED')
    if not data:
        return None
    if data.count(b'\n')!=1 or not data.endswith(b'\n'):
        raise WiringRefused('REQUEST_REFUSED')
    return bytes(data)


def _report(raw, window, emitted):
    if raw is None:
        return None
    try:
        if type(raw) is not bytes or not 0<len(raw)<=REPORT_LIMIT:
            raise ValueError()
        value = strict_json(raw.decode('ascii'))
        if (not _valid_report(value) or canonical(value)!=raw or value['run']!=_run(window.run)
                or not window.opens_at<=value['observation']['from']<=value['observation']['until']<=emitted):
            raise ValueError()
    except Exception:
        raise WiringRefused('REPORT_REFUSED') from None
    return base64.b64encode(raw).decode('ascii')


def receipt_frame(window, raw, emitted):
    _window(window)
    if not _epoch(emitted) or not window.opens_at<=emitted<=window.closes_at:
        raise WiringRefused('REPORT_REFUSED')
    body = dict(version=RESPONSE_VERSION, emitted=emitted, report=_report(raw, window, emitted))
    tag = hmac.new(bytes.fromhex(window.nonce), b'jsm-2760-publisher-egress\0'+request_frame(window)
                   +b'\0'+canonical(body), sha256).hexdigest()
    output = canonical(dict(body, tag=tag))
    if len(output)>OUTPUT_LIMIT:
        raise WiringRefused('REPORT_REFUSED')
    return output


def read_receipt(raw, expected_window, now):
    _window(expected_window)
    try:
        if (type(raw) is not bytes or not 0<len(raw)<=OUTPUT_LIMIT or not _epoch(now)
                or not expected_window.opens_at<=now<=expected_window.closes_at):
            raise ValueError()
        obj = strict_json(raw.decode('ascii'))
        if type(obj) is not dict or set(obj)!={'version','emitted','report','tag'}:
            raise ValueError()
        encoded = obj['report']
        report = None if encoded is None else base64.b64decode(encoded, validate=True)
        if not _epoch(obj['emitted']) or obj['emitted']>now:
            raise ValueError()
        expected = receipt_frame(expected_window, report, obj['emitted'])
        if not hmac.compare_digest(raw, expected):
            raise ValueError()
        return report
    except Exception:
        raise WiringRefused('REPORT_REFUSED') from None


def publisher_entry(fd, requested_site_sha, deadline, *, expected_window, release_guard, observe, epoch):
    """Connect the explicitly selected report-only mode to an authorized observer.

    Empty input cannot route a report command to the legacy installer.
    No untrusted payload becomes authority.
    The bound release guard must hold the deployment lock and independently
    prove the current generation before any application or DB observation.
    """
    raw = read_request_fd(fd, deadline)
    if raw is None:
        raise WiringRefused('REQUEST_REFUSED')
    require_request(raw, expected_window, requested_site_sha, epoch())
    with release_guard(requested_site_sha):
        report = observe(expected_window)
        result = receipt_frame(expected_window, report, epoch())
    return 0, result


def _splice(raw, size, digest, splice):
    if (type(raw) is not bytes or len(raw)!=size or sha256(raw).hexdigest()!=digest
            or not raw.startswith((b'#!/usr/bin/env bash\n',b'#!/bin/bash\n')) or splice in raw):
        raise WiringRefused('INSTALLER_PREIMAGE_REFUSED')
    shebang, remainder = raw.split(b'\n',1)
    return shebang+b'\n'+splice+remainder


def _unsplice(raw, size, digest, splice):
    if type(raw) is not bytes or len(raw)!=size+len(splice):
        raise WiringRefused('INSTALLER_CANDIDATE_REFUSED')
    shebang, separator, remainder = raw.partition(b'\n')
    if not separator or not remainder.startswith(splice):
        raise WiringRefused('INSTALLER_CANDIDATE_REFUSED')
    restored = shebang+separator+remainder[len(splice):]
    if _splice(restored, size, digest, splice)!=raw:
        raise WiringRefused('INSTALLER_CANDIDATE_REFUSED')
    return restored


def splice_installer(raw):
    return _splice(raw, ORIGINAL_SIZE, ORIGINAL_SHA256, GATE)


def unsplice_installer(raw):
    return _unsplice(raw, ORIGINAL_SIZE, ORIGINAL_SHA256, GATE)


def splice_wrapper(raw):
    return _splice(raw, WRAPPER_SIZE, WRAPPER_SHA256, WRAPPER_GATE)


def unsplice_wrapper(raw):
    return _unsplice(raw, WRAPPER_SIZE, WRAPPER_SHA256, WRAPPER_GATE)
