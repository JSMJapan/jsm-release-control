#!/usr/bin/env python3
"""Deploy only through the protected, owner-dispatched GitHub TEST workflow."""

from hashlib import sha256
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apache_parity_bridge import _GitHubGet, strict_json
from article_test_actions import download
from article_test_artifact import Build
from article_test_delivery import ssh_command, transfer
from article_test_images import verify
from article_test_state import canonical, valid_run
from eva_test_actions import REPO, artifact_paths, authorize, authorize_artifact, control_paths
from eva_test_archive import EvaRefused, inspect_archive, load_pins, require
from eva_test_receiver import COMMAND, PROTOCOL, SAFE_ERRORS, SHA, prefix
from test_api_readonly_access import PIN_SHA256, private_file

RESOURCE = 'gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713'
SAFE = SAFE_ERRORS | {
    'EVA_GITHUB_APPROVAL_REFUSED', 'EVA_GITHUB_CONTEXT_REFUSED', 'EVA_ARTIFACT_SCOPE_REFUSED',
    'EVA_INSTALLATION_NOT_PROVISIONED', 'EVA_RECEIPT_REFUSED', 'EVA_OVERALL_DEADLINE',
}


def project(raw, op, run, nonce, build):
    result = strict_json(raw.decode('ascii'))
    require(type(result) is dict and canonical(result) == raw
            and result.get('protocol') == PROTOCOL, 'EVA_RECEIPT_REFUSED')
    if result.get('status') == 'BLOCKED':
        require(result.keys() in ({'protocol', 'status', 'reason'}, {'protocol', 'status', 'reason', 'nonce', 'run'})
                and result.get('nonce', nonce) == nonce and result.get('run', run) == run and result.get('reason') in SAFE_ERRORS,
                'EVA_RECEIPT_REFUSED')
        return {'status': 'BLOCKED', 'run': run, 'reason': result['reason']}
    envelope = {'status', 'run', 'protocol', 'nonce'}
    require(result.get('nonce') == nonce and result.get('run') == run, 'EVA_RECEIPT_REFUSED')
    if op == 'CLEANUP':
        require(result.keys() == envelope and result['status'] == 'CLEANED', 'EVA_RECEIPT_REFUSED')
    else:
        require(result.keys() == envelope | {'expires', 'build_sha', 'artifact_sha256', 'pdo', 'https', 'telegram', 'claude'}
                and result['status'] == 'STAGED_LOCAL_ONLY' and result['pdo'] == 'BOUND_SYNTHETIC'
                and result['https'] == 'NOT_CONFIGURED' and result['telegram'] == result['claude'] == 'NOT_RUN'
                and result['build_sha'] == build.sha and result['artifact_sha256'] == build.archive_sha256
                and type(result['expires']) is int and time.time() < result['expires'] <= time.time() + 1200,
                'EVA_RECEIPT_REFUSED')
    return {key: value for key, value in result.items() if key not in ('protocol', 'nonce')}


def transport(identity, known):
    command = ssh_command(identity, known, '')
    # Reuse fixed, verified destination and transport flags, with a separate force-command account.
    command[-2] = 'jsm-eva-stage@' + command[-2].split('@', 1)[1]
    command[-1] = COMMAND
    return command


def execute(env):
    sha, run_id = env.get('GITHUB_SHA', ''), env.get('GITHUB_RUN_ID', '')
    require(SHA.fullmatch(sha) and re.fullmatch('[1-9][0-9]{0,14}', run_id), 'EVA_GITHUB_CONTEXT_REFUSED')
    op = env.get('OPERATION')
    require(op in ('STAGE', 'CLEANUP'), 'EVA_GITHUB_CONTEXT_REFUSED')
    run = env.get('CLEANUP_RUN', '') if op == 'CLEANUP' else secrets.token_hex(6)
    require(valid_run(run) and (op == 'CLEANUP' or not env.get('CLEANUP_RUN')), 'EVA_GITHUB_CONTEXT_REFUSED')
    authorize(_GitHubGet(control_paths(run_id), token=env.get('GH_TOKEN')), env, run_id, sha)
    key, known = env.get('EVA_STAGE_SSH_KEY'), env.get('EVA_STAGE_KNOWN_HOSTS')
    require(type(key) is str and 0 < len(key) <= 16384 and '\0' not in key
            and type(known) is str and len(known) <= 16384 and sha256(known.encode()).hexdigest() == PIN_SHA256,
            'EVA_INSTALLATION_NOT_PROVISIONED')
    nonce = secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='jsm-eva-test-1620-') as folder:
        directory = Path(folder)
        identity, hosts = directory / 'identity', directory / 'known_hosts'
        private_file(identity, key.replace('\r\n', '\n').rstrip('\n') + '\n')
        private_file(hosts, known)
        build, archive, size = None, None, 0
        if op == 'STAGE':
            token = env.get('STOREFRONT_ACTIONS_READ_TOKEN')
            require(type(token) is str and re.fullmatch('[!-~]{1,4096}', token), 'EVA_INSTALLATION_NOT_PROVISIONED')
            build = load_pins()
            size = authorize_artifact(_GitHubGet(artifact_paths(build), token=token), build)
            archive = directory / 'artifact.zip'
            # The bounded HTTP downloader uses only id and digest; admission above uses the Eva name and workflow.
            envelope = Build(build.sha, build.run_id, build.artifact_id, build.archive_sha256)
            download(envelope, token, archive, size, time.monotonic() + 300)
            inspected, _ = inspect_archive(archive, build)
            verify(archive, inspected, time.monotonic() + 180, containerd_layer_sources=True)
        raw = transfer(transport(identity, hosts), prefix(op, run, nonce, sha, build, size),
                       archive, time.monotonic() + 720)
    return {**project(raw, op, run, nonce, build), 'resource': RESOURCE, 'control_sha': sha,
            'workflow_run': 'https://github.com/' + REPO + '/actions/runs/' + run_id}


def main():
    def alarm(*_):
        raise EvaRefused('EVA_OVERALL_DEADLINE')
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(1450)
    try:
        result = execute(os.environ)
    except BaseException as error:
        reason = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in SAFE else 'EVA_CONTROL_REFUSED'
        result = {'status': 'BLOCKED', 'reason': reason}
    finally:
        signal.alarm(0)
    sys.stdout.buffer.write(canonical(result))
    return int(result['status'] == 'BLOCKED')


if __name__ == '__main__':
    raise SystemExit(main())
