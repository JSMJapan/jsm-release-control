#!/usr/bin/env python3
"""#2760 fixed TEST OS metadata observer, never an SQL/DB admission runner.

The existing protected key-only TEST route carries a fixed Linux metadata
capsule. No application/config/DB credentials or data are read. Observed OS
relationships cannot promote a target to trusted API/DB binding or admission.
"""
import datetime
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
from apache_parity_bridge import Refused, _bounded, strict_json
from hostinger_preflight import policy_ready
from test_api_readonly_access import TestPolicyApi, PIN_SHA256, private_file, _python_version
from test_api_installed_route_readonly import wrap_root_program
from test_db_os_metadata import LIBRARY

REPO = 'JSMJapan/jsm-release-control'
GH_REPO = '/repos/' + REPO
GH_ENV = GH_REPO + '/environments/test-api-readonly-access'
OVERALL_SECONDS = 60
SAFE_REASONS = frozenset(('OWNER_MANUAL_MAIN_TEST_DB_WORKFLOW_REQUIRED',
    'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED', 'INDEPENDENT_TARGET_ADMISSION_REQUIRED',
    'NO_ARGUMENTS_OR_INPUTS_ACCEPTED', 'OVERALL_DEADLINE', 'TEST_DB_SCOPE_REJECTED',
    'TEST_SSH_KEY_NOT_CONFIGURED', 'EXACT_TEST_HOST_PIN_REQUIRED', 'NONCE_REQUIRED',
    'SSH_TRANSPORT_NOT_CONFIRMED', 'REMOTE_IDENTITY_SCHEMA_REJECTED',
    'OS_METADATA_OBSERVED_DB_ADMISSION_BLOCKED', 'OS_METADATA_PARTIAL_DB_ADMISSION_BLOCKED'))


def safe_reason(error):
    reason = error.args[0] if isinstance(error, Refused) and len(error.args) == 1 else None
    return reason if type(reason) is str and reason in SAFE_REASONS else 'TEST_DB_SCOPE_REJECTED'


def context_ready(env):
    fixed = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
        GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
        GITHUB_WORKFLOW_REF=REPO + '/.github/workflows/test-db-metadata-readonly.yml@refs/heads/main')
    if (any(env.get(key) != value for key, value in fixed.items())
            or type(env.get('GITHUB_SHA')) is not str or not re.fullmatch('[0-9a-f]{40}', env['GITHUB_SHA'])
            or env.get('GITHUB_WORKFLOW_SHA') != env['GITHUB_SHA']
            or type(env.get('GITHUB_RUN_ID')) is not str or not re.fullmatch('[0-9]{1,15}', env['GITHUB_RUN_ID'])):
        raise Refused('OWNER_MANUAL_MAIN_TEST_DB_WORKFLOW_REQUIRED')


def blocked_receipt(reason, *, policy_verified=False):
    # No observed values are accepted here. These are deliberately unresolved,
    # not false, and not a successful effective-binding or SQL observation.
    reason = reason if type(reason) is str and reason in SAFE_REASONS else 'TEST_DB_SCOPE_REJECTED'
    policy_verified = policy_verified is True
    return dict(receipt_version='jsm-test-db-scope-2760-v1', status='BLOCKED', scope_state='PREPARED',
        db_proof='BLOCKED_TARGET_ADMISSION' if policy_verified else 'NOT_ESTABLISHED', reason=reason,
        target_resource='gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713',
        target_domain='develop.jsmjapan.com', protected_policy_verified=policy_verified, admitted_baseline=None,
        effective_api_binding='NOT_ESTABLISHED', db_target_identity='NOT_ESTABLISHED',
        diagnostic_db_principal='NOT_OBSERVED', application_db_principal='NOT_OBSERVED',
        db_grants='NOT_ESTABLISHED', db_data_provenance='NOT_ESTABLISHED',
        db_isolation='NOT_ESTABLISHED', egress_isolation='NOT_ESTABLISHED', sql='NOT_ATTEMPTED',
        database_credentials='NOT_ACCESSED', ssh='NOT_ATTEMPTED', sudo_root_identity=None,
        os_observation=None, test_disk_identity='NOT_ESTABLISHED', application_execution='NOT_PERFORMED',
        provider_requests='NOT_PERFORMED', database_writes='NOT_PERFORMED',
        missing_evidence=['INDEPENDENT_CURRENT_TARGET_BASELINE', 'ACTIVE_API_TO_DB_BINDING',
            'DIAGNOSTIC_AND_APPLICATION_PRINCIPAL_BOUNDARIES', 'SYNTHETIC_LOADER_ADMISSION',
            'EGRESS_AND_PRODUCTION_SEPARATION'])


def policy_gate(api, env):
    context_ready(env)  # Before policy network access and before any credential.
    repo = api.get_json(GH_REPO)
    environment = api.get_json(GH_ENV)
    branches = api.get_json(GH_ENV + '/deployment-branch-policies')
    try:
        policy_ready(repo, environment, branches)  # Existing shared pure guard, unchanged.
        rules = [row for row in environment['protection_rules'] if row.get('type') == 'required_reviewers']
        reviewer = rules[0]['reviewers'][0]['reviewer']
        if (environment.get('name') != 'test-api-readonly-access'
                or type(reviewer.get('id')) is not int or reviewer['id'] != 327623967
                or type(branches.get('total_count')) is not int or branches['total_count'] != 1):
            raise ValueError()
    except Exception:
        raise Refused('PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED') from None
    # Independent SQL admission remains terminally blocked. The caller can only
    # run the fixed OS metadata capsule, never a caller-selected target/query.
    return blocked_receipt('INDEPENDENT_TARGET_ADMISSION_REQUIRED', policy_verified=True)


def need(value, reason):
    if not value:
        raise Refused(reason)


def remote_program(nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'NONCE_REQUIRED')
    child=LIBRARY+'\nprint(json.dumps(_observe('+repr(nonce)+'),separators=(",",":"),sort_keys=True))\n'
    return wrap_root_program(nonce,child)


def _child_projection(child, nonce):
    # Strictly closed, typed public schema: arbitrary raw paths/FDs/errors are
    # not forwarded, even if the remote capsule malfunctions.
    fields={'version','nonce','euid','observation_state','processes','sockets','datadir',
        'effective_api_binding','test_disk_identity','db_proof','sql'}
    if (type(child) is not dict or set(child)!=fields or child['version']!='jsm-test-db-os-2760-v1'
            or child['nonce']!=nonce or type(child['euid']) is not int or child['euid']!=0
            or child['observation_state'] not in ('PARTIAL','OBSERVED')
            or child['effective_api_binding']!='NOT_ESTABLISHED' or child['test_disk_identity']!='NOT_ESTABLISHED'
            or child['db_proof']!='BLOCKED_TARGET_ADMISSION' or child['sql']!='NOT_ATTEMPTED'):
        return None
    for name,ids,booleans in (
            ('processes',('apache','php','mysql'),('exe_matches','namespace_matches','stable')),
            ('sockets',('php','mysql'),('is_socket','kernel_listener','owned_by_service_mainpid'))):
        rows=child[name]
        if type(rows) is not list or len(rows)!=len(ids):return None
        for row,identity in zip(rows,ids):
            if (type(row) is not dict or set(row)!={'id','state',*booleans} or row['id']!=identity
                    or row['state'] not in ('unknown','observed')
                    or any(row[key] is not None and type(row[key]) is not bool for key in booleans)):
                return None
    directory=child['datadir']
    if (type(directory) is not dict or set(directory)!={'state','is_directory','filesystem','device_matches'}
            or directory['state'] not in ('unknown','observed')
            or directory['filesystem'] not in ('unknown','unsupported','local_block')
            or any(directory[key] is not None and type(directory[key]) is not bool
                for key in ('is_directory','device_matches'))):return None
    complete=(all(row['state']=='observed' and all(row[k] is True for k in ('exe_matches','namespace_matches','stable'))
        for row in child['processes'])
        and all(row['state']=='observed' and all(row[k] is True for k in ('is_socket','kernel_listener','owned_by_service_mainpid'))
            for row in child['sockets'])
        and directory==dict(state='observed',is_directory=True,filesystem='local_block',device_matches=True))
    if child['observation_state']=='OBSERVED' and not complete:return None
    return child


def project_remote(raw, nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'NONCE_REQUIRED')
    try:
        need(type(raw) is bytes and 0<len(raw)<=16384,'REMOTE_IDENTITY_SCHEMA_REJECTED')
        outer=strict_json(raw.decode('ascii'))
        need(type(outer) is dict and set(outer)=={'version','nonce','principal','euid','root_diagnostic'}
            and outer['version']=='jsm-test-installed-route-outer-v2' and outer['nonce']==nonce
            and outer['principal']=='marinagurina' and type(outer['euid']) is int
            and 0<outer['euid']<=4294967295,'REMOTE_IDENTITY_SCHEMA_REJECTED')
        child=_child_projection(outer['root_diagnostic'],nonce)
    except Exception:
        raise Refused('REMOTE_IDENTITY_SCHEMA_REJECTED') from None
    complete=child is not None and child['observation_state']=='OBSERVED'
    result=blocked_receipt('OS_METADATA_OBSERVED_DB_ADMISSION_BLOCKED' if complete
        else 'OS_METADATA_PARTIAL_DB_ADMISSION_BLOCKED',policy_verified=True)
    result.update(ssh='OBSERVED',sudo_root_identity=True if child is not None else None,os_observation=child)
    return result


def collect(api, env):
    deadline=time.monotonic()+OVERALL_SECONDS
    policy_gate(api,env)  # Existing public policy before any SSH credential access.
    key,known=env.get('TEST_API_ADMIN_SSH_KEY'),env.get('TEST_API_KNOWN_HOSTS')
    need(type(key) is str and 0<len(key)<=16384 and '\x00' not in key,'TEST_SSH_KEY_NOT_CONFIGURED')
    need(type(known) is str and len(known)<=16384 and hashlib.sha256(known.encode()).hexdigest()==PIN_SHA256,
        'EXACT_TEST_HOST_PIN_REQUIRED')
    nonce=secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='jsm-test-db-os-ro-') as folder:
        os.chmod(folder,0o700);identity,hosts=Path(folder)/'identity',Path(folder)/'known_hosts'
        private_file(identity,key.replace('\r\n','\n').rstrip('\n')+'\n');private_file(hosts,known)
        command=['/usr/bin/ssh','-F','/dev/null','-T','-i',str(identity),'-p','22',
            '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes',
            '-o','BatchMode=yes','-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
            '-o','KbdInteractiveAuthentication=no','-o','ClearAllForwardings=yes',
            '-o','UserKnownHostsFile='+str(hosts),'-o','GlobalKnownHostsFile=/dev/null',
            '-o','ConnectTimeout=7','-o','ConnectionAttempts=1','-o','ServerAliveInterval=3',
            '-o','ServerAliveCountMax=2','-o','LogLevel=ERROR',
            'marinagurina@34.104.157.63','/usr/bin/python3','-I','-B','-S','-']
        budget=min(15,deadline-time.monotonic()-2);need(budget>0,'OVERALL_DEADLINE')
        code,raw=_bounded(command,data=remote_program(nonce),limit=16384,timeout=budget)
        need(code==0,'SSH_TRANSPORT_NOT_CONFIRMED')
        return project_remote(raw,nonce)


def main():
    def expired(*_):
        raise Refused('OVERALL_DEADLINE')
    source_sha = None
    run_url = None
    try:
        if len(sys.argv) != 1:
            raise Refused('NO_ARGUMENTS_OR_INPUTS_ACCEPTED')
        context_ready(os.environ)
        source_sha = os.environ['GITHUB_SHA']
        run_url = 'https://github.com/' + REPO + '/actions/runs/' + os.environ['GITHUB_RUN_ID']
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS)
        result = collect(TestPolicyApi(), os.environ)
    except Exception as error:
        result = blocked_receipt(safe_reason(error))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    result.update(source_sha=source_sha, workflow_run_url=run_url,
        python_version=_python_version(),
        verified_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'))
    print(json.dumps(result, separators=(',', ':'), sort_keys=True))
    return 1  # Scope preparation is never an accepted DB check or a green DB gate.


if __name__ == '__main__':
    raise SystemExit(main())
