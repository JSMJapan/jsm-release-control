#!/usr/bin/env python3
"""#2760 non-admitting TEST DB scope barrier; not an SQL executor.

No independent current target admission exists in the reviewed records. This
candidate verifies the existing public GitHub protection policy, then stops
before credential access, SSH, configuration reads, PHP or any SQL connection.
No caller-supplied baseline or apparent literal target can bypass that stop.
The separate evidence/metadata contract is documented in docs/2760-test-db.md.
"""
import datetime
import json
import os
from pathlib import Path
import re
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apache_parity_bridge import Refused
from hostinger_preflight import policy_ready
from test_api_readonly_access import TestPolicyApi, _python_version

REPO = 'JSMJapan/jsm-release-control'
GH_REPO = '/repos/' + REPO
GH_ENV = GH_REPO + '/environments/test-api-readonly-access'
OVERALL_SECONDS = 60
SAFE_REASONS = frozenset(('OWNER_MANUAL_MAIN_TEST_DB_WORKFLOW_REQUIRED',
    'PROTECTED_TEST_OWNER_MAIN_ENVIRONMENT_REQUIRED', 'INDEPENDENT_TARGET_ADMISSION_REQUIRED',
    'NO_ARGUMENTS_OR_INPUTS_ACCEPTED', 'OVERALL_DEADLINE', 'TEST_DB_SCOPE_REJECTED'))


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
        credentials='NOT_ACCESSED', ssh='NOT_ATTEMPTED', application_execution='NOT_PERFORMED',
        provider_requests='NOT_PERFORMED', database_writes='NOT_PERFORMED',
        missing_evidence=['INDEPENDENT_CURRENT_TARGET_BASELINE', 'ACTIVE_API_TO_DB_BINDING',
            'DIAGNOSTIC_AND_APPLICATION_PRINCIPAL_BOUNDARIES', 'SYNTHETIC_LOADER_ADMISSION',
            'EGRESS_AND_PRODUCTION_SEPARATION'])


def collect(api, env):
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
    # Intentional terminal admission barrier. There is no SQL runner, target
    # parser, SSH command or baseline override hidden behind this condition.
    # A later reviewed candidate must supply independently admitted evidence and
    # separately implement/review execution; that capability is absent here.
    return blocked_receipt('INDEPENDENT_TARGET_ADMISSION_REQUIRED', policy_verified=True)


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
