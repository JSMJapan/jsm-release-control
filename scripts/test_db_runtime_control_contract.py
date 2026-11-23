"""Context and result schema for the public TEST control workflow only."""
from hashlib import sha256
import json
import re

from test_db_installer_receipt import _SCOPE, _valid_run


VERSION = 'jsm-test-db-control-report-v1'
REPO = 'JSMJapan/jsm-release-control'
WORKFLOW = '.github/workflows/test-db-runtime-report.yml'
ENVIRONMENT_NAME = 'test-api-readonly-access'
RUN_ACTOR = 'JSMJapan'
# Reference input for the manifest comparison, not an observed serving SHA.
REFERENCE_SITE_SHA = '4855198662bc28ee8ba41cf60ec430299f0a2222'
SCOPE = dict(dict(_SCOPE), repository=REPO, workflow=WORKFLOW, deployment_environment=ENVIRONMENT_NAME)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
            + '\n').encode('ascii')


def digest(context):
    return sha256(canonical(context)).hexdigest()


def context_valid(context):
    if (type(context) is not dict or set(context) != {'scope', 'run', 'control_sha'}
            or context['scope'] != SCOPE or not _valid_run(context['run'])):
        return False
    run = context['run']
    sha = context['control_sha']
    return (type(sha) is str and re.fullmatch('[0-9a-f]{40}', sha) is not None and run['workflow_sha'] == sha
            and run['requested_site_sha'] == REFERENCE_SITE_SHA and run['attempt'] == 1
            and run['actor'] == run['triggering_actor'] == RUN_ACTOR)


def report_valid(report):
    if type(report) is not dict or set(report) != {'status', 'configured_runtime', 'local_peer', 'sql', 'metadata'}:
        return False
    observed = 'OBSERVED'
    sql = report['sql']
    if report['status'] == 'BLOCKED':
        return (report['metadata'] is None and report['configured_runtime'] == 'NOT_ESTABLISHED'
                and report['local_peer'] in ('NOT_ESTABLISHED', observed)
                and sql in ('NOT_ATTEMPTED', 'AUTHORIZED_NOT_CONFIRMED', 'ONE_METADATA_SELECT_OBSERVED')
                and (sql == 'NOT_ATTEMPTED' or report['local_peer'] == observed))
    metadata = report['metadata']
    return (report['status'] == observed and report['configured_runtime'] == report['local_peer'] == observed
            and sql == 'ONE_METADATA_SELECT_OBSERVED' and type(metadata) is dict
            and set(metadata) == {'schema_matches', 'principal_kind', 'version_family', 'server_read_only', 'query_count'}
            and metadata['schema_matches'] is True and metadata['principal_kind'] in ('ROOT', 'OTHER')
            and metadata['version_family'] in ('MYSQL_5_7', 'MYSQL_8', 'MARIADB', 'OTHER')
            and type(metadata['server_read_only']) is bool and type(metadata['query_count']) is int
            and metadata['query_count'] == 1)
