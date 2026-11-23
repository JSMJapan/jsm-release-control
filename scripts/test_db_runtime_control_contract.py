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
PHP_FILES = ('test_db_runtime_entry.php', 'test_db_runtime_probe.php', 'test_db_runtime_pdo.php',
             'test_db_runtime_php_channel.php', 'test_db_runtime_startup.php')
STAGES = ('CONTEXT', 'FPM_BEFORE', 'PRE_ENTRY', 'CHANNEL', 'STARTUP', 'LOCAL_TARGET', 'CONNECT', 'PEER_BEFORE_SQL',
          'SELECT', 'PEER_AFTER_SQL', 'FPM_AFTER', 'FASTCGI_END', 'COMPLETE')
REASONS = ('CONTEXT_REQUIRED', 'ROOT_LINUX_REQUIRED', 'FPM_REFUSED', 'CHANNEL_REFUSED', 'FRAME_REFUSED',
           'FRAME_LIMIT', 'DEADLINE', 'FASTCGI_REFUSED', 'STARTUP_REFUSED', 'CONFIG_SHAPE_REFUSED',
           'GENERATED_CONFIG_REFUSED', 'STARTUP_SOURCE_REFUSED', 'STARTUP_HOOK_REFUSED', 'STARTUP_CONTEXT_REFUSED',
           'VENDOR_PROFILE_REFUSED', 'MODEL_SOURCE_REFUSED', 'PROC_REFUSED', 'CGROUP_UNAVAILABLE',
           'APPLICATION_REFUSED', 'DB_DEFINITION_REFUSED', 'PDO_ATTRIBUTE_REFUSED', 'PDO_CAPABILITY_REFUSED',
           'PDO_AUTH_REFUSED', 'PDO_CONNECT_REFUSED', 'PDO_QUERY_REFUSED', 'METADATA_REFUSED', 'TARGET_REFUSED',
           'CGROUP_REFUSED', 'PROCESS_REFUSED', 'TCP_REFUSED', 'DOCKER_UNCONFIRMED', 'MYSQL_CANDIDATE_REFUSED',
           'LOCAL_LISTENER_REFUSED', 'FORWARDING_UNCONFIRMED', 'PEER_CHANGED', 'PHP_PEER_REFUSED', 'DB_PEER_REFUSED',
           'INTERNAL_REFUSED', 'PRE_ENTRY_UNIT_REFUSED', 'PRE_ENTRY_ENV_REFUSED', 'PRE_ENTRY_CONFIG_REFUSED',
           'PRE_ENTRY_HOOK_REFUSED', 'PRE_ENTRY_SELECTION_REFUSED', 'PRE_ENTRY_CHANGED', 'PRE_ENTRY_LIMIT', 'STAGING_VIEW_REFUSED')
FD_REASONS = tuple(role + '_' + code for role in ('DB', 'PHP', 'PROXY') for code in
                   ('FD_ENTRY_LIMIT', 'FD_NAME_REFUSED', 'FD_TARGET_LIMIT', 'FD_DISAPPEARED',
                    'FD_ACCESS_REFUSED', 'FD_IO_REFUSED'))
REPORT_FIELDS = ('status', 'stage', 'reason', 'configured_runtime', 'local_peer', 'sql', 'metadata', 'fastcgi_state', 'pre_entry', 'effective_ini_selection', 'worker_memory', 'dependency_trust',
                 'synthetic_provenance', 'grants', 'egress_isolation', 'arbitrary_request_binding')
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


def staging_valid(staging):
    def identity(row):
        return (type(row['device']) is int and 0 <= row['device'] < 2 ** 64
                and type(row['inode']) is int and 0 < row['inode'] < 2 ** 64)

    if (type(staging) is not dict or set(staging) != {'path', 'device', 'inode', 'files'}
            or type(staging['path']) is not str
            or re.fullmatch('/run/jsm-db-2760-[0-9a-f]{32}', staging['path']) is None
            or not identity(staging) or type(staging['files']) is not dict or set(staging['files']) != set(PHP_FILES)):
        return False
    return all(type(row) is dict and set(row) == {'device', 'inode', 'size', 'sha256'}
               and identity(row) and row['device'] == staging['device']
               and type(row['size']) is int and 0 < row['size'] <= 128 * 1024
               and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
               for row in staging['files'].values())


def report_valid(report):
    if (type(report) is not dict or set(report) != set(REPORT_FIELDS) or report['stage'] not in STAGES
            or report['fastcgi_state'] not in ('NOT_SENT', 'FINISHED', 'UNCONFIRMED')):
        return False
    if (report['pre_entry'] not in ('NOT_ESTABLISHED','OBSERVED')
            or report['effective_ini_selection']!='NOT_ATTESTED' or report['worker_memory']!='NOT_ATTESTED'
            or report['dependency_trust']!='INSTALLED_PHP_AND_VENDOR_NOT_ATTESTED'
            or any(report[key]!='UNKNOWN' for key in ('synthetic_provenance','grants','egress_isolation'))
            or report['arbitrary_request_binding']!='NOT_ESTABLISHED'):
        return False
    observed = 'OBSERVED'
    sql = report['sql']
    if report['status'] == 'BLOCKED':
        return (report['reason'] in REASONS + FD_REASONS
                and report['metadata'] is None and report['configured_runtime'] == 'NOT_ESTABLISHED'
                and report['local_peer'] in ('NOT_ESTABLISHED', observed)
                and sql in ('NOT_ATTEMPTED', 'AUTHORIZED_NOT_CONFIRMED', 'ONE_METADATA_SELECT_OBSERVED')
                and (sql == 'NOT_ATTEMPTED' or report['local_peer'] == observed and report['fastcgi_state'] != 'NOT_SENT'))
    metadata = report['metadata']
    return (report['status'] == observed and report['stage'] == 'COMPLETE' and report['reason'] is None
            and report['pre_entry']=='OBSERVED' and report['fastcgi_state'] == 'FINISHED' and report['configured_runtime'] == report['local_peer'] == observed
            and sql == 'ONE_METADATA_SELECT_OBSERVED' and type(metadata) is dict
            and set(metadata) == {'schema_matches', 'principal_kind', 'version_family', 'server_read_only', 'query_count'}
            and metadata['schema_matches'] is True and metadata['principal_kind'] in ('ROOT', 'OTHER')
            and metadata['version_family'] in ('MYSQL_5_7', 'MYSQL_8', 'MARIADB', 'OTHER')
            and type(metadata['server_read_only']) is bool and type(metadata['query_count']) is int
            and metadata['query_count'] == 1)
