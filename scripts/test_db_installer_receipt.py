"""Pure producer and verifier for a reviewed TEST installer report (#2760).

This interface does not observe a deployed application or authenticate sources.
Only a separately authorized caller can supply independently authenticated pins.
"""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
import re
from typing import Optional


_VERSION = 'jsm-test-db-installer-receipt-v1'
_MAX_BYTES = 4096
_PEER_DOMAIN = b'jsm-test-db-installer-peer-v1\x00'
_SCOPE = (
    ('repository', 'JSMJapan/jsm-storefront'),
    ('workflow', '.github/workflows/sandbox-publish.yml'),
    ('ref', 'refs/heads/main'),
    ('event', 'workflow_dispatch'),
    ('deployment_environment', 'sandbox'),
    ('host', 'develop.jsmjapan.com'),
    ('project', 'dark-berm-508215-d2'),
    ('zone', 'asia-northeast1-a'),
    ('vm_id', '150919059249400713'),
    ('vm_name', 'jsm-sandbox'),
    ('environment', 'TEST'),
)
_BINDING = (
    ('path', '/api'),
    ('web_server', 'APACHE'),
    ('handler', 'PROXY_FCGI'),
    ('fpm_service', 'php7.4-fpm.service'),
    ('fpm_pool', 'www'),
    ('db_family', 'MYSQL'),
)
_RUN_FIELDS = {'workflow_sha', 'requested_site_sha', 'id', 'attempt', 'actor', 'triggering_actor'}
_GENERATION_FIELDS = {'installed_site_sha', 'apache_sha256', 'php_sha256', 'descriptor_sha256', 'db_target_sha256'}
_PEER_FIELDS = {'route', 'php_leg_sha256', 'db_leg_sha256', 'db_target_sha256', 'forwarding_sha256'}
_REPORT_FIELDS = {'version', 'scope', 'run', 'installer_provenance_sha256', 'observation', 'binding', 'peer'}


@dataclass(frozen=True)
class ServingGeneration:
    installed_site_sha: str
    apache_sha256: str
    php_sha256: str
    descriptor_sha256: str
    db_target_sha256: str


@dataclass(frozen=True)
class PeerEvidence:
    route: str
    php_leg_sha256: str
    db_leg_sha256: str
    db_target_sha256: str
    forwarding_sha256: Optional[str] = None


@dataclass(frozen=True)
class AuthenticatedPins:
    """Values acquired from trusted sources outside this library.

    Constructing this data object grants no authority. Its provenance and the
    freshness of the current generation and clock are the caller's obligation.
    """
    receipt_sha256: str
    workflow_sha: str
    requested_site_sha: str
    run_id: str
    run_attempt: int
    actor: Optional[str]
    triggering_actor: Optional[str]
    installer_provenance_sha256: str
    observation_not_before: int
    run_finished_at: int
    verify_not_after: int
    current_generation: ServingGeneration
    descriptor_sha256: str
    db_target_sha256: str
    peer_evidence_sha256: Optional[str] = None


def _hex(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def _epoch(value):
    return type(value) is int and 0 < value <= 253402300799


def _actor(value):
    return value is None or (
        type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?', value) is not None
    )


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _record(value, fields):
    return type(value) is dict and set(value) == fields


def _run(workflow_sha, requested_site_sha, run_id, run_attempt, actor, triggering_actor):
    return dict(workflow_sha=workflow_sha, requested_site_sha=requested_site_sha,
                id=run_id, attempt=run_attempt, actor=actor, triggering_actor=triggering_actor)


def _valid_run(run):
    return (
        _record(run, _RUN_FIELDS)
        and _hex(run['workflow_sha'], 40)
        and _hex(run['requested_site_sha'], 40)
        and type(run['id']) is str
        and re.fullmatch('[1-9][0-9]{0,14}', run['id']) is not None
        and type(run['attempt']) is int
        and 0 < run['attempt'] <= 2147483647
        and _actor(run['actor'])
        and _actor(run['triggering_actor'])
    )


def _generation(value):
    if type(value) is not ServingGeneration:
        return None
    return dict(installed_site_sha=value.installed_site_sha, apache_sha256=value.apache_sha256,
                php_sha256=value.php_sha256, descriptor_sha256=value.descriptor_sha256, db_target_sha256=value.db_target_sha256)


def _valid_generation(value, site_sha):
    return (
        _record(value, _GENERATION_FIELDS)
        and _hex(value['installed_site_sha'], 40)
        and value['installed_site_sha'] == site_sha
        and all(_hex(value[key]) for key in _GENERATION_FIELDS - {'installed_site_sha'})
    )


def _peer(value):
    return dict(route=value.route, php_leg_sha256=value.php_leg_sha256, db_leg_sha256=value.db_leg_sha256,
                db_target_sha256=value.db_target_sha256, forwarding_sha256=value.forwarding_sha256)


def _valid_peer(value, db_target_sha256):
    if (not _record(value, _PEER_FIELDS) or type(value['route']) is not str
            or not _hex(value['db_target_sha256']) or value['db_target_sha256'] != db_target_sha256):
        return False
    if not _hex(value['php_leg_sha256']) or not _hex(value['db_leg_sha256']):
        return False
    if value['php_leg_sha256'] == value['db_leg_sha256']:
        return False
    if value['route'] == 'DIRECT':
        return value['forwarding_sha256'] is None
    return (
        value['route'] in ('PROXY', 'DNAT')
        and _hex(value['forwarding_sha256'])
        and value['forwarding_sha256'] not in (value['php_leg_sha256'], value['db_leg_sha256'])
    )


def _valid_report(value):
    if not _record(value, _REPORT_FIELDS) or value['version'] != _VERSION or value['scope'] != dict(_SCOPE):
        return False
    run = value['run']
    if not _valid_run(run) or not _hex(value['installer_provenance_sha256']):
        return False
    observation = value['observation']
    if not _record(observation, {'from', 'until', 'before', 'after'}):
        return False
    if not _epoch(observation['from']) or not _epoch(observation['until']) or observation['from'] > observation['until']:
        return False
    if not _valid_generation(observation['before'], run['requested_site_sha']) or observation['after'] != observation['before']:
        return False
    binding = value['binding']
    fixed = dict(_BINDING)
    if not _record(binding, set(fixed) | {'descriptor_sha256', 'db_target_sha256'}):
        return False
    if any(binding[key] != expected for key, expected in fixed.items()):
        return False
    if any(binding[key] != observation['before'][key] for key in ('descriptor_sha256', 'db_target_sha256')):
        return False
    return value['peer'] is None or _valid_peer(value['peer'], binding['db_target_sha256'])


def render_installer_receipt(*, workflow_sha, requested_site_sha, run_id, run_attempt, actor, triggering_actor,
                             installer_provenance_sha256, observed_from, observed_until, before, after, peer=None):
    """Serialize verified observations from a future authorized installer.

    Only precomputed, nonsecret projections are accepted. Fixed route labels
    describe the observations the caller must make and do not observe the route.
    """
    if type(before) is not ServingGeneration or (peer is not None and type(peer) is not PeerEvidence):
        raise ValueError('INVALID_INSTALLER_REPORT')
    value = dict(
        version=_VERSION,
        scope=dict(_SCOPE),
        run=_run(workflow_sha, requested_site_sha, run_id, run_attempt, actor, triggering_actor),
        installer_provenance_sha256=installer_provenance_sha256,
        observation={'from': observed_from, 'until': observed_until, 'before': _generation(before), 'after': _generation(after)},
        binding=dict(_BINDING, descriptor_sha256=before.descriptor_sha256, db_target_sha256=before.db_target_sha256),
        peer=None if peer is None else _peer(peer),
    )
    if not _valid_report(value):
        raise ValueError('INVALID_INSTALLER_REPORT')
    return _canonical(value)


def _report_digest(raw):
    return sha256(raw).hexdigest()


def _verdict(reason, *, configuration_verified=False, peer_verified=False):
    return dict(status='VERIFIED_REPORT' if configuration_verified else 'BLOCKED', reason=reason,
                configuration_binding='VERIFIED' if configuration_verified else 'UNKNOWN',
                actual_db_peer='VERIFIED' if peer_verified else 'UNKNOWN',
                db_isolation='NOT_ESTABLISHED', db_admission='NOT_ESTABLISHED')


def verify_installer_receipt(raw=None, *, pins=None, now=None):
    """Compare a canonical report to separately authenticated caller inputs.

    This verifies correspondence, not the authenticity of the caller's inputs
    or the present state of TEST. Neither result grants any database admission.
    """
    if raw is None or pins is None:
        return _verdict('TRUSTED_REPORT_UNAVAILABLE')
    if type(pins) is not AuthenticatedPins or not _hex(pins.receipt_sha256) or not _epoch(now):
        return _verdict('INVALID_AUTHENTICATED_CONTEXT')
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_BYTES:
        return _verdict('INVALID_INSTALLER_REPORT')
    if not compare_digest(_report_digest(raw), pins.receipt_sha256):
        return _verdict('REPORT_DIGEST_MISMATCH')
    try:
        value = json.loads(raw.decode('ascii'))
        if not _valid_report(value) or _canonical(value) != raw:
            return _verdict('INVALID_INSTALLER_REPORT')
    except (ValueError, UnicodeError, RecursionError):
        return _verdict('INVALID_INSTALLER_REPORT')

    run = _run(pins.workflow_sha, pins.requested_site_sha, pins.run_id, pins.run_attempt, pins.actor, pins.triggering_actor)
    generation = _generation(pins.current_generation)
    if (not _valid_run(run) or not _valid_generation(generation, run['requested_site_sha'])
            or not all(_hex(item) for item in (pins.installer_provenance_sha256, pins.descriptor_sha256, pins.db_target_sha256))
            or (pins.peer_evidence_sha256 is not None and not _hex(pins.peer_evidence_sha256))
            or not all(_epoch(item) for item in (pins.observation_not_before, pins.run_finished_at, pins.verify_not_after))):
        return _verdict('INVALID_AUTHENTICATED_CONTEXT')

    observation = value['observation']
    if not pins.observation_not_before <= observation['from'] <= observation['until'] <= pins.run_finished_at <= now <= pins.verify_not_after:
        return _verdict('OBSERVATION_OUTSIDE_TRUSTED_WINDOW')
    binding = value['binding']
    if (value['run'] != run or value['installer_provenance_sha256'] != pins.installer_provenance_sha256
            or observation['after'] != generation or binding['descriptor_sha256'] != pins.descriptor_sha256
            or binding['db_target_sha256'] != pins.db_target_sha256):
        return _verdict('AUTHENTICATED_CONTEXT_MISMATCH')

    peer = value['peer']
    peer_verified = peer is not None and pins.peer_evidence_sha256 is not None and compare_digest(
        _report_digest(_PEER_DOMAIN + raw), pins.peer_evidence_sha256)
    reason = 'PEER_VERIFIED' if peer_verified else 'CONFIGURATION_VERIFIED'
    return _verdict(reason, configuration_verified=True, peer_verified=peer_verified)
