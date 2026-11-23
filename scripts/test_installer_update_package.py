"""Deterministic TEST installer splice. No copy of the installer is shipped."""

from hashlib import sha256

PROTOCOL = 'jsm-test-installer-update-v1'
OPERATIONS = ('CHECK', 'APPLY', 'ROLLBACK')
ORIGINAL_SIZE = 8033
ORIGINAL_SHA256 = '4b0815ff755c6b29165a8102f2bc47c2a7dd49a567b367b2c55637522996a6cc'
UPDATED_SHA256 = '2708153242a0efb911db34978bd4bbe8c345964156e9b908e8e1fdfbdbff7518'
ANCHOR = b'trap - EXIT\n'
REPORTER = '/usr/local/libexec/jsm-test-db-report'
HOOK = (
    b'# JSM TEST installer report (#2760)\n'
    b'/usr/bin/env -i PATH=/usr/bin:/bin LANG=C '
    b'/usr/bin/timeout --signal=TERM --kill-after=1 3 '
    + REPORTER.encode('ascii')
    + b' </dev/null >/dev/null 2>&1 || :\n'
)
UPDATED_SIZE = ORIGINAL_SIZE + len(HOOK)
MAX_INSTALLER_BYTES = UPDATED_SIZE
STATUSES = frozenset((
    'READY', 'APPLIED', 'ROLLED_BACK', 'ALREADY_APPLIED', 'ALREADY_ORIGINAL',
    'PREIMAGE_REFUSED', 'REPORTER_UNAVAILABLE', 'TARGET_REFUSED', 'LOCK_REFUSED',
    'WRITE_REFUSED', 'READBACK_UNCERTAIN', 'REQUEST_REFUSED',
))


def transform(raw, operation):
    """Calculate only the pinned transition or inverse. Writes are separate."""
    if operation not in OPERATIONS:
        return 'REQUEST_REFUSED', None
    if type(raw) is not bytes or len(raw) not in (ORIGINAL_SIZE, UPDATED_SIZE):
        return 'PREIMAGE_REFUSED', None
    digest = sha256(raw).hexdigest()
    if len(raw) == ORIGINAL_SIZE and digest == ORIGINAL_SHA256:
        if operation == 'ROLLBACK':
            return 'ALREADY_ORIGINAL', None
        if raw.count(ANCHOR) != 1 or HOOK in raw:
            return 'PREIMAGE_REFUSED', None
        result = raw.replace(ANCHOR, HOOK + ANCHOR, 1)
        if len(result) != UPDATED_SIZE or sha256(result).hexdigest() != UPDATED_SHA256:
            return 'PREIMAGE_REFUSED', None
        return 'READY', result if operation == 'APPLY' else None

    if len(raw) == UPDATED_SIZE and digest == UPDATED_SHA256:
        if operation != 'ROLLBACK':
            return 'ALREADY_APPLIED', None
        if raw.count(HOOK + ANCHOR) != 1:
            return 'PREIMAGE_REFUSED', None
        result = raw.replace(HOOK + ANCHOR, ANCHOR, 1)
        if len(result) != ORIGINAL_SIZE or sha256(result).hexdigest() != ORIGINAL_SHA256:
            return 'PREIMAGE_REFUSED', None
        return 'READY', result

    return 'PREIMAGE_REFUSED', None
