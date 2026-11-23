"""Private one-shot FPM dialogue; no transport to TEST and no SQL here.

The caller supplies a context obtained by the protected private publisher.
Syntax validation is not authentication of GitHub, a VM or a database.
"""
import hashlib
import hmac
import json
import re
import time

from apache_parity_bridge import strict_json
from test_db_installer_receipt import _SCOPE, _valid_run

VERSION = 'jsm-test-db-runtime-2760-v1'
MAX_FRAME = 4096
TOTAL_SECONDS = 3
IO_SECONDS = .75
ROLES = ('ROOT', 'PHP')
STAGES = ('HELLO', 'TARGET', 'OPEN', 'CONNECTED', 'SELECT', 'RESULT', 'ABORT', 'REFUSED')
PHP_REASONS = ('STARTUP_REFUSED','CONFIG_SHAPE_REFUSED','GENERATED_CONFIG_REFUSED','STARTUP_SOURCE_REFUSED',
    'STARTUP_HOOK_REFUSED','STARTUP_CONTEXT_REFUSED','VENDOR_PROFILE_REFUSED','APPLICATION_REFUSED',
    'DB_DEFINITION_REFUSED','PDO_ATTRIBUTE_REFUSED','PDO_CAPABILITY_REFUSED','PDO_AUTH_REFUSED',
    'PDO_CONNECT_REFUSED','PDO_QUERY_REFUSED','METADATA_REFUSED','INTERNAL_REFUSED','DEADLINE')


class Rejected(ValueError):
    """Only code-owned reasons may cross the private/public boundary."""
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def context_digest(context):
    if (type(context) is not dict or set(context) != {'scope', 'run', 'control_sha'}
            or context['scope'] != dict(_SCOPE) or not _valid_run(context['run'])
            or context['run']['attempt'] != 1
            or type(context['control_sha']) is not str
            or not re.fullmatch('[0-9a-f]{40}', context['control_sha'])):
        raise Rejected('CONTEXT_REQUIRED')
    return hashlib.sha256(canonical(context)).hexdigest()


def _key(nonce):
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise Rejected('NONCE_REQUIRED')
    return bytes.fromhex(nonce)


def _tag(nonce, digest, role, sequence, payload):
    return hmac.new(_key(nonce), b'jsm-test-db-runtime-2760\0' + digest.encode('ascii')
                    + b'\0' + role.encode('ascii') + b'\0' + str(sequence).encode('ascii')
                    + b'\0' + canonical(payload), hashlib.sha256).hexdigest()


def payload_valid(role, sequence, value):
    """No free-form objects/floats; PHP and Python sign exactly the same domain."""
    if type(value) is not dict:
        return False
    stage = value.get('stage')
    if role == 'ROOT':
        if sequence == 0:
            return (set(value) == {'stage', 'publisher_uid'} and stage == 'HELLO'
                    and type(value['publisher_uid']) is int and 0 < value['publisher_uid'] <= 2147483647)
        if sequence in (2, 4):
            return set(value) == {'stage'} and stage in (('OPEN', 'ABORT') if sequence == 2 else ('SELECT', 'ABORT'))
        if sequence == 6:
            return (set(value) == {'stage', 'accepted'} and stage == 'RESULT'
                    and type(value['accepted']) is bool)
    if role == 'PHP':
        if sequence in (1, 3, 5) and stage == 'REFUSED':
            return set(value) == {'stage','reason'} and value['reason'] in PHP_REASONS
        if sequence == 1:
            return (set(value) == {'stage', 'host', 'port', 'schema', 'same_db'} and stage == 'TARGET'
                    and value['host'] == '127.0.0.1' and type(value['port']) is int and 1 <= value['port'] <= 65535
                    and type(value['schema']) is str and re.fullmatch('[A-Za-z0-9_]{1,64}', value['schema']) is not None
                    and value['same_db'] is True)
        if sequence == 3:
            return set(value) == {'stage', 'native_pdo'} and stage == 'CONNECTED' and value['native_pdo'] is True
        if sequence == 5:
            return (set(value) == {'stage', 'schema_matches', 'principal_kind', 'version_family', 'server_read_only', 'query_count'}
                    and stage == 'RESULT' and type(value['schema_matches']) is bool
                    and value['principal_kind'] in ('ROOT', 'OTHER')
                    and value['version_family'] in ('MYSQL_5_7', 'MYSQL_8', 'MARIADB', 'OTHER')
                    and type(value['server_read_only']) is bool and type(value['query_count']) is int
                    and value['query_count'] == 1)
    return False


def encode(nonce, digest, role, sequence, payload):
    if (type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None
            or role not in ROLES or type(sequence) is not int or not 0 <= sequence <= 6
            or not payload_valid(role, sequence, payload)):
        raise Rejected('FRAME_REFUSED')
    try:
        result = canonical(dict(context=digest, role=role, sequence=sequence,
                                payload=payload, tag=_tag(nonce, digest, role, sequence, payload)))
    except (ValueError, TypeError, UnicodeError):
        raise Rejected('FRAME_REFUSED') from None
    if len(result) > MAX_FRAME:
        raise Rejected('FRAME_LIMIT')
    return result


def decode(raw, nonce, digest, role, sequence):
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_FRAME:
            raise ValueError()
        value = strict_json(raw.decode('ascii'))
        if (type(value) is not dict or set(value) != {'context', 'role', 'sequence', 'payload', 'tag'}
                or canonical(value) != raw or value['context'] != digest or value['role'] != role
                or type(value['sequence']) is not int or value['sequence'] != sequence
                or type(value['tag']) is not str or re.fullmatch('[0-9a-f]{64}', value['tag']) is None
                or not hmac.compare_digest(value['tag'], _tag(nonce, digest, role, sequence, value['payload']))):
            raise ValueError()
        # Reuse the encoder's type/domain checks, without retaining raw input.
        if encode(nonce, digest, role, sequence, value['payload']) != raw:
            raise ValueError()
        return value['payload']
    except Exception:
        raise Rejected('FRAME_REFUSED') from None


class Wire:
    """An existing private connected socket, with an absolute caller deadline."""
    def __init__(self, stream, nonce, digest, deadline):
        _key(nonce)
        self.stream, self.nonce, self.digest, self.deadline = stream, nonce, digest, deadline

    def _timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Rejected('DEADLINE')
        self.stream.settimeout(min(IO_SECONDS, remaining))

    def send(self, role, sequence, payload):
        raw = encode(self.nonce, self.digest, role, sequence, payload)
        self._timeout()
        try:
            self.stream.sendall(raw)
            self._timeout()
        except Rejected:
            raise
        except Exception:
            raise Rejected('CHANNEL_REFUSED') from None

    def receive(self, role, sequence):
        raw = bytearray()
        try:
            while not raw.endswith(b'\n'):
                self._timeout()
                part = self.stream.recv(min(1024, MAX_FRAME + 1 - len(raw)))
                if not part or len(raw) + len(part) > MAX_FRAME:
                    raise Rejected('FRAME_LIMIT')
                raw.extend(part)
            self._timeout()
            return decode(bytes(raw), self.nonce, self.digest, role, sequence)
        except Rejected:
            raise
        except Exception:
            raise Rejected('CHANNEL_REFUSED') from None
