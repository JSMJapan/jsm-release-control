"""Bounded TEST-only profile, TLS and Claude relay. No live defaults are provided."""

import errno
from hashlib import sha256
from http.client import HTTPSConnection
from ipaddress import IPv4Address
import os
from pathlib import Path
import re
import socket
import ssl
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apache_parity_bridge import strict_json
from eva_test_archive import require
from eva_test_ingress import ApacheIngress, Ingress, ISOLATED_HOST
from article_test_state import canonical

TLS_DIRECTORY = Path('/etc/jsm-eva-test-1620')
LEASE_SECONDS = 720
LIVE_ENV = {
    'gate-user': 'EVA_ISOLATED_GATE_USERNAME', 'gate-password': 'EVA_ISOLATED_GATE_PASSWORD',
    'bridge-secret': 'EVA_ISOLATED_BRIDGE_SECRET', 'anthropic': 'EVA_ISOLATED_ANTHROPIC_KEY',
}
LIVE_FIELDS = {'status', 'origin', 'ingress', 'provider_ipv4', 'certificate_sha256'}
APACHE_FIELDS = LIVE_FIELDS | {'vhost_sha256'}
DEDICATED_FIELDS = LIVE_FIELDS | {'listen_ipv4'}


def live_policy(raw):
    value = strict_json(raw.decode('ascii'))
    require(type(value) is dict and value.get('status') == 'PINNED', 'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    ingress = value.get('ingress')
    require((ingress == 'existing-apache' and value.keys() == APACHE_FIELDS)
            or (ingress == 'dedicated' and value.keys() == DEDICATED_FIELDS), 'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    origin = value['origin']
    require(type(origin) is str and origin.startswith('https://') and ISOLATED_HOST.fullmatch(origin[8:]),
            'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    provider = IPv4Address(value['provider_ipv4'])
    require(str(provider) == value['provider_ipv4'] and provider.is_global and not provider.is_multicast
            and type(value['certificate_sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['certificate_sha256']),
            'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    if ingress == 'existing-apache':
        require(type(value['vhost_sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['vhost_sha256']),
                'EVA_TEST_VHOST_REFUSED')
    else:
        listen = IPv4Address(value['listen_ipv4'])
        require(str(listen) == value['listen_ipv4'] and listen.is_private and not listen.is_unspecified
                and not listen.is_loopback and not listen.is_link_local and not listen.is_multicast,
                'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    return value

def validate_credentials(value):
    patterns = {
        'gate-user': r'[A-Za-z0-9_-]{3,48}', 'gate-password': r'[!-~]{18,128}', 'bridge-secret': '[a-f0-9]{64}',
        'anthropic': r'[A-Za-z0-9_-]{16,256}',
    }
    require(type(value) is dict and value.keys() == patterns.keys()
            and all(type(value[key]) is str and re.fullmatch(pattern, value[key]) for key, pattern in patterns.items()),
            'EVA_LIVE_INPUTS_NOT_CONFIGURED')
    return value


def env_credentials(env):
    return canonical(validate_credentials({name: env.get(key) for name, key in LIVE_ENV.items()}))


def read_credentials(raw):
    value = validate_credentials(strict_json(raw.decode('ascii')))
    require(canonical(value) == raw, 'EVA_LIVE_INPUTS_NOT_CONFIGURED')
    return value


def load_policy(root=None):
    folder = Path(__file__).resolve().parent if root is None else Path(root)
    with (folder / 'eva_test_live_policy.json').open('rb') as source:
        raw = source.read(2049)
    require(len(raw) <= 2048, 'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    return live_policy(raw)


def verify_certificate(certificate, policy):
    body = certificate.read_bytes()
    require(0 < len(body) <= 32768, 'EVA_LIVE_PROFILE_NOT_PROVISIONED')
    text = body.decode('ascii')
    leaf = text.split('-----END CERTIFICATE-----', 1)[0] + '-----END CERTIFICATE-----'
    fingerprint = sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest()
    require(fingerprint == policy['certificate_sha256'], 'EVA_LIVE_PROFILE_NOT_PROVISIONED')


def connection_at(address):
    class AnthropicConnection(HTTPSConnection):
        def connect(self):
            require(self.host == 'api.anthropic.com' and self.port == 443, 'EVA_LIVE_SERVICE_REFUSED')
            output = socket.create_connection((address, 443), timeout=self.timeout)
            try:
                self.sock = self._context.wrap_socket(output, server_hostname=self.host)
            except BaseException:
                output.close()
                raise
    return AnthropicConnection


def prove_egress_guard():
    # No data is sent. A denied IPv4 connect confirms that the relay's cgroup
    # actually enforces its allow rule on this kernel, before any paid activity.
    try:
        with socket.create_connection(('127.0.0.2', 1), timeout=1):
            pass
    except OSError as failure:
        require(failure.errno in (errno.EPERM, errno.EACCES), 'EVA_LIVE_PROVIDER_ISOLATION_REFUSED')
        return
    require(False, 'EVA_LIVE_PROVIDER_ISOLATION_REFUSED')


def relay(run, expires):
    prove_egress_guard()
    directory = Path(os.environ['CREDENTIALS_DIRECTORY'])
    with (directory / 'anthropic').open('rb') as file:
        key = file.read(257).decode('ascii')
    require(re.fullmatch('[A-Za-z0-9_-]{16,256}', key), 'EVA_LIVE_INPUTS_NOT_CONFIGURED')
    sys.path.insert(0, '/run/eva-relay-code')
    os.environ['ANTHROPIC_API_KEY'] = key
    import provider
    provider.HTTPSConnection = connection_at(load_policy()['provider_ipv4'])
    provider.main()


def https(run, expires):
    policy = load_policy()
    unix = '/run/eva-ingress/http.sock'
    if policy['ingress'] == 'existing-apache':
        server = ApacheIngress(policy['origin'][8:], unix, run, expires)
    else:
        directory = Path(os.environ['CREDENTIALS_DIRECTORY'])
        certificate, key = directory / 'certificate', directory / 'key'
        verify_certificate(certificate, policy)
        server = Ingress((policy['listen_ipv4'], 443), policy['origin'][8:], unix, certificate, key, run=run, expires=expires)
    with server:
        server.serve_forever(poll_interval=0.5)


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 4 and sys.argv[1] in ('https', 'relay') and re.fullmatch('[a-f0-9]{12}', sys.argv[2])
                and re.fullmatch('[1-9][0-9]{9}', sys.argv[3]),
                'EVA_LIVE_PROFILE_NOT_PROVISIONED')
        {'https': https, 'relay': relay}[sys.argv[1]](sys.argv[2], int(sys.argv[3]))
    except (OSError, ValueError, KeyError, ImportError):
        raise SystemExit('EVA_LIVE_SERVICE_REFUSED') from None
