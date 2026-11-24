"""Apache 2.4 fixture for the proposed isolated paths on existing TEST TLS."""

from contextlib import ExitStack, contextmanager
from hashlib import sha256
import http.client
from pathlib import Path
from socketserver import UnixStreamServer
import os
import shutil
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from eva_test_apache import AUTH, CONFIG, PUBLIC_BRIDGE, PUBLIC_GATE, PUBLIC_HOST, patched
from eva_test_archive import EvaRefused
from eva_test_ingress import ApacheIngress, BRIDGE
from test_eva_test_ingress import Fixture, start

APACHE = '/usr/sbin/apache2'
MODULES = Path('/usr/lib/apache2/modules')
BASE = b'''<VirtualHost *:443>
ServerName develop.jsmjapan.com
SSLEngine On
SSLCertificateFile "{certificate}"
SSLCertificateKeyFile "{key}"
RewriteEngine On
RewriteRule ^/?old$ - [R=410,L]
RewriteRule ^/? - [R=403,L]
<Location />
    AuthType Basic
    AuthName Legacy
    AuthUserFile "{users}"
    Require valid-user
</Location>
</VirtualHost>
'''


class PatchTests(unittest.TestCase):
    def test_route_order_and_refusal_for_unknown_or_already_patched_bytes(self):
        baseline = BASE
        updated = patched(baseline, sha256(baseline).hexdigest())
        self.assertLess(updated.index(CONFIG), updated.index(b'RewriteRule ^/?old'))
        self.assertLess(updated.index(b'</Location>'), updated.index(AUTH))
        self.assertEqual(updated.replace(CONFIG, b'').replace(AUTH, b''), baseline)
        for raw in (updated, baseline.replace(b'develop.', b'prod.'), baseline.replace(b'SSLEngine On', b'SSLEngine Off')):
            with self.assertRaises(EvaRefused):
                patched(raw, sha256(raw).hexdigest())
        with self.assertRaises(EvaRefused):
            patched(baseline, 'f' * 64)
        for fmt in (b'%{Authorization}i', b'%{Set-Cookie}o', b'%{eva_teacher_test}C', b'%200,302{Cookie}i', b'%!401{Authorization}i',
                    b'%200{Set-Cookie}o', b'%!401{eva_teacher_test}C', b'%>200{Set-Cookie}o'):
            unsafe = baseline.replace(b'SSLEngine On', b'SSLEngine On\nLogFormat "' + fmt + b'" unsafe')
            with self.assertRaises(EvaRefused):
                patched(unsafe, sha256(unsafe).hexdigest())



def listen_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextmanager
def run_apache(config, port):
    args = [APACHE, '-f', str(config)]
    subprocess.run([*args, '-t'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    process = subprocess.Popen([*args, '-DFOREGROUND'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('synthetic Apache startup failed')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError('synthetic Apache readiness timed out')
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@unittest.skipUnless(Path(APACHE).is_file() and MODULES.is_dir() and shutil.which('openssl'),
                     'native Apache module fixture requires the Linux CI image')
class NativeApacheTests(unittest.TestCase):
    def test_existing_tls_policies_and_two_owned_routes_and_rollback(self):
        with ExitStack() as stack:
            directory = Path(stack.enter_context(TemporaryDirectory(prefix='eva-apache-', dir='/tmp')))
            directory.chmod(0o755)
            cert, key, config, users = [directory / name for name in ('ca.pem', 'ca.key', 'httpd.conf', 'empty-users')]
            openssl = directory / 'openssl.cnf'
            openssl.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN='
                               + PUBLIC_HOST + '\n[ext]\nsubjectAltName=DNS:' + PUBLIC_HOST + '\n')
            subprocess.run(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(key), '-out', str(cert), '-config', str(openssl)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=12)
            users.write_bytes(b'')
            unix = directory / 'upstream.sock'
            backend = UnixStreamServer(str(unix), Fixture)
            backend.rows = []
            start(stack, backend)
            relay = ApacheIngress('eva-fixture.jsmjapan.com', str(unix), 'a1b2c3d4e5f6', int(time.time()) + 600)
            start(stack, relay)
            port = listen_port()
            context = ssl.create_default_context(cafile=str(cert))

            modules = ('mpm_event', 'proxy', 'proxy_http', 'ssl', 'rewrite', 'authn_core', 'authz_core', 'auth_basic',
                       'authn_file', 'authz_user', 'socache_shmcb')
            master = ''.join(f'LoadModule {name}_module {MODULES}/mod_{name}.so\n' for name in modules)
            master += (f'Listen 127.0.0.1:{port}\nPidFile "{directory}/pid"\n'
                       f'ServerName {PUBLIC_HOST}\nServerRoot "{directory}"\nErrorLog /dev/null\n'
                       f'DocumentRoot "{directory}"\nUser www-data\nGroup www-data\n')
            baseline = BASE.decode().format(certificate=cert, key=key, users=users).encode()
            routed = patched(baseline, sha256(baseline).hexdigest())

            def configure(value):
                config.write_bytes(master.encode() + value.replace(b'<VirtualHost *:443>', f'<VirtualHost *:{port}>'.encode()))

            def request(method, path, headers=None, body=None, authority=PUBLIC_HOST):
                with socket.create_connection(('127.0.0.1', port), timeout=3) as channel:
                    with context.wrap_socket(channel, server_hostname=PUBLIC_HOST) as secure:
                        client = http.client.HTTPConnection(authority, timeout=3)
                        client.sock = secure
                        client.request(method, path, body, {'Host': authority, **(headers or {})})
                        result = client.getresponse()
                        return result.status, dict(result.getheaders()), result.read()

            configure(baseline)
            with run_apache(config, port):
                baseline_codes = [request('GET', path)[0] for path in ('/old', '/__gate/', PUBLIC_GATE, PUBLIC_BRIDGE)]
            configure(routed)
            with run_apache(config, port):
                self.assertEqual([request('GET', item)[0] for item in ('/old', '/__gate/')], baseline_codes[:2])
                code, headers, _ = request('GET', PUBLIC_GATE)
                self.assertEqual((code, headers['X-Eva-Test-Run']), (401, 'a1b2c3d4e5f6'))
                self.assertNotEqual(request('GET', PUBLIC_GATE, authority='foreign.invalid')[0], 302)
                self.assertNotEqual(request('GET', PUBLIC_GATE.replace('/gate?', '/gate/one?'))[0], 302)
                code, headers, _ = request('GET', PUBLIC_GATE, {'Authorization': 'Basic Zml4dHVyZQ=='})
                self.assertEqual(code, 302)
                self.assertIn('Path=' + PUBLIC_BRIDGE, headers['Set-Cookie'])
                code, _, _ = request('POST', PUBLIC_BRIDGE, {'Content-Type': 'application/json',
                                     'Cookie': 'eva_teacher_test=synthetic', 'X-Eva-Teacher-Secret': 'a' * 64}, b'{}')
                self.assertEqual(code, 200)
                self.assertEqual([row[1] for row in backend.rows], ['/__gate/?next=%2Fru%2F', BRIDGE])
            self.assertEqual(routed.replace(CONFIG, b'').replace(AUTH, b''), baseline)
            configure(baseline)
            with run_apache(config, port):
                self.assertEqual([request('GET', path)[0] for path in ('/old', '/__gate/', PUBLIC_GATE, PUBLIC_BRIDGE)],
                                 baseline_codes)
