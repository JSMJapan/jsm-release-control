"""Native TLS/SNI and Unix route checks using a generated local-only certificate."""

from contextlib import ExitStack
import http.client
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import shutil
import socket
from socketserver import UnixStreamServer
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from eva_test_ingress import BRIDGE, CI_HOST, GATE, Ingress


def start(stack, server):
    stack.callback(server.server_close)
    worker = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    worker.start()
    stack.callback(worker.join, 4)
    stack.callback(server.shutdown)


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.rows.append((self.command, self.path, dict(self.headers), None))
        self.send_response_only(302)
        self.send_header('Location', '/ru/')
        self.send_header('Set-Cookie', 'eva_teacher_test=synthetic; Secure; HttpOnly; SameSite=Strict; Path=' + BRIDGE)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        self.server.rows.append((self.command, self.path, dict(self.headers), raw))
        reply = b'{"success":true}'
        self.send_response_only(200)
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for native TLS fixture')
class NativeIngressTests(unittest.TestCase):
    def test_exact_sni_host_and_gateway_paths_to_disposable_socket(self):
        with ExitStack() as stack:
            directory = Path(stack.enter_context(TemporaryDirectory(prefix='eva-tls-', dir='/tmp')))
            cert, key, config = (directory / name for name in ('test.pem', 'test.key', 'test.cnf'))
            config.write_text('[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = ext\n'
                              '[dn]\nCN = ' + CI_HOST + '\n[ext]\nsubjectAltName = DNS:' + CI_HOST + '\n')
            subprocess.run(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(key), '-out', str(cert), '-config', str(config)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=20)
            unix = directory / 'eva.sock'
            service = UnixStreamServer(str(unix), Fixture)
            service.rows = []
            start(stack, service)
            ingress = Ingress(('127.0.0.1', 0), CI_HOST, str(unix), cert, key, fixture=True)
            start(stack, ingress)
            context = ssl.create_default_context(cafile=str(cert))

            def request(host, method, path, headers=None, body=None, authority=CI_HOST, trust=context):
                with socket.create_connection(ingress.server_address, timeout=3) as raw:
                    tls = trust.wrap_socket(raw, server_hostname=host)
                    with tls:
                        client = http.client.HTTPConnection(authority, timeout=3)
                        client.sock = tls
                        client.request(method, path, body, {'Host': authority, **(headers or {})})
                        result = client.getresponse()
                        return result.status, dict(result.getheaders()), result.read()

            with self.assertRaises(ssl.SSLError):
                request('develop.jsmjapan.com', 'GET', GATE, {'Authorization': 'Basic Zml4dHVyZQ=='})
            with self.assertRaises(ssl.SSLError):
                request(CI_HOST, 'GET', GATE, trust=ssl.create_default_context())
            self.assertEqual(request(CI_HOST, 'GET', GATE, authority='develop.jsmjapan.com')[0], 404)
            self.assertEqual(request(CI_HOST, 'GET', '/')[0], 404)
            self.assertEqual(request(CI_HOST, 'GET', GATE)[0], 401)
            self.assertEqual(service.rows, [])
            status, headers, body = request(CI_HOST, 'GET', GATE, {'Authorization': 'Basic Zml4dHVyZQ=='})
            self.assertEqual((status, headers['Location'], body), (302, '/ru/', b''))
            self.assertIn('Secure', headers['Set-Cookie'])
            self.assertEqual(service.rows[0][:2], ('GET', GATE))
            self.assertEqual(service.rows[0][2]['Authorization'], 'Basic Zml4dHVyZQ==')
            self.assertEqual(request(CI_HOST, 'POST', BRIDGE + '?different=1')[0], 404)
            body = '{"question":"Учебная посылка"}'.encode('utf-8')
            status, _, answer = request(CI_HOST, 'POST', BRIDGE, {'Content-Type': 'application/json',
                                        'Cookie': 'eva_teacher_test=synthetic', 'X-Eva-Teacher-Secret': 'a' * 64}, body)
            self.assertEqual((status, answer), (200, b'{"success":true}'))
            self.assertEqual(service.rows[1][3], body)
            self.assertNotIn('Authorization', service.rows[1][2])

    def test_no_wildcard_shared_or_loopback_live_bind(self):
        for ip in ('0.0.0.0', '127.0.0.1', '169.254.169.254'):
            with self.subTest(ip=ip), self.assertRaisesRegex(ValueError, 'EVA_TLS_BINDING_REFUSED'):
                Ingress((ip, 443), 'eva-test-1620.jsmjapan.com', None, None, None)
        with self.assertRaisesRegex(ValueError, 'EVA_TLS_BINDING_REFUSED'):
            Ingress(('192.0.2.5', 443), 'develop.jsmjapan.com', None, None, None)


class IngressTimeoutTests(unittest.TestCase):
    def test_unix_connect_and_response_have_different_limits(self):
        from unittest.mock import Mock, patch
        import eva_test_ingress as tls
        clock = [10.0]
        sock = Mock()

        def connect(_):
            clock[0] += 2

        sock.connect.side_effect = connect
        with (patch.object(tls.time, 'monotonic', side_effect=lambda: clock[0]),
              patch.object(tls.socket, 'socket', return_value=sock)):
            client = tls.UnixClient('/tmp/synthetic', CI_HOST, 54)
            client.connect()
            self.assertEqual([call.args[0] for call in sock.settimeout.call_args_list], [4.0, 42.0])
            reader = tls.DeadlineReader(sock, 54)
            clock[0] = 18
            reader.readinto(bytearray(8))
            self.assertEqual(sock.settimeout.call_args.args, (36,))
            clock[0] = 55
            with self.assertRaises(TimeoutError):
                reader.readinto(bytearray(8))
            self.assertEqual(sock.makefile.return_value.readinto.call_count, 1)
            reader.close()
