"""HTTPS ingress for an explicitly proven Eva-only address and Unix listener.

The local stage does not use this module to open ports. The same boundary can be
tested offline against a synthetic TLS certificate and a disposable Unix listener.
"""

import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Address
import io
import re
import socket
import ssl
import time

from eva_test_apache import PROFILE_PORT, PUBLIC_BRIDGE, PUBLIC_GATE, PUBLIC_HOST

GATE = '/__gate/?next=%2Fru%2F'
BRIDGE = '/api/ru/v1/eva/teacher'
CI_HOST = 'eva-teacher-test.invalid'
ISOLATED_HOST = re.compile(r'eva-[a-z0-9](?:[a-z0-9-]{0,53}[a-z0-9])?\.jsmjapan\.com')
LIMIT = 16384
REPLY_LIMIT = 65536
REQUEST_SECONDS = 48
CONNECT_SECONDS = 4


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError('EVA_TLS_DEADLINE')
    return seconds


class DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline):
        self.sock = sock
        self.raw = sock.makefile('rb', buffering=0)
        self.deadline = deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(remaining(self.deadline))
        return self.raw.readinto(buffer)

    def close(self):
        self.raw.close()
        super().close()


class TimedResponse(http.client.HTTPResponse):
    def __init__(self, sock, *, deadline, **kwargs):
        super().__init__(sock, **kwargs)
        reader = io.BufferedReader(DeadlineReader(sock, deadline))
        self.fp.close()
        self.fp = reader


class UnixClient(http.client.HTTPConnection):
    def __init__(self, path, host, deadline):
        super().__init__(host)
        self.path = path
        self.deadline = deadline
        self.response_class = lambda sock, **kwargs: TimedResponse(sock, deadline=deadline, **kwargs)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(min(CONNECT_SECONDS, remaining(self.deadline)))
        self.sock.connect(self.path)
        self.sock.settimeout(remaining(self.deadline))


class Ingress(HTTPServer):
    allow_reuse_address = False

    def __init__(self, address, host, unix_path, certificate, private_key, *, fixture=False, run=None, expires=None):
        ip = IPv4Address(address[0])
        local = fixture and host == CI_HOST and ip == IPv4Address('127.0.0.1')
        dedicated = (not fixture and ISOLATED_HOST.fullmatch(host) and address[1] == 443
                     and not ip.is_unspecified and not ip.is_loopback and not ip.is_multicast and not ip.is_link_local)
        if not (local or dedicated):
            raise ValueError('EVA_TLS_BINDING_REFUSED')
        self.authority, self.unix_path = host, unix_path
        self.upstream_authority = host
        self.gate_path, self.bridge_path = GATE, BRIDGE
        self.run, self.expires = run, expires
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certificate, private_key)
        self.context.set_servername_callback(self.sni)
        super().__init__(address, Route)

    def sni(self, _, name, __):
        if name != self.authority:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    def get_request(self):
        connection, address = super().get_request()
        try:
            connection.settimeout(4)
            return self.context.wrap_socket(connection, server_side=True), address
        except OSError:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        self.close_request(request)


class ApacheIngress(HTTPServer):
    """Loopback relay for the two path-scoped routes on existing TEST TLS."""

    allow_reuse_address = False

    def __init__(self, internal_host, unix_path, run, expires):
        if not (ISOLATED_HOST.fullmatch(internal_host) and re.fullmatch('[a-f0-9]{12}', run)):
            raise ValueError('EVA_TEST_VHOST_REFUSED')
        self.authority, self.upstream_authority = PUBLIC_HOST, internal_host
        self.gate_path, self.bridge_path = PUBLIC_GATE, PUBLIC_BRIDGE
        self.unix_path, self.run, self.expires = unix_path, run, expires
        super().__init__(('127.0.0.1', PROFILE_PORT), Route)

    def handle_error(self, request, client_address):
        self.close_request(request)


class Route(BaseHTTPRequestHandler):
    def setup(self):
        self.deadline = time.monotonic() + REQUEST_SECONDS
        super().setup()
        reader = io.BufferedReader(DeadlineReader(self.connection, self.deadline))
        self.rfile.close()
        self.rfile = reader

    def log_message(self, format, *args):
        pass

    def reply(self, code, body=b'', extra=()):
        self.connection.settimeout(remaining(self.deadline))
        self.send_response_only(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        if self.server.run is not None:
            self.send_header('X-Eva-Test-Run', self.server.run)
            self.send_header('X-Eva-Test-Expires', str(self.server.expires))
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self.reply(code)

    def single(self, header):
        values = self.headers.get_all(header, [])
        if len(values) != 1 or len(values[0]) > 4096 or any(ch in values[0] for ch in '\r\n\0'):
            raise ValueError('EVA_TLS_HEADER_REFUSED')
        return values[0]

    def admitted_authority(self):
        return (self.server.expires is None or time.time() < self.server.expires) and self.single('Host') == self.server.authority and not any(
            name in self.headers for name in ('Transfer-Encoding', 'Proxy-Authorization', 'Expect'))

    def do_GET(self):
        try:
            allowed = (self.path == self.server.gate_path and self.admitted_authority()
                       and not any(name in self.headers for name in ('Cookie', 'Content-Length', 'X-Eva-Teacher-Secret')))
            if not allowed:
                self.reply(404)
                return
            auth = self.single('Authorization')
            if not re.fullmatch(r'Basic [A-Za-z0-9+/=]{4,512}', auth):
                self.reply(401)
                return
        except ValueError:
            self.reply(401)
            return
        self.forward('GET', GATE, {'Authorization': auth}, None)

    def do_POST(self):
        try:
            allowed = self.path == self.server.bridge_path and self.admitted_authority() and 'Authorization' not in self.headers
            if not allowed:
                self.reply(404)
                return
            length = self.single('Content-Length')
            if not re.fullmatch('[1-9][0-9]{0,4}', length) or int(length) > LIMIT:
                raise ValueError('EVA_TLS_LENGTH_REFUSED')
            form = self.single('Content-Type')
            cookie, bridge = self.single('Cookie'), self.single('X-Eva-Teacher-Secret')
            if form != 'application/json' or not re.fullmatch('[a-f0-9]{64}', bridge):
                raise ValueError('EVA_TLS_HEADER_REFUSED')
            body = self.rfile.read(int(length))
            if len(body) != int(length):
                raise ValueError('EVA_TLS_LENGTH_REFUSED')
        except (ValueError, OSError):
            self.reply(400)
            return
        self.forward('POST', BRIDGE, {'Content-Type': form, 'Cookie': cookie, 'X-Eva-Teacher-Secret': bridge}, body)

    def forward(self, method, path, headers, body):
        client = UnixClient(self.server.unix_path, self.server.upstream_authority, self.deadline)
        try:
            client.request(method, path, body, {'Host': self.server.upstream_authority, **headers})
            response = client.getresponse()
            payload = response.read(REPLY_LIMIT + 1)
            remaining(self.deadline)
            if len(payload) > REPLY_LIMIT:
                raise ValueError('EVA_TLS_RESPONSE_REFUSED')
            if method == 'GET':
                if response.status == 302:
                    cookies = [value for name, value in response.getheaders() if name.lower() == 'set-cookie']
                    if (response.getheader('Location') != '/ru/' or len(cookies) != 1 or len(cookies[0]) > 512
                            or any(ch in cookies[0] for ch in '\r\n\0')):
                        raise ValueError('EVA_TLS_RESPONSE_REFUSED')
                    cookie = cookies[0]
                    if self.server.bridge_path != BRIDGE:
                        path = '; Path=' + BRIDGE + ';'
                        if cookie.count(path) != 1:
                            raise ValueError('EVA_TLS_RESPONSE_REFUSED')
                        cookie = cookie.replace(path, '; Path=' + self.server.bridge_path + ';', 1)
                    self.reply(302, extra=(('Location', '/ru/'), ('Set-Cookie', cookie)))
                    return
                if response.status not in (401, 404, 503):
                    raise ValueError('EVA_TLS_RESPONSE_REFUSED')
                self.reply(response.status)
                return
            if response.status not in (200, 400, 401, 403, 404, 415, 429, 500, 503):
                raise ValueError('EVA_TLS_RESPONSE_REFUSED')
            self.reply(response.status, payload if response.status == 200 else b'')
        except (OSError, ValueError, http.client.HTTPException):
            self.reply(503)
        finally:
            client.close()
