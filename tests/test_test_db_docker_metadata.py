"""Offline Docker-summary fixtures only; never the real daemon or TEST."""
import importlib.util
import json
from pathlib import Path
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test_db_docker_metadata.py'
ID = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64


def summary(identity=ID):
    return dict(Id=identity, Image='mysql:5.7', ImageID=IMAGE,
        Ports=[dict(PrivatePort=3306, PublicPort=3306, IP='127.0.0.1', Type='tcp')],
        Command='PRIVATE_COMMAND', Labels={'private': 'PRIVATE_LABEL'},
        Names=['PRIVATE_NAME'], Mounts=[{'Source': 'PRIVATE_MOUNT'}])


class Wire:
    def __init__(self, chunks):
        self.chunks = list(chunks)
    def settimeout(self, value):
        assert 0 < value <= .75
    def recv(self, size):
        if not self.chunks:
            return b''
        value = self.chunks.pop(0)
        assert len(value) <= size
        return value


class DockerMetadataTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'approved Docker discovery parser is missing')
        spec = importlib.util.spec_from_file_location('docker_metadata_candidate', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.ns = {}
        exec(compile(self.module.LIBRARY, '<fixed-docker-discovery>', 'exec'), self.ns)

    def test_summary_keeps_only_typed_identity_and_endpoint_predicates(self):
        result = self.ns['_docker_parse_body'](json.dumps([summary()]).encode())
        self.assertEqual(result, [dict(id=ID, image_id=IMAGE, image_family='mysql',
            port3306_exposed=True, port3306_published=True,
            port3306_loopback=True, port3306_nonloopback=False)])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_ninth_container_is_not_reported_as_an_empty_success(self):
        eight = [summary(format(i, '064x')) for i in range(8)]
        self.assertEqual(len(self.ns['_docker_parse_body'](json.dumps(eight).encode())), 8)
        with self.assertRaises(ValueError) as caught:
            self.ns['_docker_parse_body'](json.dumps(eight + [summary('f' * 64)]).encode())
        self.assertEqual(caught.exception.code, 'LIMIT_EXCEEDED')

    def test_unknown_image_and_malformed_ports_remain_unknown_without_raw_values(self):
        item = summary(); item.update(Image='PRIVATE/image:tag', ImageID='PRIVATE_ID',
            Ports=[dict(PrivatePort=True, Type='tcp')])
        result = self.ns['_docker_parse_body'](json.dumps([item]).encode())[0]
        self.assertEqual(result['image_family'], 'other')
        self.assertIsNone(result['image_id'])
        self.assertIsNone(result['port3306_exposed'])
        self.assertIsNone(result['port3306_published'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_duplicate_identity_keys_trailing_data_and_wrong_root_are_refused(self):
        duplicate_key = ('[{"Id":"' + ID + '","Id":"' + 'c' * 64 + '"}]').encode()
        for body in (duplicate_key, b'{}', b'[] trailing', b'[true]',
                json.dumps([summary(), summary()]).encode(), b'[{"Id":true}]'):
            with self.subTest(body=body[:30]):
                with self.assertRaises(ValueError): self.ns['_docker_parse_body'](body)

    def test_ipv6_and_nonloopback_publications_are_closed_booleans(self):
        item = summary(); item['Image'] = 'mariadb:10.11'
        item['Ports'] = [dict(PrivatePort=3306, PublicPort=3307, IP='::1', Type='tcp'),
            dict(PrivatePort=3306, PublicPort=3306, IP='0.0.0.0', Type='tcp')]
        result = self.ns['_docker_parse_body'](json.dumps([item]).encode())[0]
        self.assertEqual(result['image_family'], 'mariadb')
        self.assertTrue(result['port3306_loopback']); self.assertTrue(result['port3306_nonloopback'])

    def test_fixed_http_parser_accepts_bounded_200_json_and_no_other_framing(self):
        good = b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]'
        self.assertEqual(self.ns['_docker_http_response'](Wire([good]), time.monotonic()+.7), b'[]')
        for wire in (good.replace(b'200 OK', b'302 Found'),
                good.replace(b'Content-Length: 2', b'Content-Length: 2\r\nContent-Length: 2'),
                good.replace(b'Content-Length: 2', b'Transfer-Encoding: chunked'),
                good.replace(b'application/json', b'text/html'),
                good.replace(b'Content-Length: 2', b' Content-Length: 2'),
                good.replace(b'Content-Length: 2', b'Content-Length: 65537'), good[:-1], good+b'x'):
            with self.subTest(wire=wire[:80]):
                with self.assertRaises(ValueError):
                    self.ns['_docker_http_response'](Wire([wire]), time.monotonic()+.7)


if __name__ == '__main__':
    unittest.main()
