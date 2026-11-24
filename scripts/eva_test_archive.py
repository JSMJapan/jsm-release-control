"""Verify exactly the private Eva Actions archive admitted by the control revision."""

from dataclasses import dataclass
from pathlib import Path
import os
import re
import stat
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

from apache_parity_bridge import strict_json
from article_test_artifact import Build, Inspected, bounded_hash, file_stamp

BRIDGE = 'b81d8ecc4a22bfcb62aa2718d666347675195934'
BRIDGE_TREE = '2bf5c35bc75ff5267ee024f6a970b6f9ca34d8df'
RUNNER = '024226ec3bcb3bcba0b229c7194e006d127b24af'
RUNNER_TREE = 'b70854d7e540712a09d532e42a5dab91fa4f729d'
LIMITS = {
    'acceptance.json': 8192, 'app-image-id': 72, 'build-commit': 41, 'mysql-image-id': 72,
    'images.tar.gz': 2 * 1024**3, 'runner.tar.gz': 128 * 1024, 'schema.sql': 8192,
    'seed.sql': 8192, 'source.json': 32768, 'SHA256SUMS': 1024,
}
ARCHIVE_LIMIT = sum(LIMITS.values()) + 65536
RECEIPT = {
    'status': 'CI_NATIVE_PASS', 'database': 'NEW_SYNTHETIC_FAQ', 'pdo_binding': 'VERIFIED',
    'network': 'LOOPBACK_ONLY', 'writer_grants': 'TWO_FAQ_TABLES', 'owner_cycles': 1,
    'lesson_in_next_context': True, 'fixture_provider_calls': 2, 'external_calls': 0, 'cleanup': 'VERIFIED',
}
SHA256 = re.compile('[0-9a-f]{64}')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')


class EvaRefused(ValueError):
    pass


def require(value, code='EVA_PACKAGE_REFUSED'):
    if not value:
        raise EvaRefused(code)


@dataclass(frozen=True)
class EvaBuild(Build):
    @property
    def artifact_name(self):
        return 'eva-test-1620-' + self.sha

    @property
    def tags(self):
        return ('jsm-eva-test:' + self.sha, 'jsm-eva-mysql:' + self.sha)


def load_pins(path=None):
    source = Path(__file__).with_name('eva_test_pins.json') if path is None else path
    raw = source.read_bytes()
    require(len(raw) <= 2048, 'EVA_ARTIFACT_NOT_PINNED')
    value = strict_json(raw.decode('ascii'))
    require(type(value) is dict and set(value) == {'status', 'sha', 'run_id', 'artifact_id', 'archive_sha256'}
            and value['status'] == 'PINNED', 'EVA_ARTIFACT_NOT_PINNED')
    return EvaBuild(*(value[name] for name in ('sha', 'run_id', 'artifact_id', 'archive_sha256')))


def inspect_archive(path, build):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and file_stamp(info) == file_stamp(path.stat(follow_symlinks=False)))
        digest, size = bounded_hash(file, ARCHIVE_LIMIT)
        require(digest == build.archive_sha256 and size == info.st_size)
        file.seek(0)
        with ZipFile(file) as archive:
            items = archive.infolist()
            require(len(items) == len(LIMITS) and {item.filename for item in items} == set(LIMITS))
            for item in items:
                require(0 < item.file_size <= LIMITS[item.filename] and not item.flag_bits & 1
                        and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                        and item.compress_type in (ZIP_STORED, ZIP_DEFLATED) and not item.extra and not item.comment)
            checksums = {}
            for line in archive.read('SHA256SUMS').decode('ascii').splitlines():
                checksum, sep, name = line.partition('  ')
                require(sep and SHA256.fullmatch(checksum) and name in LIMITS and name != 'SHA256SUMS' and name not in checksums)
                checksums[name] = checksum
            require(checksums.keys() == LIMITS.keys() - {'SHA256SUMS'})
            for name, checksum in checksums.items():
                with archive.open(name) as member:
                    require(bounded_hash(member, LIMITS[name]) == (checksum, archive.getinfo(name).file_size))
            require(archive.read('build-commit') == (build.sha + '\n').encode('ascii'))
            source = strict_json(archive.read('source.json').decode('ascii'))
            fields = ('bridge_commit', 'bridge_tree', 'runner_commit', 'runner_tree')
            require(tuple(source[name] for name in fields) == (BRIDGE, BRIDGE_TREE, RUNNER, RUNNER_TREE))
            fixtures = {name + '_sha256': checksums[name + '.sql'] for name in ('schema', 'seed')}
            require(all(source.get(name) == digest for name, digest in fixtures.items()))
            receipt = strict_json(archive.read('acceptance.json').decode('ascii'))
            require(receipt.keys() == RECEIPT.keys() | fixtures.keys()
                    and all(type(receipt[key]) is type(value) and receipt[key] == value for key, value in (RECEIPT | fixtures).items()))
            images = tuple(archive.read(name).decode('ascii') for name in ('app-image-id', 'mysql-image-id'))
            require(len(set(images)) == 2 and all(IMAGE.fullmatch(value.removesuffix('\n')) and value.endswith('\n') for value in images))
            metadata = {name: archive.read(name) for name in ('schema.sql', 'seed.sql')}
            lengths = {item.filename: item.file_size for item in items}
        require(file_stamp(info) == file_stamp(os.fstat(file.fileno())) == file_stamp(path.stat(follow_symlinks=False)))
    inspected = Inspected(build, lengths, BRIDGE, BRIDGE_TREE, *[value[:-1] for value in images],
                          size, lengths['images.tar.gz'], fixtures['schema_sha256'], fixtures['seed_sha256'])
    return inspected, metadata
