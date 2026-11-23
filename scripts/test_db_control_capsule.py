"""Fixed root-side code rendered into the existing TEST transport."""
import base64
import bz2
from contextlib import ExitStack
import fcntl
from hashlib import sha256
from io import BytesIO
import json
import os
import secrets
import selectors
import signal
import subprocess
import sys
import time
from zipfile import ZIP_STORED, ZipFile


class PackageRefused(ValueError):
    """The bounded archive does not match the reviewed checkout."""


def decode_package(encoded, expected_size, expected_hash, pins):
    if not 0 < expected_size <= 512 * 1024 or not 0 < len(encoded) <= 128 * 1024:
        raise PackageRefused()
    compressed = base64.b64decode(encoded, validate=True)
    if base64.b64encode(compressed) != encoded:
        raise PackageRefused()
    decoder = bz2.BZ2Decompressor()
    raw = decoder.decompress(compressed, max_length=expected_size + 1)
    if len(raw) != expected_size or not decoder.eof or decoder.unused_data or sha256(raw).hexdigest() != expected_hash:
        raise PackageRefused()
    php = {}
    with ZipFile(BytesIO(raw)) as archive:
        members = archive.infolist()
        if len(members) != len(pins):
            raise PackageRefused()
        for info, (name, size, expected) in zip(members, pins):
            if (info.filename != name or info.file_size != size or not 0 < size <= 128 * 1024
                    or info.compress_type != ZIP_STORED or info.compress_size != size
                    or info.flag_bits != 0 or info.extra or info.comment):
                raise PackageRefused()
            data = archive.read(info)
            if sha256(data).hexdigest() != expected:
                raise PackageRefused()
            if name.startswith('php/'):
                php[name[4:]] = data
    return raw, php


def archive_descriptor(stack, raw):
    fd = os.memfd_create('jsm-db-2760', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    stack.callback(os.close, fd)
    with os.fdopen(fd, 'wb', closefd=False) as file:
        file.write(raw)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    reader = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
    stack.callback(os.close, reader)
    writer_info, reader_info = os.fstat(fd), os.fstat(reader)
    if ((writer_info.st_dev, writer_info.st_ino, len(raw)) !=
            (reader_info.st_dev, reader_info.st_ino, reader_info.st_size)
            or fcntl.fcntl(reader, fcntl.F_GET_SEALS) != seals):
        raise PackageRefused()
    return reader


def pairs(rows):
    value = dict(rows)
    if len(rows) != len(value):
        raise ValueError()
    return value


def invalid_constant(_):
    raise ValueError()


def run_producer(fd, data, deadline_ns):
    # The parent's process and TERM handlers stay alive to settle staging.
    if not 0 < len(data) <= 4096 or time.monotonic_ns() >= deadline_ns:
        raise TimeoutError()
    command = ['/usr/bin/python3', '-I', '-B', '-S', '/proc/self/fd/' + str(fd)]
    with subprocess.Popen(command, pass_fds=(fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}) as process:
        try:
            process.stdin.write(data)
            process.stdin.close()
            raw = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    left = (deadline_ns - time.monotonic_ns()) / 1e9
                    if left <= 0 or not selector.select(left):
                        raise TimeoutError()
                    chunk = os.read(process.stdout.fileno(), 4097 - len(raw))
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > 4096:
                        raise ValueError()
            left = (deadline_ns - time.monotonic_ns()) / 1e9
            if left <= 0 or process.wait(timeout=left) != 0:
                raise ValueError()
        finally:
            if process.poll() is None:
                process.kill()
    return json.loads(raw.decode('ascii'), object_pairs_hook=pairs, parse_constant=invalid_constant)


def terminate(*_):
    raise TimeoutError()


def root_receipt(challenge, context, encoded, size, expected_hash, pins):
    receipt = dict(version=VERSION, nonce=challenge, euid=os.geteuid(),
                   context_sha256=sha256(canonical(context)).hexdigest(),
                   transport_reason='CAPSULE_PACKAGE_REFUSED', cleanup='NOT_NEEDED', report=None)
    if sys.platform != 'linux' or os.geteuid() != 0:
        return receipt
    # GNU timeout starts before interpreter setup. Keep a reserve inside its 4s cap.
    started = time.monotonic_ns()
    producer_deadline = started + 2_900_000_000
    child_deadline = started + 3_350_000_000
    signal.signal(signal.SIGTERM, terminate)
    try:
        archive, php = decode_package(encoded, size, expected_hash, pins)
        with ExitStack() as stack:
            fd = archive_descriptor(stack, archive)
            receipt['transport_reason'] = 'STAGING_REFUSED'
            with staged_php('/run', secrets.token_hex(16), php) as staging:
                payload = canonical(dict(context=context, staging=staging, deadline_ns=producer_deadline))
                receipt['transport_reason'] = 'CAPSULE_PRODUCER_REFUSED'
                try:
                    if time.monotonic_ns() >= producer_deadline:
                        receipt['transport_reason'] = 'CAPSULE_DEADLINE'
                    else:
                        report = run_producer(fd, payload, child_deadline)
                        if not report_valid(report):
                            raise ValueError()
                        receipt['report'] = report
                        if report['fastcgi_state'] == 'UNCONFIRMED':
                            raise DeferCleanup()
                        receipt['transport_reason'] = None
                except Exception:
                    # The producer may have sent FastCGI before its final receipt failed.
                    raise DeferCleanup() from None
            receipt['cleanup'] = 'VERIFIED'
    except CleanupUnconfirmed:
        receipt['transport_reason'] = 'STAGING_CLEANUP_UNCONFIRMED'
        receipt['cleanup'] = 'UNCONFIRMED'
    except Exception:
        pass
    return receipt
