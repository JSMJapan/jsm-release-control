"""Fixed TEST installer CMS capture capsule. Import and render are offline."""

STATUSES = ('CAPTURED', 'PREFLIGHT_REFUSED', 'PATH_REFUSED', 'SOURCE_CHANGED', 'ENCRYPTION_REFUSED')
MAX_CIPHERTEXT_BYTES = 9000

_VALIDATION = 'MAX_CIPHERTEXT_BYTES = ' + repr(MAX_CIPHERTEXT_BYTES) + '\n' + r'''
import base64
import binascii
import hashlib
import re

_MAX_PLAINTEXT_BYTES = 8192
_AUTH_ENVELOPED = bytes.fromhex('2a864886f70d0109100117')
_DATA = bytes.fromhex('2a864886f70d010701')
_RSA_KEY = bytes.fromhex('2a864886f70d010101')
_RSA_OAEP = bytes.fromhex('2a864886f70d010107')
_MGF1 = bytes.fromhex('2a864886f70d010108')
_SHA256 = bytes.fromhex('608648016503040201')
_AES256_GCM = bytes.fromhex('60864801650304012e')


class _DER:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def item(self, tag=None):
        i = self.offset
        if i + 2 > len(self.data):
            raise ValueError()
        actual, width = self.data[i:i + 2]
        i += 2
        if actual & 31 == 31 or (tag is not None and tag != actual):
            raise ValueError()
        if width >= 128:
            width -= 128
            if not 1 <= width <= 2 or i + width > len(self.data) or not self.data[i]:
                raise ValueError()
            size = int.from_bytes(self.data[i:i + width], 'big')
            i += width
            if size < 128:
                raise ValueError()
        else:
            size = width
        if i + size > len(self.data):
            raise ValueError()
        self.offset = i + size
        return actual, self.data[i:self.offset]

    def read(self, tag):
        return self.item(tag)[1]

    def inside(self, tag):
        return _DER(self.read(tag))

    def end(self):
        if self.offset != len(self.data):
            raise ValueError()


def _exact(data, expected):
    if data != expected:
        raise ValueError()


def _sha256_algorithm(parent):
    algorithm = parent.inside(0x30)
    _exact(algorithm.read(0x06), _SHA256)
    if algorithm.offset < len(algorithm.data):
        _exact(algorithm.read(0x05), b'')
    algorithm.end()


def _validate_recipient(data):
    name = _DER(data)
    issuer = name.inside(0x30)
    if not issuer.data or len(issuer.data) > 1024:
        raise ValueError()
    while issuer.offset < len(issuer.data):
        rdn = issuer.inside(0x31)
        if not rdn.data:
            raise ValueError()
        while rdn.offset < len(rdn.data):
            attribute = rdn.inside(0x30)
            oid = attribute.read(0x06)
            if not oid or oid[-1] & 128:
                raise ValueError()
            tag, value = attribute.item()
            if tag not in (0x0c, 0x13, 0x14, 0x16, 0x1c, 0x1e) or not value:
                raise ValueError()
            attribute.end()
    serial = name.read(0x02)
    if (not 1 <= len(serial) <= 21 or serial[0] & 128 or not any(serial)
            or (len(serial) > 1 and not serial[0] and not serial[1] & 128)):
        raise ValueError()
    name.end()


def _envelope(data):
    if type(data) is not bytes or not 1 <= len(data) <= MAX_CIPHERTEXT_BYTES:
        raise ValueError()
    top = _DER(data)
    content = top.inside(0x30)
    top.end()
    _exact(content.read(0x06), _AUTH_ENVELOPED)
    wrapped = content.inside(0xa0)
    content.end()
    container = wrapped.inside(0x30)
    wrapped.end()
    _exact(container.read(0x02), b'\x00')

    recipients = container.inside(0x31)
    recipient = recipients.inside(0x30)
    recipients.end()
    _exact(recipient.read(0x02), b'\x00')
    recipient_id = recipient.read(0x30)
    _validate_recipient(recipient_id)
    key_algorithm = recipient.inside(0x30)
    _exact(key_algorithm.read(0x06), _RSA_OAEP)
    oaep = key_algorithm.inside(0x30)
    key_algorithm.end()
    explicit_hash = oaep.inside(0xa0)
    _sha256_algorithm(explicit_hash)
    explicit_hash.end()
    mask = oaep.inside(0xa1)
    mgf1 = mask.inside(0x30)
    mask.end()
    _exact(mgf1.read(0x06), _MGF1)
    _sha256_algorithm(mgf1)
    mgf1.end()
    # OpenSSL omits the default empty OAEP label.
    oaep.end()
    encrypted_key = recipient.read(0x04)
    if not 256 <= len(encrypted_key) <= 512:
        raise ValueError()
    recipient.end()

    encrypted = container.inside(0x30)
    _exact(encrypted.read(0x06), _DATA)
    gcm = encrypted.inside(0x30)
    _exact(gcm.read(0x06), _AES256_GCM)
    parameters = gcm.inside(0x30)
    gcm.end()
    iv = parameters.read(0x04)
    _exact(parameters.read(0x02), b'\x10')
    parameters.end()
    length = len(encrypted.read(0x80))
    encrypted.end()
    tag = container.read(0x04)
    container.end()
    if len(iv) != 12 or not 1 <= length <= _MAX_PLAINTEXT_BYTES or len(tag) != 16:
        raise ValueError()
    return recipient_id, len(encrypted_key), iv, length


def _certificate_identity(pem):
    if type(pem) is not bytes or not 1 <= len(pem) <= 4096:
        raise ValueError()
    match = re.fullmatch(rb'-----BEGIN CERTIFICATE-----\n((?:[A-Za-z0-9+/=]{1,64}\n)+)-----END CERTIFICATE-----\n', pem)
    if match is None:
        raise ValueError()
    body = match[1].replace(b'\n', b'')
    data = base64.b64decode(body, validate=True)
    _exact(base64.b64encode(data), body)
    cert = _DER(data)
    sequence = cert.inside(0x30)
    cert.end()
    tbs = sequence.inside(0x30)
    sequence.read(0x30)
    sequence.read(0x03)
    sequence.end()
    if tbs.data.startswith(b'\xa0'):
        version = tbs.inside(0xa0)
        _exact(version.read(0x02), b'\x02')
        version.end()
    start = tbs.offset
    tbs.read(0x02)
    serial = tbs.data[start:tbs.offset]
    tbs.read(0x30)
    start = tbs.offset
    tbs.read(0x30)
    identity = tbs.data[start:tbs.offset] + serial
    _validate_recipient(identity)
    tbs.read(0x30)  # validity
    tbs.read(0x30)  # subject
    spki = tbs.inside(0x30)
    algorithm = spki.inside(0x30)
    _exact(algorithm.read(0x06), _RSA_KEY)
    _exact(algorithm.read(0x05), b'')
    algorithm.end()
    bits = spki.read(0x03)
    spki.end()
    if not bits or bits[0] != 0:
        raise ValueError()
    public_key = _DER(bits[1:])
    key = public_key.inside(0x30)
    public_key.end()
    modulus = key.read(0x02)
    exponent = key.read(0x02)
    key.end()
    if len(modulus) != 385 or modulus[0] != 0 or not modulus[1] & 128 or not modulus[-1] & 1:
        raise ValueError()
    if exponent != b'\x01\x00\x01':
        raise ValueError()
    return identity, 384


def validate_envelope(ciphertext, recipient_pem=None):
    # Validate the bounded CMS shape and, if supplied, its exact recipient ID.
    try:
        evidence = _envelope(ciphertext)
        return recipient_pem is None or evidence[:2] == _certificate_identity(recipient_pem)
    except (ValueError, binascii.Error):
        return False


def _certificate_pinned(pem, digest):
    if (type(pem) is not bytes or not 1 <= len(pem) <= 4096
            or type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None
            or hashlib.sha256(pem).hexdigest() != digest):
        return False
    try:
        _certificate_identity(pem)
        return True
    except (ValueError, binascii.Error):
        return False

'''

_ROOT = r'''
import fcntl
import json
import os
import resource
import selectors
import stat
import subprocess
import time

_OPENSSL = '/usr/bin/openssl'
_CRYPTO_ENV = dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',OPENSSL_CONF='/dev/null')
_DIR_COMPONENTS = ('usr','local','sbin')
_LEAF = 'jsm-sandbox-deploy'
_CANARY = b'jsm-test-installer-cms-public-canary-v1'


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    return remaining


def _bounded_crypto(argv, stdin, limit, deadline, *, recipient_fd=None):
    _remaining(deadline)
    binary = os.stat(_OPENSSL, follow_symlinks=False)
    if not stat.S_ISREG(binary.st_mode) or not _safe_mode(binary) or not binary.st_mode & stat.S_IXUSR:
        raise ValueError()
    stamp = _stamp(binary)
    with selectors.DefaultSelector() as selector:
        process = subprocess.Popen([_OPENSSL, *argv], env=_CRYPTO_ENV, close_fds=True,
            pass_fds=() if recipient_fd is None else (recipient_fd,), stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            output = bytearray()
            written = 0
            streams = [(process.stdout, selectors.EVENT_READ)]
            if stdin is not None:
                streams.append((process.stdin, selectors.EVENT_WRITE))
            for stream, operation in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, operation)
            while selector.get_map():
                for event, operation in selector.select(_remaining(deadline)):
                    stream = event.fileobj
                    _remaining(deadline)
                    if operation == selectors.EVENT_READ:
                        part = os.read(stream.fileno(), min(4096, limit + 1 - len(output)))
                        if part:
                            output.extend(part)
                            if len(output) > limit:
                                raise ValueError()
                            continue
                    else:
                        written += os.write(stream.fileno(), stdin[written:written + 4096])
                        if written < len(stdin):
                            continue
                    selector.unregister(stream)
                    stream.close()
            if process.wait(timeout=_remaining(deadline)) != 0:
                raise ValueError()
            if _stamp(os.stat(_OPENSSL, follow_symlinks=False)) != stamp:
                raise ValueError()
            _remaining(deadline)
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
            if process.stdin is not None:
                process.stdin.close()
            process.stdout.close()


def _cms(data, recipient_fd, deadline):
    return _bounded_crypto(
        ['cms','-encrypt','-binary','-outform','DER','-aes-256-gcm','-provider','default',
         '-recip','/proc/self/fd/' + str(recipient_fd),'-keyopt','rsa_padding_mode:oaep',
         '-keyopt','rsa_oaep_md:sha256','-keyopt','rsa_mgf1_md:sha256'],
        data, MAX_CIPHERTEXT_BYTES, deadline, recipient_fd=recipient_fd)


def _preflight(pem, digest, deadline):
    if os.geteuid() != 0 or not _certificate_pinned(pem, digest):
        raise ValueError()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    version = _bounded_crypto(['version'], None, 256, deadline)
    if re.fullmatch(rb'OpenSSL 3\.[0-9]+\.[0-9]+[a-z]?(?: [ -~]+)?\n', version) is None:
        raise ValueError()
    _remaining(deadline)
    cert_fd = os.memfd_create('jsm-test-installer-recipient',
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        if os.write(cert_fd, pem) != len(pem):
            raise OSError()
        fcntl.fcntl(cert_fd, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(cert_fd, 0, os.SEEK_SET)
        witness = _envelope(_cms(_CANARY, cert_fd, deadline))
        if witness[:2] != _certificate_identity(pem) or witness[3] != len(_CANARY):
            raise ValueError()
        return cert_fd, witness
    except BaseException:
        os.close(cert_fd)
        raise


def _stamp(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _safe_mode(info):
    return info.st_uid == 0 and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0


def _parents(deadline):
    current = []
    try:
        for name in ('/', *_DIR_COMPONENTS):
            _remaining(deadline)
            parent = current[-1] if current else None
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            current.append(fd)
            info = os.fstat(fd)
            if not _safe_mode(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError()
        return current
    except BaseException:
        for fd in reversed(current):
            os.close(fd)
        raise


def _check_binding(descriptors, parents, leaf, source_fd, deadline):
    _remaining(deadline)
    if parents != tuple(_stamp(os.fstat(fd)) for fd in descriptors):
        raise ValueError()
    if leaf != _stamp(os.fstat(source_fd)):
        raise ValueError()
    fresh = _parents(deadline)
    try:
        if parents != tuple(_stamp(os.fstat(fd)) for fd in fresh):
            raise ValueError()
        if leaf != _stamp(os.stat(_LEAF, dir_fd=fresh[-1], follow_symlinks=False)):
            raise ValueError()
    finally:
        for fd in reversed(fresh):
            os.close(fd)
    _remaining(deadline)


def _capture(pem, digest, deadline):
    cert_fd = None
    source_fd = None
    parents = []
    phase = 'PREFLIGHT_REFUSED'
    try:
        cert_fd, witness = _preflight(pem, digest, deadline)
        phase = 'PATH_REFUSED'
        parents = _parents(deadline)
        stamps = tuple(_stamp(os.fstat(fd)) for fd in parents)
        _remaining(deadline)
        before = os.stat(_LEAF, dir_fd=parents[-1], follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or not _safe_mode(before)
                or before.st_nlink != 1 or not 1 <= before.st_size <= _MAX_PLAINTEXT_BYTES):
            raise ValueError()
        leaf = _stamp(before)
        source_fd = os.open(_LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=parents[-1])
        phase = 'SOURCE_CHANGED'
        _check_binding(parents, stamps, leaf, source_fd, deadline)
        data = bytearray()
        while len(data) <= before.st_size:
            _remaining(deadline)
            part = os.read(source_fd, min(4096, before.st_size + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        if len(data) != before.st_size:
            raise ValueError()
        _check_binding(parents, stamps, leaf, source_fd, deadline)
        phase = 'ENCRYPTION_REFUSED'
        ciphertext = _cms(data, cert_fd, deadline)
        receipt = _envelope(ciphertext)
        if receipt[:2] != witness[:2] or receipt[2] == witness[2] or receipt[3] != before.st_size:
            raise ValueError()
        phase = 'SOURCE_CHANGED'
        _check_binding(parents, stamps, leaf, source_fd, deadline)
        return 'CAPTURED', base64.b64encode(ciphertext).decode('ascii')
    except Exception:
        return phase, None
    finally:
        for fd in ([source_fd] if source_fd is not None else []) + list(reversed(parents)) + ([cert_fd] if cert_fd is not None else []):
            try:
                os.close(fd)
            except OSError:
                pass


def _main(nonce, pem, digest):
    euid = os.geteuid()
    status, ciphertext = _capture(pem, digest, time.monotonic() + 3)
    print(json.dumps(dict(version='jsm-test-installer-cms-v1',nonce=nonce,euid=euid,status=status,
        ciphertext=ciphertext), ensure_ascii=True, separators=(',', ':'), sort_keys=True))
'''


_validation = {}
exec(_VALIDATION, _validation)
validate_envelope = _validation['validate_envelope']


def render(nonce: str, recipient_pem: bytes, recipient_sha256: str) -> str:
    """Build standalone ASCII Python after checking the pinned public certificate."""
    import re
    if (type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None
            or not _validation['_certificate_pinned'](recipient_pem, recipient_sha256)):
        raise ValueError('PREFLIGHT_REFUSED')
    return _VALIDATION + _ROOT + '\n_main(' + repr(nonce) + ',' + repr(recipient_pem) + ',' + repr(recipient_sha256) + ')\n'
