"""Read the fixed TEST route contract and report only safe configuration metadata."""

from hashlib import sha256
from ipaddress import IPv4Address
import json
import os
import re
import socket
import ssl
import subprocess

from eva_test_apache import PUBLIC_HOST, patched, publisher_lock, read_active, verify_logs
from test_installer_update_receiver import _host_matches

VERSION = 'jsm-eva-route-preflight-1620-v1'


def metadata():
    if os.geteuid() != 0 or not _host_matches():
        raise ValueError('EVA_PREFLIGHT_TARGET_REFUSED')
    with publisher_lock():
        raw, _ = read_active()
        baseline = sha256(raw).hexdigest()
        patched(raw, baseline)
        includes = apache('-t', '-D', 'DUMP_INCLUDES')
        verify_logs(includes)
        listing = apache('-S')
        pattern = rb'\s*(?:(?:\*|[0-9.]+):443 |port 443 namevhost )' + re.escape(PUBLIC_HOST.encode('ascii'))
        pattern += rb' \((/etc/apache2/sites-enabled/jsm-sandbox-443\.conf):[0-9]+\)'
        active = [row for row in listing.splitlines() if re.fullmatch(pattern, row)]
        if len(active) != 1:
            raise ValueError('EVA_PREFLIGHT_VHOST_REFUSED')
        context = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', 443), timeout=1) as channel:
            with context.wrap_socket(channel, server_hostname=PUBLIC_HOST) as tls:
                certificate = sha256(tls.getpeercert(binary_form=True)).hexdigest()
        current, _ = read_active()
        if sha256(current).hexdigest() != baseline:
            raise ValueError('EVA_PREFLIGHT_VHOST_REFUSED')
    candidates = sorted({
        IPv4Address(row[4][0]) for row in socket.getaddrinfo('api.anthropic.com', 443, socket.AF_INET, socket.SOCK_STREAM)
        if IPv4Address(row[4][0]).is_global and not IPv4Address(row[4][0]).is_multicast
    })
    if not candidates or len(candidates) > 12:
        raise ValueError('EVA_PREFLIGHT_PROVIDER_REFUSED')
    return {'vhost_sha256': baseline, 'certificate_sha256': certificate, 'publisher_lock': 'OBSERVED_AND_AVAILABLE',
            'provider_ipv4': str(candidates[0]), 'log_scope': 'ADMITTED', 'tls': 'LOCAL_SNI_VERIFIED'}


def apache(*args):
    command = ('/usr/sbin/apache2ctl', *args)
    response = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}, stdin=subprocess.DEVNULL)
    if len(response.stdout) > 32768:
        raise ValueError('EVA_PREFLIGHT_VHOST_REFUSED')
    return response.stdout


def main(nonce):
    try:
        details = metadata()
        result = {'status': 'OBSERVED', 'binding': details}
    except (OSError, ValueError, subprocess.SubprocessError):
        result = {'status': 'BLOCKED', 'binding': None}
    print(json.dumps({'version': VERSION, 'nonce': nonce, 'euid': os.geteuid(), **result},
                     sort_keys=True, separators=(',', ':')))
