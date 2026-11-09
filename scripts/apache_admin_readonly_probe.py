#!/usr/bin/env python3
"""Manual GitHub-only admin transport probe. No config content, writes or install.

Uses an existing owner admin identity. BatchMode/publickey-only rejects key
passphrase prompts; no agent, password or passphrase fallback.
The previous Hostinger inventory proof is run42571345299/source30f5a911.
Private source/CI/archive/install admission is deliberately not established here.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hostinger_preflight import Api, GH_ENV, GH_REPO, GITHUB, REPO, policy_ready
from hostinger_preflight import Refused as PolicyRefused

PIN_SHA256 = '52eae07dbf3b29f109dfc41b12fa12f50765bee7bb69df4da8ba783ca040ac65'
VERSION = 'jsm-apache-admin-ro-v1'
MAX_OUTPUT = 4096
SSH_SECONDS = 15


class Refused(Exception):
    """Only fixed safe reason codes cross the process boundary."""


def context_ready(env):
    expected = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
                    GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_WORKFLOW_REF=REPO + '/.github/workflows/apache-admin-readonly-probe.yml@refs/heads/main')
    if (any(env.get(name) != value for name, value in expected.items())
            or not re.fullmatch('[0-9a-f]{40}', env.get('GITHUB_SHA', ''))
            or env.get('GITHUB_WORKFLOW_SHA') != env.get('GITHUB_SHA')
            or not re.fullmatch('[0-9]{1,15}', env.get('GITHUB_RUN_ID', ''))):
        raise Refused('OWNER_MANUAL_MAIN_ADMIN_WORKFLOW_REQUIRED')


def remote_program(nonce):
    if not re.fullmatch('[0-9a-f]{32}', nonce):
        raise Refused('NONCE_REQUIRED')
    # stdin program is a code constant plus one validated random nonce. lstat
    # does not follow links or read file bytes; neither Apache nor a service runs.
    return ("import json,os,stat\n"
            "def metadata(path):\n"
            "    try:\n"
            "        info=os.lstat(path)\n"
            "    except OSError:\n"
            "        return dict(present=False,regular=False,root_owned=False,mode=None)\n"
            "    return dict(present=True,regular=stat.S_ISREG(info.st_mode),root_owned=info.st_uid==0,mode=stat.S_IMODE(info.st_mode))\n"
            "print(json.dumps(dict(version='jsm-apache-admin-ro-v1',nonce='" + nonce + "',euid=os.geteuid(),"
            "apache_binary=metadata('/usr/sbin/apache2'),apache_config=metadata('/etc/apache2/apache2.conf'),writes_performed=False),sort_keys=True))\n").encode('ascii')


def project_remote(raw, nonce):
    try:
        if type(raw) is not bytes or len(raw) > MAX_OUTPUT:
            raise ValueError()
        value = json.loads(raw.decode('ascii'))
        if (type(value) is not dict or set(value) != {'version', 'nonce', 'euid', 'apache_binary', 'apache_config', 'writes_performed'}
                or value['version'] != VERSION or value['nonce'] != nonce
                or type(value['euid']) is not int or value['euid'] != 0 or value['writes_performed'] is not False):
            raise ValueError()
        for name in ('apache_binary', 'apache_config'):
            item = value[name]
            if (type(item) is not dict or set(item) != {'present', 'regular', 'root_owned', 'mode'}
                    or any(type(item[field]) is not bool for field in ('present', 'regular', 'root_owned'))
                    or (item['present'] and (type(item['mode']) is not int or not 0 <= item['mode'] <= 0o7777))
                    or (not item['present'] and (item['mode'] is not None or item['regular'] or item['root_owned']))):
                raise ValueError()
        return dict(root_identity=True, apache_binary=dict(value['apache_binary']), apache_config=dict(value['apache_config']))
    except Exception:
        raise Refused('REMOTE_SCHEMA_NONCE_OR_ROOT_REJECTED') from None


def bounded_ssh(command, program):
    process = None
    deadline = time.monotonic() + SSH_SECONDS
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, close_fds=True)
        process.stdin.write(program)
        process.stdin.close()
        output = bytearray()
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refused('SSH_DEADLINE')
                events = ready.select(remaining)
                if not events:
                    raise Refused('SSH_DEADLINE')
                chunk = os.read(process.stdout.fileno(), min(1024, MAX_OUTPUT + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise Refused('REMOTE_OUTPUT_BOUND')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refused('SSH_DEADLINE')
        if process.wait(timeout=remaining) != 0:
            raise Refused('SSH_KEY_LOAD_OR_AUTH_OR_COMMAND_FAILED')
        return bytes(output)
    except Refused:
        raise
    except subprocess.TimeoutExpired:
        raise Refused('SSH_DEADLINE') from None
    except Exception:
        raise Refused('SSH_KEY_LOAD_OR_AUTH_OR_COMMAND_FAILED') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


def private_file(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write(value)


def collect(api, env):
    context_ready(env)
    repo = api.get_json(GITHUB, GH_REPO)
    environment = api.get_json(GITHUB, GH_ENV)
    branches = api.get_json(GITHUB, GH_ENV + '/deployment-branch-policies')
    try:
        policy_ready(repo, environment, branches)
    except PolicyRefused:
        raise Refused('PROTECTED_OWNER_MAIN_ENVIRONMENT_REQUIRED') from None
    key = env.get('APACHE_BOOTSTRAP_ADMIN_SSH_KEY')
    known = env.get('APACHE_BOOTSTRAP_KNOWN_HOSTS')
    if not isinstance(key, str) or not 0 < len(key) <= 16384 or '\x00' in key:
        raise Refused('ADMIN_SSH_KEY_NOT_CONFIGURED')
    if (not isinstance(known, str) or len(known) > 16384
            or hashlib.sha256(known.encode('utf-8')).hexdigest() != PIN_SHA256):
        raise Refused('EXACT_TRUSTED_HOST_PIN_REQUIRED')
    nonce = secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='jsm-admin-ro-') as folder:
        os.chmod(folder, 0o700)
        identity, hosts = Path(folder) / 'identity', Path(folder) / 'known_hosts'
        # Normalize only transport line endings in this temporary copy; preserve
        # all body spaces and the owner-provided value. Host-pin bytes stay exact.
        private_file(identity, key.replace('\r\n', '\n').rstrip('\n') + '\n')
        private_file(hosts, known)
        command = ['ssh', '-F', '/dev/null', '-T', '-i', str(identity), '-p', '17177',
                   '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
                   '-o', 'KbdInteractiveAuthentication=no', '-o', 'ClearAllForwardings=yes',
                   '-o', 'UserKnownHostsFile=' + str(hosts), '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'ConnectTimeout=7', '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=3',
                   '-o', 'ServerAliveCountMax=2', '-o', 'LogLevel=ERROR',
                   'root@187.77.118.50', '/usr/bin/python3', '-I', '-B', '-']
        metadata = project_remote(bounded_ssh(command, remote_program(nonce)), nonce)
    return dict(metadata, status='ADMIN_READ_ONLY_PROBE_COMPLETE', resource='hostinger:srv1687281',
                domain='jsmjapan.com', ip='187.77.118.50', ssh_port=17177, known_hosts_sha256=PIN_SHA256,
                source_sha=env['GITHUB_SHA'], workflow_run_url='https://github.com/' + REPO + '/actions/runs/' + env['GITHUB_RUN_ID'],
                writes_performed=False, apache_channel='NOT_ACTIVATED', source_package_admission='NOT_ESTABLISHED')


def main():
    def expired(*_):
        raise Refused('OVERALL_DEADLINE')
    try:
        if len(sys.argv) != 1:
            raise Refused('NO_ARGUMENTS_OR_INPUTS_ACCEPTED')
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 60)
        result = collect(Api(), os.environ)
        result['verified_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, Refused) else 'ADMIN_PROBE_REJECTED'
        print(json.dumps(dict(status='BLOCKED', reason=reason, writes_performed=False,
                              apache_channel='NOT_ACTIVATED', source_package_admission='NOT_ESTABLISHED'), sort_keys=True))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    raise SystemExit(main())
