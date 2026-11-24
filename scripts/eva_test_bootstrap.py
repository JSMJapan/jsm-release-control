#!/usr/bin/env python3
"""Owner-approved provisioning of the one forced-command Eva TEST receiver."""

import base64
from hashlib import sha256
import os
from pathlib import Path
import re
import sys
import time
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apache_parity_bridge import _GitHubGet, _read_regular, strict_json
from eva_test_actions import authorize, control_paths
from eva_test_archive import load_pins, require
from test_installer_capture_encrypted import _receive
from test_installer_receiver_bootstrap_host import HOST_SOURCE

ADMIN_ENV = 'test-api-readonly-access'
VERSION = 'jsm-eva-bootstrap-1620-v1'
SCOPE = 'INSTALL_EVA_ONLY_RECEIVER'
ROOT = 'jsm-eva-test-1620'
ACCOUNT = 'jsm-eva-stage'
MODULES = (
    'apache_parity_bridge.py', 'hostinger_preflight.py', 'test_api_readonly_access.py',
    'article_test_artifact.py', 'article_test_actions.py', 'article_test_docker.py', 'article_test_host.py',
    'article_test_images.py', 'article_test_receiver.py', 'article_test_state.py', 'article_test_smoke.py',
    'test_installer_update_receiver.py', 'test_installer_update_package.py',
    'eva_test_apache.py', 'eva_test_archive.py', 'eva_test_host.py', 'eva_test_ingress.py', 'eva_test_receiver.py',
    'eva_test_live.py', 'eva_test_live_policy.json',
    'eva_test_forced_command.sh', 'eva_test_pins.json',
)
UNITS = ('jsm-eva-test-1620-expiry.service', 'jsm-eva-test-1620-expiry.timer')
STATUSES = {'BOOTSTRAPPED', 'TARGET_REFUSED', 'INPUT_REFUSED', 'PREEXISTING_REFUSED', 'BOOTSTRAP_FAILED', 'STATE_UNCERTAIN'}


def verified_key(text, fingerprint):
    require(type(text) is str and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}', text), 'EVA_BOOTSTRAP_KEY_REFUSED')
    raw = (text + '\n').encode('ascii')
    require(sha256(raw).hexdigest() == fingerprint, 'EVA_BOOTSTRAP_KEY_REFUSED')
    key = base64.b64decode(text.split()[1], validate=True)
    require(len(key) == 51 and key[:19] == b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' and any(key[19:]),
            'EVA_BOOTSTRAP_KEY_REFUSED')
    return raw


def fixed_template():
    # Keep original #2760 bootstrap semantics for its own user/files. This closure is only Eva.
    source = HOST_SOURCE
    replacements = {
        "_BOOT_PARENTS = (_BOOT_LOCAL, ('var', 'lib'), ('etc', 'sudoers.d'))":
            "_BOOT_PARENTS = (_BOOT_LOCAL, ('var', 'lib'), ('etc', 'sudoers.d'), ('etc', 'systemd', 'system'))",
        'local, varlib, sudoers = (row[1] for row in anchors)':
            'local, varlib, sudoers, units = (row[1] for row in anchors)',
        "or not _boot_absent(varlib, _BOOT_HOME_LEAF) or not _boot_absent(sudoers, _BOOT_DEST)):":
            "or not _boot_absent(varlib, _BOOT_HOME_LEAF) or not _boot_absent(sudoers, _BOOT_DEST)"
            "\n                    or any(not _boot_absent(units, name) for name in _EVA_UNITS)):",
        "                _boot_file(stack, created, package, name, files[source], mode, deadline)":
            "                target = units if name in _EVA_UNITS else package"
            "\n                _boot_file(stack, created, target, name, files[source], mode, deadline)",
    }
    for old, new in replacements.items():
        require(source.count(old) == 1, 'EVA_BOOTSTRAP_TEMPLATE_CHANGED')
        source = source.replace(old, new)
    require(source.endswith('\n_boot_main()\n'), 'EVA_BOOTSTRAP_TEMPLATE_CHANGED')
    return source.removesuffix('\n_boot_main()\n')


def capsule(nonce, public, control_sha, root=None):
    require(re.fullmatch('[0-9a-f]{32}', nonce) and re.fullmatch('[0-9a-f]{40}', control_sha),
            'EVA_BOOTSTRAP_CONTEXT_REFUSED')
    root = Path(__file__).resolve().parents[1] if root is None else Path(root)
    load_pins(root / 'scripts/eva_test_pins.json')
    files = {name: _read_regular(root / 'scripts' / name, 65536) for name in MODULES}
    files.update({name: _read_regular(root / 'ops/eva-test-1620' / name, 8192) for name in UNITS})
    files['control.sha'] = (control_sha + '\n').encode('ascii')
    members = {name: ('forced-command' if name == 'eva_test_forced_command.sh' else name,
                  0o755 if name == 'eva_test_forced_command.sh' else 0o444, len(raw), sha256(raw).hexdigest())
               for name, raw in files.items()}
    destination = '/usr/local/libexec/' + ROOT
    force, login = destination + '/forced-command', destination + '/login-shell'
    sudo = (ACCOUNT + ' ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I -B -S '
            + destination + '/eva_test_receiver.py serve\n').encode('ascii')
    shell = ('#!/bin/sh\n[ "$#" -eq 2 ] && [ "$1" = "-c" ] && [ "$2" = "' + force
             + '" ] || exit 64\nexec ' + force + '\n').encode('ascii')
    settings = {
        '_BOOT_NONCE': nonce, '_BOOT_PUBLIC_KEY': public, '_BOOT_FILES': files, '_BOOT_MEMBERS': members,
        '_BOOT_VERSION': VERSION, '_BOOT_ACCOUNT': ACCOUNT, '_BOOT_ROOT': destination,
        '_BOOT_HOME_LEAF': ROOT + '-home', '_BOOT_HOME': '/var/lib/' + ROOT + '-home',
        '_BOOT_DEST': ROOT, '_BOOT_FORCE': force, '_BOOT_LOGIN': login,
        '_BOOT_SUDO_LINE': sudo, '_BOOT_SHELL': shell, '_BOOT_PUBLIC_SHA256': sha256(public).hexdigest(),
        '_EVA_UNITS': UNITS,
    }
    source = fixed_template() + '\n' + '\n'.join(f'{name}={value!r}' for name, value in settings.items()) + '\n_boot_main()\n'
    compile(source, '<Eva TEST bootstrap>', 'exec')
    payload = base64.b64encode(zlib.compress(source.encode('ascii'), level=9))
    encoded = f'import base64,zlib;exec(compile(zlib.decompress(base64.b64decode({payload!r})), "<Eva TEST bootstrap>", "exec"))'
    require(len(encoded) < 110000, 'EVA_BOOTSTRAP_PACKAGE_REFUSED')
    return encoded


def project(raw, nonce):
    outer = strict_json(raw.decode('ascii'))
    root = outer.get('root_diagnostic')
    require(outer.keys() == {'version', 'nonce', 'principal', 'euid', 'root_diagnostic'}
            and outer['version'] == 'jsm-test-installed-route-outer-v2' and outer['nonce'] == nonce
            and outer['principal'] == 'marinagurina' and type(outer['euid']) is int and outer['euid'] > 0
            and type(root) is dict and root.keys() == {'version', 'nonce', 'euid', 'status'}
            and root['version'] == VERSION and root['nonce'] == nonce and type(root['euid']) is int and root['euid'] == 0
            and root['status'] in STATUSES, 'EVA_BOOTSTRAP_RECEIPT_REFUSED')
    return root['status']


def execute(env):
    sha = env.get('GITHUB_SHA', '')
    run = env.get('GITHUB_RUN_ID', '')
    require(re.fullmatch('[0-9a-f]{40}', sha) and re.fullmatch('[1-9][0-9]{0,14}', run)
            and env.get('APPROVED_SCOPE') == SCOPE, 'EVA_BOOTSTRAP_CONTEXT_REFUSED')
    paths = control_paths(run, environment_name=ADMIN_ENV)
    authorize(_GitHubGet(paths, token=env.get('GH_TOKEN')), env, run, sha, environment_name=ADMIN_ENV, job='bootstrap')
    public = verified_key(env.get('EVA_STAGE_PUBLIC_KEY'), env.get('APPROVED_PUBLIC_KEY_SHA256'))
    raw, nonce = _receive(env, time.monotonic() + 60, lambda challenge: capsule(challenge, public, sha))
    return project(raw, nonce)


def main():
    try:
        status = execute(os.environ)
    except Exception:
        status = 'EVA_BOOTSTRAP_REFUSED'
    print(status)
    return int(status != 'BOOTSTRAPPED')


if __name__ == '__main__':
    raise SystemExit(main())
