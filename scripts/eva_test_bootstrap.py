#!/usr/bin/env python3
"""Owner-approved provisioning of the one forced-command Eva TEST receiver."""

import base64
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import re
import sys
import time
import zlib
from zipfile import ZIP_DEFLATED, ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apache_parity_bridge import _GitHubGet, _read_regular, strict_json
from article_test_state import canonical
from eva_test_actions import REPO, authorize, control_paths
from eva_test_archive import load_pins, require
from eva_test_live import approved_policy, live_policy
from eva_test_route_preflight import VERSION as ROUTE_VERSION
from test_installer_capture_encrypted import _receive
from test_installer_receiver_bootstrap_host import HOST_SOURCE

ADMIN_ENV = 'test-api-readonly-access'
VERSION = 'jsm-eva-bootstrap-1620-v1'
SCOPE = 'INSTALL_EVA_ONLY_RECEIVER'
PREFLIGHT_SCOPE = 'OBSERVE_EVA_TEST_ROUTE'
UPGRADE_SCOPE = 'UPGRADE_EVA_ONLY_RECEIVER'
UPGRADE_VERSION = 'jsm-eva-receiver-upgrade-1620-v1'
UPGRADE_STATUSES = {'UPGRADED', 'ALREADY_CURRENT', 'INPUT_REFUSED', 'TARGET_REFUSED',
                    'RECEIVER_BUSY', 'PREVIOUS_REFUSED', 'ROLLED_BACK', 'STATE_UNCERTAIN'}
PREFLIGHT_MODULES = ('apache_parity_bridge.py', 'hostinger_preflight.py', 'article_test_artifact.py', 'eva_test_archive.py', 'eva_test_apache.py',
                     'test_installer_update_package.py', 'test_installer_update_receiver.py', 'eva_test_route_preflight.py')
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
# Byte-for-byte jsm-sandbox receiver from BOOTSTRAP 45340677450.
# The generated route policy was bound to PREFLIGHT 45340440257.
PREVIOUS_SHA = '8086f91b8a43cc28dc0a5ff41492606c4774d920'
PREVIOUS_RECEIVER = {
    'apache_parity_bridge.py': '4332a64986c8d4313d9e9ba695fabfb04e98efa941b29fa4e4012272953aaaa4',
    'article_test_actions.py': '771a871e10e4ac28417776185b72871b79ecf14ecb20370f2c35f944bbd8d656',
    'article_test_artifact.py': '6e9c22885703eab9aaf032191c7e17e3072bce369bcfd4211179cc67be1987bd',
    'article_test_docker.py': 'e17d816647306852bc7bda6a1beff0a6449a00240260571e292de2aef91041ea',
    'article_test_host.py': 'a26eebb0244c9ec1af88bae24e1a96d08640bb6f13dd26ed9fc09aa2a66e2ef9',
    'article_test_images.py': '32f38456ccd2874d87d6ab0e1d3da19d2979b59649b23eb1005112110aeabb0c',
    'article_test_receiver.py': '88c723d10a7677dabf9c374e4ceff8967c0d41368c1ccf771998e451dd8ab3b6',
    'article_test_smoke.py': '9a44d5f58099f1028d5d2bc9d4827b8dd2d9179fbe2cc92c214024461eef2c01',
    'article_test_state.py': 'c4a6c1b0a42395cedb1453cee8f3b5cc38dc0917677d971dfc99833aa956abfd',
    'control.sha': '26a46a58a09d0abd3a25c59807814c0628f7e6ac3008f0d7d106c599addbf973',
    'eva_test_apache.py': 'f3061ec20f2d4556135b1ed79463f7348d6c202bfb60457e5e3dcc6ebbd134e3',
    'eva_test_archive.py': 'c79f8ea2a00cf53ab61ef170a96f67369554ce6c2fb8c2b1398b422e9eb2df5e',
    'eva_test_host.py': '1bb01ab6a9a558f96bdc8fec04a1339743e66a0e5b7ff38a066b3b74c7f1abe2',
    'eva_test_ingress.py': '9baf75423e0dcdc7b0412b6fb751e0a429d6184c628e681610b725a38850dfa0',
    'eva_test_live.py': '8c01c36ab000445f10dd35ad06d988b987d30c89000a77a65bc78e218dc0b381',
    'eva_test_live_policy.json': '69e951bffdabcf95a1ad01d1156fa36b52ecfe5174fcfaa1f68c863e05948c03',
    'eva_test_pins.json': 'a8eea3db5c4ceb6385e8d0ded74a7a1cb4c1534ec932aaab727baad719b1cf45',
    'eva_test_receiver.py': 'cfda491628d758c064e271067a7098032136a48ef2600e5b38bfc98d6b147a29',
    'forced-command': 'b71e291efdde011e36feea8b2841e5735eb60764b6344303b9ace7b0582b4199',
    'hostinger_preflight.py': 'edb8a35940ad886f3e3ccf1e205054b5d64b23d328462dc5bd921ff422904cbc',
    'login-shell': '0e07ffeba12bb0a669544ff67cb21ae8f05b4477df54ae2aaf8b8a4083709d12',
    'test_api_readonly_access.py': '91d26cff6e35a9edc5aeada3c7a3d4f1117720655ddec7cf4b63553fed241e25',
    'test_installer_update_package.py': 'e40fd150cd9b3f639db36024344a1962f96845cfd287077f56df2300e1c79fe5',
    'test_installer_update_receiver.py': '092850b35c348f46d5b02a147a28d94bcd6411b307be8120495c72eb8c6b3a74',
}


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


def capsule(nonce, public, control_sha, root=None, policy=None):
    require(re.fullmatch('[0-9a-f]{32}', nonce) and re.fullmatch('[0-9a-f]{40}', control_sha),
            'EVA_BOOTSTRAP_CONTEXT_REFUSED')
    root = Path(__file__).resolve().parents[1] if root is None else Path(root)
    load_pins(root / 'scripts/eva_test_pins.json')
    files = {name: _read_regular(root / 'scripts' / name, 65536) for name in MODULES}
    files.update({name: _read_regular(root / 'ops/eva-test-1620' / name, 8192) for name in UNITS})
    if policy is not None:
        files['eva_test_live_policy.json'] = canonical(policy)
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


def preflight_capsule(nonce, root=None):
    require(re.fullmatch('[0-9a-f]{32}', nonce), 'EVA_BOOTSTRAP_CONTEXT_REFUSED')
    root = Path(__file__).resolve().parent if root is None else Path(root)
    output = BytesIO()
    with ZipFile(output, 'w', compression=ZIP_DEFLATED) as archive:
        for name in PREFLIGHT_MODULES:
            archive.writestr(name, _read_regular(root / name, 65536))
    payload = base64.b64encode(output.getvalue())
    source = ("import base64,os,sys; f=os.memfd_create('eva-1620-preflight',0); os.write(f,base64.b64decode("
              + repr(payload) + ")); sys.path.insert(0,'/proc/self/fd/'+str(f)); "
              "from eva_test_route_preflight import main; main(" + repr(nonce) + ")")
    require(len(source) < 110000, 'EVA_BOOTSTRAP_PACKAGE_REFUSED')
    return source


def upgrade_capsule(nonce, control_sha, policy, root=None):
    require(re.fullmatch('[0-9a-f]{32}', nonce) and re.fullmatch('[0-9a-f]{40}', control_sha)
            and control_sha != PREVIOUS_SHA, 'EVA_BOOTSTRAP_CONTEXT_REFUSED')
    folder = Path(__file__).resolve().parent if root is None else Path(root)
    fixed = _read_regular(folder / 'eva_test_host.py', 65536)
    require(sha256(fixed).hexdigest() != PREVIOUS_RECEIVER['eva_test_host.py'],
            'EVA_UPGRADE_REQUIRES_FIXED_HOST_MODULE')
    for module in MODULES:
        if module in ('eva_test_host.py', 'eva_test_live_policy.json'):
            continue
        installed = 'forced-command' if module == 'eva_test_forced_command.sh' else module
        require(sha256(_read_regular(folder / module, 65536)).hexdigest() == PREVIOUS_RECEIVER[installed],
                'EVA_UPGRADE_MODULE_DRIFT')
    validated = live_policy(canonical(policy))
    require(validated['ingress'] == 'existing-apache', 'EVA_ROUTE_PREFLIGHT_REFUSED')
    replacements = {'control.sha': (control_sha + '\n').encode('ascii'),
                    'eva_test_host.py': fixed, 'eva_test_live_policy.json': canonical(validated)}
    program = _read_regular(folder / 'eva_test_receiver_upgrade_host.py', 65536).decode('ascii')
    source = (fixed_template() + '\n' + program +
              f'\nupgrade_main({nonce!r}, {replacements!r}, {PREVIOUS_RECEIVER!r}, {UPGRADE_VERSION!r})\n')
    compile(source, '<Eva TEST upgrade>', 'exec')
    payload = base64.b64encode(zlib.compress(source.encode('ascii'), level=9))
    encoded = f'import base64,zlib;exec(compile(zlib.decompress(base64.b64decode({payload!r})), "<Eva TEST upgrade>", "exec"))'
    require(len(encoded) < 110000, 'EVA_BOOTSTRAP_PACKAGE_REFUSED')
    return encoded


def transport_receipt(raw, nonce):
    outer = strict_json(raw.decode('ascii'))
    root = outer.get('root_diagnostic')
    require(outer.keys() == {'version', 'nonce', 'principal', 'euid', 'root_diagnostic'}
            and outer['version'] == 'jsm-test-installed-route-outer-v2' and outer['nonce'] == nonce
            and outer['principal'] == 'marinagurina' and type(outer['euid']) is int and outer['euid'] > 0
            and type(root) is dict and root.get('nonce') == nonce
            and type(root.get('euid')) is int and root['euid'] == 0,
            'EVA_BOOTSTRAP_RECEIPT_REFUSED')
    return root


def preflight_receipt(raw, nonce):
    root = transport_receipt(raw, nonce)
    require(root.keys() == {'version', 'nonce', 'euid', 'status', 'binding'} and root['version'] == ROUTE_VERSION
            and root['status'] in ('OBSERVED', 'BLOCKED'), 'EVA_BOOTSTRAP_RECEIPT_REFUSED')
    binding = root['binding']
    if root['status'] == 'OBSERVED':
        require(type(binding) is dict and binding.keys() == {'vhost_sha256', 'certificate_sha256', 'publisher_lock',
                                                             'provider_ipv4', 'log_scope', 'tls'}
                and all(type(binding[name]) is str and re.fullmatch('[0-9a-f]{64}', binding[name])
                        for name in ('vhost_sha256', 'certificate_sha256'))
                and type(binding['provider_ipv4']) is str and re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}', binding['provider_ipv4'])
                and binding['publisher_lock'] == 'OBSERVED_AND_AVAILABLE' and binding['tls'] == 'LOCAL_SNI_VERIFIED'
                and binding['log_scope'] == 'ADMITTED', 'EVA_BOOTSTRAP_RECEIPT_REFUSED')
    else:
        require(binding is None, 'EVA_BOOTSTRAP_RECEIPT_REFUSED')
    return {'status': root['status'], 'binding': binding}


def project(raw, nonce, version=VERSION, statuses=STATUSES):
    root = transport_receipt(raw, nonce)
    require(root.keys() == {'version', 'nonce', 'euid', 'status'}
            and root['version'] == version and root['status'] in statuses, 'EVA_BOOTSTRAP_RECEIPT_REFUSED')
    return {'status': root['status']}


def execute(env):
    sha = env.get('GITHUB_SHA', '')
    run = env.get('GITHUB_RUN_ID', '')
    operation = env.get('OPERATION')
    expected = {'BOOTSTRAP': SCOPE, 'PREFLIGHT': PREFLIGHT_SCOPE, 'UPGRADE_RECEIVER': UPGRADE_SCOPE}
    require(re.fullmatch('[0-9a-f]{40}', sha) and re.fullmatch('[1-9][0-9]{0,14}', run)
            and operation in expected and env.get('APPROVED_SCOPE') == expected[operation], 'EVA_BOOTSTRAP_CONTEXT_REFUSED')
    paths = control_paths(run, environment_name=ADMIN_ENV)
    authorize(_GitHubGet(paths, token=env.get('GH_TOKEN')), env, run, sha, environment_name=ADMIN_ENV, job='bootstrap')
    if operation == 'PREFLIGHT':
        raw, nonce = _receive(env, time.monotonic() + 60, preflight_capsule)
        return {**preflight_receipt(raw, nonce), 'control_sha': sha,
                'workflow_run': 'https://github.com/' + REPO + '/actions/runs/' + run}
    policy = approved_policy(env.get('ROUTE_PREFLIGHT_RUN'), sha)
    if operation == 'UPGRADE_RECEIVER':
        raw, nonce = _receive(env, time.monotonic() + 60, lambda challenge: upgrade_capsule(challenge, sha, policy))
        return project(raw, nonce, UPGRADE_VERSION, UPGRADE_STATUSES)
    public = verified_key(env.get('EVA_STAGE_PUBLIC_KEY'), env.get('APPROVED_PUBLIC_KEY_SHA256'))
    raw, nonce = _receive(env, time.monotonic() + 60, lambda challenge: capsule(challenge, public, sha, policy=policy))
    return project(raw, nonce)


def main():
    try:
        result = execute(os.environ)
    except Exception:
        result = {'status': 'EVA_BOOTSTRAP_REFUSED'}
    sys.stdout.buffer.write(canonical(result))
    if result['status'] == 'OBSERVED' and os.environ.get('GITHUB_ACTIONS') == 'true':
        print('::notice file=scripts/eva_test_bootstrap.py,line=1,title=JSM Eva route preflight receipt::'
              + canonical(result).decode('ascii').strip())
    return int(result['status'] not in ('BOOTSTRAPPED', 'OBSERVED', 'UPGRADED', 'ALREADY_CURRENT'))


if __name__ == '__main__':
    raise SystemExit(main())
