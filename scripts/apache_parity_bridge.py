#!/usr/bin/env python3
"""Source-only public policy/private pack adapter. No SSH, signer or installer.

Private helpers are imported only by an isolated bounded child after exact Git,
reviewed executable pins, source ancestry and selected-source checker checks.
Downloaded archives are data, never imported. This module has no live CLI.
"""
if __name__ == '__main__':
    print('{"reason":"TASK1_SOURCE_ONLY_NO_LIVE_CLI","status":"BLOCKED"}')
    raise SystemExit(1)

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import stat
import subprocess
import tempfile
import time

from hostinger_preflight import Refused, policy_ready

CONTROL_REPO = 'JSMJapan/jsm-release-control'
SOURCE_REPO = 'JSMJapan/jsm-storefront'
ENVIRONMENTS = ('apache-parity-bootstrap', 'apache-parity-policy-read', 'apache-parity-signing')
PUBLIC_REPO_PATH = '/repos/' + CONTROL_REPO
PUBLIC_PATHS = {PUBLIC_REPO_PATH} | {
    PUBLIC_REPO_PATH + '/environments/' + name + suffix
    for name in ENVIRONMENTS for suffix in ('', '/deployment-branch-policies')}
CLOSURE = ('activate.py', 'activation_pack.py', 'activation_verify.py', 'package.py',
           'prepare.py', 'controller.py', 'protocol.py', 'namespace_check.py')
CHECKERS = ('scripts/seo/googlebot_parity.py', 'scripts/seo/ssr_check.py')
CHECKS = ('Тесты', 'Поиск секретов', 'Тесты компонентов')
PIN_FIELDS = {'schema', 'control_repository', 'source_repository', 'resource', 'domain', 'admission',
              'source_pr', 'reviewed_head_sha', 'source_merge_sha', 'builder_sha', 'pack_run_id', 'artifact_id',
              'archive_sha256', 'inventory_sha256', 'bundle_sha256', 'payload_sha256', 'binding_sha256',
              'deployment_authorized', 'executable_sha256'}
MAX_JSON = 256 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024


def need(condition, code):
    if not condition:
        raise Refused(code)


def strict_json(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'DUPLICATE_JSON_FIELD')
            value[key] = item
        return value
    def invalid(_):
        raise Refused('JSON_CONSTANT_REFUSED')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError):
        raise Refused('JSON_RESPONSE_REFUSED') from None


def validate_pins(pins, *, require_binding=True):
    need(type(pins) is dict and set(pins) == PIN_FIELDS, 'PIN_SCHEMA_REQUIRED')
    fixed = dict(schema='jsm-apache-public-bridge-v1', control_repository=CONTROL_REPO,
                 source_repository=SOURCE_REPO, resource='hostinger:srv1687281', domain='jsmjapan.com')
    need(all(pins.get(name) == value for name, value in fixed.items()), 'PIN_SCOPE_MISMATCH')
    need(pins['deployment_authorized'] is False, 'DEPLOYMENT_NOT_AUTHORIZED')
    need(pins['admission'] == 'ESTABLISHED' and all(value is not None for name, value in pins.items()
         if require_binding or name != 'binding_sha256'), 'PINS_UNRESOLVED')
    for name in ('source_pr', 'pack_run_id', 'artifact_id'):
        need(type(pins[name]) is int and 0 < pins[name] < (10 ** 7 if name == 'source_pr' else 10 ** 15), 'PIN_ID_FORMAT')
    for name in ('reviewed_head_sha', 'source_merge_sha', 'builder_sha'):
        need(type(pins[name]) is str and re.fullmatch('[0-9a-f]{40}', pins[name]), 'PIN_SHA_FORMAT')
    for name in ('archive_sha256', 'inventory_sha256', 'bundle_sha256', 'payload_sha256', 'binding_sha256'):
        if name == 'binding_sha256' and pins[name] is None and not require_binding:
            continue  # Source/archive verification precedes the first real operator binding probe.
        need(type(pins[name]) is str and re.fullmatch('[0-9a-f]{64}', pins[name]), 'PIN_DIGEST_FORMAT')
    closure = pins['executable_sha256']
    need(type(closure) is dict and set(closure) == set(CLOSURE)
         and all(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) for value in closure.values()),
         'EXECUTABLE_PINS_REQUIRED')


def context_ready(context):
    fixed = dict(GITHUB_REPOSITORY=CONTROL_REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
                 GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                 GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com')
    workflows = {CONTROL_REPO + '/.github/workflows/' + name + '@refs/heads/main'
                 for name in ('apache-bootstrap.yml', 'apache-parity.yml')}
    need(type(context) is dict and all(context.get(name) == value for name, value in fixed.items())
         and context.get('GITHUB_WORKFLOW_REF') in workflows
         and type(context.get('GITHUB_SHA')) is str and re.fullmatch('[0-9a-f]{40}', context['GITHUB_SHA'])
         and context.get('GITHUB_WORKFLOW_SHA') == context['GITHUB_SHA']
         and type(context.get('GITHUB_RUN_ID')) is str and re.fullmatch('[0-9]{1,15}', context['GITHUB_RUN_ID']),
         'PUBLIC_OWNER_MANUAL_MAIN_FIRST_ATTEMPT_REQUIRED')


def public_policy_ready(context, repo, environments, branches):
    context_ready(context)
    need(type(environments) is dict and set(environments) == set(ENVIRONMENTS)
         and type(branches) is dict and set(branches) == set(ENVIRONMENTS), 'THREE_PUBLIC_POLICIES_REQUIRED')
    try:
        for name in ENVIRONMENTS:
            policy_ready(repo, environments[name], branches[name])
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError):
        raise Refused('PUBLIC_POLICY_SCHEMA_REFUSED') from None


class _GitHubGet:
    def __init__(self, paths, token=None):
        self.paths, self.token = frozenset(paths), token
        self.deadline = time.monotonic() + 45

    def remaining(self):
        value = self.deadline - time.monotonic()
        need(value > 0, 'GITHUB_READ_DEADLINE')
        return min(value, 10)

    def get_json(self, path):
        need(type(path) is str and path in self.paths, 'FIXED_GITHUB_GET_SCOPE_REQUIRED')
        connection = response = None
        try:
            connection = http.client.HTTPSConnection('api.github.com', 443, timeout=self.remaining(),
                                                       context=ssl.create_default_context())
            headers = {'Accept': 'application/vnd.github+json', 'Accept-Encoding': 'identity',
                       'User-Agent': 'jsm-apache-public-bridge-1568', 'X-GitHub-Api-Version': '2022-11-28',
                       'Connection': 'close'}
            if self.token is not None:
                headers['Authorization'] = 'Bearer ' + self.token
            connection.request('GET', path, body=None, headers=headers)
            body_socket = connection.sock  # getresponse() detaches it for Connection: close.
            need(body_socket is not None, 'GITHUB_SOCKET_REQUIRED')
            body_socket.settimeout(self.remaining())
            response = connection.getresponse()
            need(response.status == 200, 'GITHUB_GET_STATUS_REFUSED')  # Redirects are never followed.
            need((response.getheader('Content-Type') or '').split(';')[0].strip().lower() == 'application/json',
                 'GITHUB_JSON_CONTENT_TYPE_REQUIRED')
            need((response.getheader('Content-Encoding') or 'identity').lower() == 'identity',
                 'GITHUB_ENCODING_REFUSED')
            length = response.getheader('Content-Length')
            need(length is None or (re.fullmatch('[0-9]+', length) and int(length) <= MAX_JSON), 'GITHUB_RESPONSE_LIMIT')
            raw = bytearray()
            while True:
                body_socket.settimeout(self.remaining())
                chunk = response.read1(min(16384, MAX_JSON + 1 - len(raw)))
                raw.extend(chunk)
                need(len(raw) <= MAX_JSON, 'GITHUB_RESPONSE_LIMIT')
                if not chunk:
                    return strict_json(raw.decode('utf-8'))
        except Refused:
            raise
        except Exception:
            raise Refused('GITHUB_TRANSPORT_OR_SCHEMA_REFUSED') from None
        finally:
            if response is not None: response.close()
            if connection is not None: connection.close()


class PublicPolicyApi(_GitHubGet):
    def __init__(self):
        super().__init__(PUBLIC_PATHS)  # No credential argument or provider/blob origin.


class PrivateSourceApi(_GitHubGet):
    def __init__(self, pins, token):
        validate_pins(pins, require_binding=False)
        need(type(token) is str and re.fullmatch('[!-~]{1,4096}', token), 'SOURCE_READ_CREDENTIAL_REQUIRED')
        base = '/repos/' + SOURCE_REPO
        paths = {base, base + '/pulls/' + str(pins['source_pr']),
                 base + '/commits/' + pins['reviewed_head_sha'] + '/check-runs?filter=latest&per_page=100',
                 base + '/actions/runs/' + str(pins['pack_run_id']),
                 base + '/actions/artifacts/' + str(pins['artifact_id'])}
        super().__init__(paths, token)


def collect_source_metadata(context, pins, public_api, credential_provider, *, private_factory=PrivateSourceApi):
    context_ready(context)  # Before network and every credential-provider call.
    repo = public_api.get_json(PUBLIC_REPO_PATH)
    envs, branches = {}, {}
    for name in ENVIRONMENTS:
        path = PUBLIC_REPO_PATH + '/environments/' + name
        envs[name] = public_api.get_json(path)
        branches[name] = public_api.get_json(path + '/deployment-branch-policies')
    public_policy_ready(context, repo, envs, branches)
    validate_pins(pins, require_binding=False)
    source = private_factory(pins, credential_provider())
    base = '/repos/' + SOURCE_REPO
    metadata = dict(repository=source.get_json(base), pr=source.get_json(base + '/pulls/' + str(pins['source_pr'])),
                    checks=source.get_json(base + '/commits/' + pins['reviewed_head_sha'] + '/check-runs?filter=latest&per_page=100'),
                    run=source.get_json(base + '/actions/runs/' + str(pins['pack_run_id'])),
                    artifact=source.get_json(base + '/actions/artifacts/' + str(pins['artifact_id'])))
    source_metadata_ready(pins, metadata)
    return metadata  # Internal data only; never a public receipt/log/artifact.


def source_metadata_ready(pins, metadata):
    validate_pins(pins, require_binding=False)
    try:
        need(type(metadata) is dict and {'repository', 'pr', 'checks', 'run', 'artifact'} <= set(metadata)
             and set(metadata) <= {'repository', 'pr', 'checks', 'run', 'artifact', 'request'}, 'SOURCE_METADATA_REQUIRED')
        repo, pr, run, artifact = (metadata[name] for name in ('repository', 'pr', 'run', 'artifact'))
        need(repo.get('full_name') == SOURCE_REPO and repo.get('private') is True, 'PRIVATE_SOURCE_REPOSITORY_REQUIRED')
        labels = pr.get('labels')
        need(pr.get('merged') is True and pr['base'].get('ref') == 'main' and type(labels) is list
             and len(labels) <= 100 and all(type(row) is dict and type(row.get('name')) is str for row in labels)
             and 'apache-parity-reviewed' in {row['name'] for row in labels}, 'REVIEWED_MERGED_SOURCE_REQUIRED')
        need(pr.get('number') == pins['source_pr']
             and pr.get('html_url') == 'https://github.com/' + SOURCE_REPO + '/pull/' + str(pins['source_pr'])
             and pr['base']['repo']['full_name'] == SOURCE_REPO and pr['head']['repo']['full_name'] == SOURCE_REPO
             and pr['head']['sha'] == pins['reviewed_head_sha'] and pr.get('merge_commit_sha') == pins['source_merge_sha'],
             'EXACT_PRIVATE_SOURCE_PR_REQUIRED')
        checks = metadata['checks']['check_runs']
        need(type(checks) is list and len(checks) <= 100, 'BOUNDED_SOURCE_CHECKS_REQUIRED')
        for name in CHECKS:
            selected = [row for row in checks if row.get('name') == name]
            need(selected and all(type(row.get('id')) is int and 0 < row['id'] < 10 ** 15 for row in selected),
                 'EXACT_PRIVATE_CI_REQUIRED')
            row = max(selected, key=lambda item: item['id'])
            need(row.get('head_sha') == pins['reviewed_head_sha'] and row.get('status') == 'completed'
                 and row.get('conclusion') == 'success'
                 and row.get('url') == 'https://api.github.com/repos/' + SOURCE_REPO + '/check-runs/' + str(row['id']),
                 'EXACT_PRIVATE_CI_REQUIRED')
        expected = dict(id=pins['pack_run_id'], path='.github/workflows/apache-parity-activation-pack.yml',
                        head_sha=pins['builder_sha'], head_branch='main', event='workflow_dispatch',
                        run_attempt=1, status='completed', conclusion='success')
        need(type(run.get('id')) is int and type(run.get('run_attempt')) is int
             and all(run.get(key) == value for key, value in expected.items())
             and run['repository']['full_name'] == SOURCE_REPO and run['actor']['login'] == 'JSMJapan'
             and run['triggering_actor']['login'] == 'JSMJapan', 'EXACT_PRIVATE_PACK_RUN_REQUIRED')
        need(type(artifact.get('id')) is int and artifact.get('id') == pins['artifact_id'] and artifact.get('expired') is False
             and artifact.get('name') == 'apache-activation-1568-' + pins['builder_sha']
             and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= 3 * 1024 * 1024
             and type(artifact['workflow_run']['id']) is int and artifact['workflow_run']['id'] == pins['pack_run_id']
             and artifact['workflow_run']['head_sha'] == pins['builder_sha'], 'EXACT_PRIVATE_ARTIFACT_REQUIRED')
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise Refused('PRIVATE_SOURCE_SCHEMA_REFUSED') from None


def _bounded(command, *, data=b'', limit=MAX_JSON, timeout=60):
    """Hard stdout/deadline limits; child stderr and private exceptions never leave."""
    environment = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                   'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0'}
    with tempfile.TemporaryFile() as input_file:
        input_file.write(data)
        input_file.seek(0)
        process = subprocess.Popen(command, stdin=input_file, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=environment, start_new_session=True)
        deadline, output = time.monotonic() + timeout, bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    need(remaining > 0, 'PRIVATE_PROCESS_DEADLINE')
                    for key, _ in selector.select(min(.2, remaining)):
                        chunk = os.read(key.fileobj.fileno(), min(16384, limit + 1 - len(output)))
                        if not chunk:
                            left = deadline - time.monotonic()
                            need(left > 0, 'PRIVATE_PROCESS_DEADLINE')
                            return process.wait(timeout=left), bytes(output)
                        output.extend(chunk)
                        need(len(output) <= limit, 'PRIVATE_PROCESS_OUTPUT_LIMIT')
        except subprocess.TimeoutExpired:
            raise Refused('PRIVATE_PROCESS_DEADLINE') from None
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise Refused('PRIVATE_PROCESS_DEADLINE') from None
            finally:
                process.stdout.close()


def _git(root, *arguments, required=True):
    code, raw = _bounded(['/usr/bin/git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                         '-C', str(root), *arguments], timeout=10, limit=1024 * 1024)
    need(not required or code == 0, 'FROZEN_SOURCE_GIT_OBJECT_REQUIRED')
    return code, raw


def _read_regular(path, limit):
    path = Path(path)
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
             and before.st_size <= limit, 'LOCAL_FILE_REFUSED')
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
        stamp = lambda row: tuple(getattr(row, key) for key in
            ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(descriptor)) == stamp(path.lstat()),
             'LOCAL_FILE_REFUSED')
        return bytes(raw)
    except OSError:
        raise Refused('LOCAL_FILE_REFUSED') from None
    finally:
        if descriptor is not None: os.close(descriptor)


def _checkout(pins, source_checkout):
    root = Path(source_checkout).resolve(strict=True)
    need(not Path(source_checkout).is_symlink() and root.is_dir(), 'CLEAN_FROZEN_SOURCE_CHECKOUT_REQUIRED')
    _, head = _git(root, 'rev-parse', 'HEAD')
    _, dirty = _git(root, 'status', '--porcelain', '--untracked-files=all')
    _, remote = _git(root, 'remote', 'get-url', 'origin')
    need(head.decode().strip() == pins['builder_sha'] and not dirty
         and remote.decode().strip() == 'https://github.com/' + SOURCE_REPO + '.git',
         'CLEAN_FROZEN_SOURCE_CHECKOUT_REQUIRED')
    code, _ = _git(root, 'merge-base', '--is-ancestor', pins['source_merge_sha'], pins['builder_sha'], required=False)
    need(code == 0, 'SOURCE_NOT_IN_MAIN')
    for path in CHECKERS:
        code, _ = _git(root, 'cat-file', '-e', pins['source_merge_sha'] + ':' + path, required=False)
        need(code == 0, 'SELECTED_SOURCE_CHECKER_REQUIRED')
    directory = root / 'infra/apache-parity'
    _, tree = _git(root, 'ls-tree', '--name-only', pins['builder_sha'] + ':infra/apache-parity')
    entries = []
    for path in directory.iterdir():
        need(len(entries) < 64, 'EXECUTABLE_CLOSURE_MISMATCH')
        entries.append(path)
    need(directory.resolve() == directory and {path.name for path in entries} == set(tree.decode().splitlines())
         and {path.name for path in entries if path.suffix == '.py'} == set(CLOSURE)
         and all(not path.is_symlink() and path.is_file() and path.suffix in ('.py', '.md', '.json', '.conf', '.sh')
                 for path in entries),
         'EXECUTABLE_CLOSURE_MISMATCH')
    for name in CLOSURE:
        path = directory / name
        _, source = _git(root, 'cat-file', 'blob', pins['source_merge_sha'] + ':infra/apache-parity/' + name)
        _, builder = _git(root, 'cat-file', 'blob', pins['builder_sha'] + ':infra/apache-parity/' + name)
        need(source == builder == _read_regular(path, MAX_JSON)
             and hashlib.sha256(source).hexdigest() == pins['executable_sha256'][name], 'EXECUTABLE_CLOSURE_MISMATCH')
    return root


_PRIVATE_WORKER = r'''
import hashlib,json,pathlib,sys,tempfile
data=json.loads(sys.stdin.buffer.read(262145))
root=pathlib.Path(data['root'])
sys.path.insert(0,data['import_root'])
from activation_verify import run_ready,compare_archive
from activation_pack import build_activation
from prepare import source_ready
from package import build
from protocol import Refuse,validate
try:
 p,m=data['pins'],data['metadata']
 run_ready(m['run'],p['builder_sha'])
 source=source_ready(m['pr'],m['checks'],data.get('operation','inspect'))
 if source!=p['source_merge_sha']: raise Refuse('SOURCE_PIN_MISMATCH')
 with tempfile.TemporaryDirectory(prefix='rebuild-',dir=data['work_root']) as temporary:
  output=pathlib.Path(temporary)/'pack'
  if data['task']=='verify':
   manifest=build_activation(root,m['pr'],m['checks'],p['builder_sha'],output)
   compare_archive(data['archive'],output)
   if hashlib.sha256((output/'activation-manifest.json').read_bytes()).hexdigest()!=p['inventory_sha256']:
    raise Refuse('INVENTORY_PIN_MISMATCH')
   result=dict(status='EXACT_SOURCE_REBUILD_VERIFIED_NOT_INSTALLED',inventory_sha256=p['inventory_sha256'],
               archive_sha256=p['archive_sha256'],source_merge_sha=source,builder_sha=p['builder_sha'])
  else:
   manifest=build(root,source,output)
   pre=m.get('request',{})
   result=dict(version='jsm-apache-parity-v1',operation=data['operation'],resource=p['resource'],domain=p['domain'],
               pr=str(p['source_pr']),source_sha=source,bundle_sha256=p['bundle_sha256'],payload_sha256=p['payload_sha256'],
               binding_sha256=p['binding_sha256'],before_sha256=pre.get('before_sha256','-'),
               after_sha256=pre.get('after_sha256','-'),context_sha256=pre.get('context_sha256','-'),
               check_sha256=pre.get('check_sha256','-'),expires=1,nonce='0'*32)
   validate(result)
  if any(manifest[name]!=p[name] for name in ('bundle_sha256','payload_sha256')): raise Refuse('PAYLOAD_PIN_MISMATCH')
 print(json.dumps(dict(status='OK',result=result),sort_keys=True))
except Refuse as error:
 print(json.dumps(dict(status='BLOCKED',reason=str(error))))
 sys.exit(1)
'''


_PRIVATE_CODES = {'PACK_WORKFLOW_PROVENANCE_MISMATCH', 'REVIEWED_MERGED_SOURCE_REQUIRED', 'REAL_TEST_EVIDENCE_REQUIRED',
                  'EXACT_SOURCE_CI_NOT_GREEN', 'EXACT_SOURCE_CI_SHA_MISMATCH', 'ACTIVATION_SOURCE_METADATA_INVALID',
                  'ACTIVATION_BUILDER_DIFFERS_FROM_REVIEWED_SOURCE', 'PACK_ARCHIVE_SIZE', 'PACK_ARCHIVE_INVENTORY_MISMATCH',
                  'PACK_ARCHIVE_EXACT_GIT_OBJECT_MISMATCH', 'PACK_ARCHIVE_INCOMPLETE', 'SOURCE_PIN_MISMATCH',
                  'INVENTORY_PIN_MISMATCH', 'PAYLOAD_PIN_MISMATCH', 'REQUEST_FIELDS', 'REQUEST_SCOPE', 'REQUEST_FORMAT',
                  'REQUEST_EXPIRY', 'INSPECT_PREIMAGE', 'PREIMAGE_REQUIRED', 'CHECK_REQUIRED'}


def _private_call(task, pins, root, metadata, **arguments):
    # Never pass process environment, tokens, PR bodies or downloaded code to the child.
    pr = {name: metadata['pr'][name] for name in ('number', 'html_url', 'merged', 'base', 'head', 'merge_commit_sha', 'labels')}
    pr['base'] = {'ref': pr['base']['ref']}
    pr['head'] = {'sha': pr['head']['sha']}
    selected = [{key: row[key] for key in ('id', 'name', 'head_sha', 'status', 'conclusion')}
                for row in metadata['checks']['check_runs'] if row.get('name') in CHECKS]
    safe = dict(pr=pr, checks=dict(check_runs=selected), run={key: metadata['run'][key] for key in
                ('path', 'head_sha', 'head_branch', 'event', 'run_attempt', 'status', 'conclusion', 'actor', 'triggering_actor')})
    safe['pr']['labels'] = [{'name': item['name']} for item in safe['pr']['labels']]
    if 'request' in metadata:
        pre = metadata['request']
        need(type(pre) is dict and set(pre) <= {'before_sha256', 'after_sha256', 'context_sha256', 'check_sha256'},
             'FIXED_PREIMAGE_FIELDS_REQUIRED')
        safe['request'] = pre
    with tempfile.TemporaryDirectory(prefix='jsm-private-worker-') as temporary:
        work = Path(temporary)
        imports = work / 'imports'
        imports.mkdir(mode=0o700)
        # Import a fresh private snapshot of reviewed Git bytes, never worktree
        # caches/extensions or archive members. The parent also owns cleanup if
        # the bounded child is killed before its own finally/context cleanup.
        for name in CLOSURE:
            _, source = _git(root, 'cat-file', 'blob', pins['builder_sha'] + ':infra/apache-parity/' + name)
            need(hashlib.sha256(source).hexdigest() == pins['executable_sha256'][name], 'EXECUTABLE_CLOSURE_MISMATCH')
            path = imports / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(source)
            need(_read_regular(path, MAX_JSON) == source, 'EXECUTABLE_CLOSURE_MISMATCH')
        data = json.dumps(dict(task=task, pins=pins, root=str(root), metadata=safe, import_root=str(imports),
                               work_root=str(work), **arguments)).encode()
        need(len(data) <= MAX_JSON, 'PRIVATE_INPUT_LIMIT')
        code, raw = _bounded(['/usr/bin/python3', '-I', '-B', '-c', _PRIVATE_WORKER], data=data, limit=8192)
    try:
        result = strict_json(raw.decode('ascii'))
        if code or result.get('status') != 'OK':
            reason = result.get('reason')
            raise Refused(reason if reason in _PRIVATE_CODES else 'PRIVATE_HELPER_REFUSED')
        return result['result']
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        raise Refused('PRIVATE_HELPER_RECEIPT_REFUSED') from None


def verify_private_pack(pins, source_checkout, archive, *, metadata=None):
    source_metadata_ready(pins, metadata)
    root = _checkout(pins, source_checkout)
    raw = _read_regular(archive, MAX_ARCHIVE)
    need(hashlib.sha256(raw).hexdigest() == pins['archive_sha256'], 'ARCHIVE_PIN_MISMATCH')
    with tempfile.TemporaryDirectory(prefix='jsm-private-pack-') as temporary:
        snapshot = Path(temporary) / 'pack.tar'
        snapshot.write_bytes(raw)
        snapshot.chmod(0o600)
        result = _private_call('verify', pins, root, metadata, archive=str(snapshot))
    expected = dict(status='EXACT_SOURCE_REBUILD_VERIFIED_NOT_INSTALLED', inventory_sha256=pins['inventory_sha256'],
                    archive_sha256=pins['archive_sha256'], source_merge_sha=pins['source_merge_sha'], builder_sha=pins['builder_sha'])
    need(result == expected, 'PRIVATE_VERIFIER_RECEIPT_PIN_MISMATCH')
    return dict(expected, control_repository=CONTROL_REPO, source_repository=SOURCE_REPO)


def prepare_request(operation, pins, source_checkout, metadata):
    validate_pins(pins)  # Unlike a pack probe, an unsigned channel request requires an established binding.
    source_metadata_ready(pins, metadata)
    need(operation in ('inspect', 'check'), 'DEPLOYMENT_NOT_AUTHORIZED')
    root = _checkout(pins, source_checkout)
    result = _private_call('prepare', pins, root, metadata, operation=operation)
    expected = dict(version='jsm-apache-parity-v1', operation=operation, resource=pins['resource'], domain=pins['domain'],
                    pr=str(pins['source_pr']), source_sha=pins['source_merge_sha'], bundle_sha256=pins['bundle_sha256'],
                    payload_sha256=pins['payload_sha256'], binding_sha256=pins['binding_sha256'],
                    expires=1, nonce='0' * 32)
    for name in ('before_sha256', 'after_sha256', 'context_sha256', 'check_sha256'):
        expected[name] = metadata.get('request', {}).get(name, '-')
    need(result == expected, 'PRIVATE_REQUEST_RECEIPT_PIN_MISMATCH')
    return expected
