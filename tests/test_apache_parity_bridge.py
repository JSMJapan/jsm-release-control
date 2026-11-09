"""Offline public-control tests; private helper integration is explicitly opt-in.

No private helper bytes, application source, archive or source history are fixtures
in this public repository. The optional local test copies reviewed helper Git
objects only into an owned temporary Git fixture and never claims live admission.
"""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
try:
    import apache_parity_bridge as bridge
except ModuleNotFoundError:
    bridge = None


def context():
    return dict(GITHUB_REPOSITORY=bridge.CONTROL_REPO, GITHUB_ACTOR='JSMJapan',
                GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
                GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_RUN_ID='1',
                GITHUB_WORKFLOW_REF=bridge.CONTROL_REPO + '/.github/workflows/apache-bootstrap.yml@refs/heads/main')


def policies():
    repo = dict(full_name=bridge.CONTROL_REPO, private=False)
    env = dict(can_admins_bypass=False,
               protection_rules=[dict(type='required_reviewers', prevent_self_review=False,
                                      reviewers=[dict(type='User', reviewer=dict(login='JSMJapan'))])],
               deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True))
    branches = dict(total_count=1, branch_policies=[dict(name='main', type='branch')])
    return repo, {name: copy.deepcopy(env) for name in bridge.ENVIRONMENTS}, {
        name: copy.deepcopy(branches) for name in bridge.ENVIRONMENTS}


def pins():
    return dict(schema='jsm-apache-public-bridge-v1', control_repository=bridge.CONTROL_REPO,
                source_repository=bridge.SOURCE_REPO, resource='hostinger:srv1687281', domain='jsmjapan.com',
                admission='ESTABLISHED', source_pr=1905, reviewed_head_sha='a' * 40,
                source_merge_sha='b' * 40, builder_sha='c' * 40, pack_run_id=10, artifact_id=11,
                archive_sha256='d' * 64, inventory_sha256='e' * 64, bundle_sha256='f' * 64,
                payload_sha256='1' * 64, binding_sha256='2' * 64, deployment_authorized=False,
                executable_sha256={name: '3' * 64 for name in bridge.CLOSURE})


def metadata(p):
    source = bridge.SOURCE_REPO
    return dict(repository=dict(full_name=source, private=True),
                pr=dict(number=p['source_pr'], html_url='https://github.com/' + source + '/pull/' + str(p['source_pr']),
                        merged=True, base=dict(ref='main', repo=dict(full_name=source)),
                        head=dict(sha=p['reviewed_head_sha'], repo=dict(full_name=source)),
                        merge_commit_sha=p['source_merge_sha'], labels=[dict(name='apache-parity-reviewed')]),
                checks=dict(check_runs=[dict(id=n + 1, name=name, head_sha=p['reviewed_head_sha'],
                                            status='completed', conclusion='success',
                                            url='https://api.github.com/repos/' + source + '/check-runs/' + str(n + 1))
                                       for n, name in enumerate(bridge.CHECKS)]),
                run=dict(id=p['pack_run_id'], repository=dict(full_name=source),
                         path='.github/workflows/apache-parity-activation-pack.yml', head_sha=p['builder_sha'],
                         head_branch='main', event='workflow_dispatch', run_attempt=1, status='completed',
                         conclusion='success', actor=dict(login='JSMJapan'), triggering_actor=dict(login='JSMJapan')),
                artifact=dict(id=p['artifact_id'], name='apache-activation-1568-' + p['builder_sha'],
                              expired=False, size_in_bytes=1024, workflow_run=dict(id=p['pack_run_id'],
                                                                                 head_sha=p['builder_sha'])))


class PublicApi:
    def __init__(self, values=None):
        repo, envs, branches = policies() if values is None else values
        self.values = {bridge.PUBLIC_REPO_PATH: repo}
        for name in bridge.ENVIRONMENTS:
            path = bridge.PUBLIC_REPO_PATH + '/environments/' + name
            self.values[path] = envs[name]
            self.values[path + '/deployment-branch-policies'] = branches[name]
        self.calls = []

    def get_json(self, path):
        self.calls.append(path)
        return self.values[path]


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()


def commit(repo):
    git(repo, 'add', '.')
    git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'offline fixture')
    return git(repo, 'rev-parse', 'HEAD')


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(bridge, 'public policy/source adapter is not implemented')

    def test_public_owner_main_attempt_policy_before_credential(self):
        for key, value in [('GITHUB_REPOSITORY', bridge.SOURCE_REPO), ('GITHUB_ACTOR', 'other'),
                           ('GITHUB_TRIGGERING_ACTOR', 'other'), ('GITHUB_REF', 'refs/heads/topic'),
                           ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_RUN_ATTEMPT', '2'),
                           ('GITHUB_WORKFLOW_SHA', 'b' * 40), ('GITHUB_WORKFLOW_REF', 'other')]:
            env, api, accessed = context(), PublicApi(), []
            env[key] = value
            with self.assertRaises(bridge.Refused):
                bridge.collect_source_metadata(env, pins(), api, lambda: accessed.append(True))
            self.assertEqual([], api.calls)
            self.assertEqual([], accessed)
        repo, envs, branches = policies()
        envs[bridge.ENVIRONMENTS[-1]]['can_admins_bypass'] = True
        accessed = []
        with self.assertRaises(bridge.Refused):
            bridge.collect_source_metadata(context(), pins(), PublicApi((repo, envs, branches)),
                                           lambda: accessed.append(True))
        self.assertEqual([], accessed)

    def test_all_three_public_policies_require_owner_main_no_bypass(self):
        bridge.public_policy_ready(context(), *policies())
        for name in bridge.ENVIRONMENTS:
            for mutation in ('bypass', 'reviewer', 'self_review', 'branch', 'missing'):
                repo, envs, branches = policies()
                if mutation == 'bypass': envs[name]['can_admins_bypass'] = True
                if mutation == 'reviewer': envs[name]['protection_rules'][0]['reviewers'][0]['type'] = 'Team'
                if mutation == 'self_review': envs[name]['protection_rules'][0]['prevent_self_review'] = True
                if mutation == 'branch': branches[name]['branch_policies'][0]['name'] = '*'
                if mutation == 'missing': del envs[name]
                with self.assertRaises(bridge.Refused):
                    bridge.public_policy_ready(context(), repo, envs, branches)
        repo, envs, branches = policies()
        repo['private'] = True
        with self.assertRaises(bridge.Refused):
            bridge.public_policy_ready(context(), repo, envs, branches)

    def test_unresolved_real_pins_and_every_malformed_pin_fail_closed(self):
        actual = json.loads((ROOT / 'scripts/apache_parity_binding.json').read_text())
        with self.assertRaisesRegex(bridge.Refused, 'PINS_UNRESOLVED'):
            bridge.validate_pins(actual)
        bridge.validate_pins(pins())
        for name in pins():
            candidate = pins()
            candidate[name] = None
            with self.subTest(name=name), self.assertRaises(bridge.Refused):
                bridge.validate_pins(candidate)
        for name, value in [('source_repository', bridge.CONTROL_REPO), ('source_pr', True),
                            ('artifact_id', 0), ('builder_sha', 'latest'), ('binding_sha256', '-'),
                            ('deployment_authorized', True), ('extra', 'synthetic-hidden')]:
            candidate = pins()
            candidate[name] = value
            with self.assertRaises(bridge.Refused):
                bridge.validate_pins(candidate)

    def test_private_source_checks_cannot_be_satisfied_by_public_ci(self):
        p = pins()
        bridge.source_metadata_ready(p, metadata(p))
        mutations = [('repository',), ('pr',), ('checks',), ('run',), ('artifact',)]
        for (area,) in mutations:
            data = metadata(p)
            if area == 'repository': data[area]['full_name'] = bridge.CONTROL_REPO
            if area == 'pr': data[area]['html_url'] = 'https://github.com/' + bridge.CONTROL_REPO + '/pull/1905'
            if area == 'checks': data[area]['check_runs'][0]['url'] = 'https://api.github.com/repos/' + bridge.CONTROL_REPO + '/check-runs/1'
            if area == 'run': data[area]['repository']['full_name'] = bridge.CONTROL_REPO
            if area == 'artifact': data[area]['workflow_run']['id'] += 1
            with self.subTest(area=area), self.assertRaises(bridge.Refused):
                bridge.source_metadata_ready(p, data)
        for area, key, value in [('pr', 'merge_commit_sha', '0' * 40), ('run', 'head_sha', '0' * 40),
                                 ('run', 'run_attempt', 2), ('artifact', 'id', 12), ('artifact', 'expired', True)]:
            data = metadata(p)
            data[area][key] = value
            with self.assertRaises(bridge.Refused): bridge.source_metadata_ready(p, data)

    def test_unknown_binding_allows_metadata_only_but_never_unsigned_request(self):
        p = pins()
        p['binding_sha256'] = None
        try:
            bridge.source_metadata_ready(p, metadata(p))
        except bridge.Refused:
            self.fail('metadata verification must not require the binding established by a later probe')
        with self.assertRaisesRegex(bridge.Refused, 'PINS_UNRESOLVED'):
            bridge.prepare_request('inspect', p, Path('/not-accessed'), metadata(p))

    def test_unmerged_unreviewed_or_nonmain_source_refuses_before_private_import(self):
        p = pins()
        for case in ('unmerged', 'unreviewed', 'nonmain'):
            data = metadata(p)
            if case == 'unmerged': data['pr']['merged'] = False
            if case == 'unreviewed': data['pr']['labels'] = []
            if case == 'nonmain': data['pr']['base']['ref'] = 'topic'
            with self.subTest(case=case), self.assertRaisesRegex(bridge.Refused, 'REVIEWED_MERGED_SOURCE_REQUIRED'):
                bridge.source_metadata_ready(p, data)

    def test_credential_is_requested_once_only_after_seven_public_policy_reads(self):
        p, public, accessed = pins(), PublicApi(), []
        data = metadata(p)
        base = '/repos/' + bridge.SOURCE_REPO
        rows = {base: data['repository'], base + '/pulls/1905': data['pr'],
                base + '/commits/' + p['reviewed_head_sha'] + '/check-runs?filter=latest&per_page=100': data['checks'],
                base + '/actions/runs/10': data['run'], base + '/actions/artifacts/11': data['artifact']}
        def credential():
            self.assertEqual(7, len(public.calls))
            accessed.append('read')
            return 'synthetic-read-credential'
        class Private:
            def get_json(self, path): return rows[path]
        def factory(selected, token):
            self.assertEqual(p, selected)
            self.assertEqual('synthetic-read-credential', token)
            return Private()
        result = bridge.collect_source_metadata(context(), p, public, credential, private_factory=factory)
        self.assertEqual(data, result)
        self.assertEqual(['read'], accessed)

    def http_fixture(self, raw=b'{}', status=200, headers=None):
        class Reply:
            def __init__(self): self.closed, self.stream = False, io.BytesIO(raw)
            def getheader(self, name): return (headers or {}).get(name, 'application/json' if name == 'Content-Type' else None)
            def read1(self, size): return self.stream.read(size)
            def close(self): self.closed = True
        reply = Reply()
        reply.status = status
        class Connection:
            class Socket:
                def settimeout(self, value): pass
            def __init__(self): self.calls, self.closed, self.sock = [], False, self.Socket()
            def request(self, method, path, body, headers): self.calls.append((method, path, body, headers))
            def getresponse(self): return reply
            def close(self): self.closed = True
        return Connection(), reply

    def test_real_get_transport_separates_auth_and_never_follows_redirects(self):
        public, reply = self.http_fixture()
        with patch.object(bridge.http.client, 'HTTPSConnection', return_value=public):
            self.assertEqual({}, bridge.PublicPolicyApi().get_json(bridge.PUBLIC_REPO_PATH))
        self.assertNotIn('Authorization', public.calls[0][3])
        self.assertNotIn('Cookie', public.calls[0][3])
        private, reply = self.http_fixture()
        with patch.object(bridge.http.client, 'HTTPSConnection', return_value=private):
            bridge.PrivateSourceApi(pins(), 'synthetic-read-credential').get_json('/repos/' + bridge.SOURCE_REPO)
        self.assertEqual('Bearer synthetic-read-credential', private.calls[0][3]['Authorization'])
        self.assertTrue(reply.closed and private.closed)
        redirect, reply = self.http_fixture(status=302, headers={'Location': 'https://blob.invalid/synthetic-hidden'})
        with patch.object(bridge.http.client, 'HTTPSConnection', return_value=redirect):
            with self.assertRaisesRegex(bridge.Refused, '^GITHUB_GET_STATUS_REFUSED$'):
                bridge.PrivateSourceApi(pins(), 'synthetic-read-credential').get_json('/repos/' + bridge.SOURCE_REPO)
        self.assertEqual(1, len(redirect.calls))
        self.assertTrue(reply.closed and redirect.closed)

    def test_real_get_transport_rejects_oversize_encoding_duplicate_json_and_deadline(self):
        cases = [(b'x' * (bridge.MAX_JSON + 1), {}), (b'{}', {'Content-Length': str(bridge.MAX_JSON + 1)}),
                 (b'{}', {'Content-Encoding': 'gzip'}), (b'{}', {'Content-Type': 'text/html'}),
                 (b'{"value":1,"value":2}', {}), (b'synthetic-hidden', {})]
        for index, (raw, headers) in enumerate(cases):
            connection, reply = self.http_fixture(raw, headers=headers)
            with self.subTest(index=index), patch.object(bridge.http.client, 'HTTPSConnection', return_value=connection):
                with self.assertRaises(bridge.Refused) as raised:
                    bridge.PublicPolicyApi().get_json(bridge.PUBLIC_REPO_PATH)
                self.assertNotIn('synthetic-hidden', str(raised.exception))
                self.assertTrue(reply.closed and connection.closed)
        api = bridge.PublicPolicyApi()
        api.deadline = 0
        with patch.object(bridge.http.client, 'HTTPSConnection', side_effect=AssertionError('network')):
            with self.assertRaisesRegex(bridge.Refused, 'GITHUB_READ_DEADLINE'):
                api.get_json(bridge.PUBLIC_REPO_PATH)

    def test_fixed_separate_public_private_get_scopes_refuse_before_network(self):
        with patch.object(bridge.http.client, 'HTTPSConnection', side_effect=AssertionError('network')):
            public = bridge.PublicPolicyApi()
            private = bridge.PrivateSourceApi(pins(), 'synthetic-read-credential')
            for path in ('/repos/' + bridge.SOURCE_REPO, bridge.PUBLIC_REPO_PATH + '/environments/other',
                         'https://example.invalid', bridge.PUBLIC_REPO_PATH + '?page=2'):
                with self.assertRaises(bridge.Refused): public.get_json(path)
            for path in (bridge.PUBLIC_REPO_PATH, '/api/vps/v1/virtual-machines',
                         '/repos/' + bridge.SOURCE_REPO + '/actions/artifacts/12',
                         'https://blob.invalid/private'):
                with self.assertRaises(bridge.Refused): private.get_json(path)

    def fixture(self, directory, *, checker=True):
        repo = Path(directory) / 'source'
        repo.mkdir()
        git(repo, 'init', '-q')
        git(repo, 'remote', 'add', 'origin', 'https://github.com/' + bridge.SOURCE_REPO + '.git')
        target = repo / 'infra/apache-parity'
        target.mkdir(parents=True)
        for name in bridge.CLOSURE:
            (target / name).write_text("raise RuntimeError('SYNTHETIC_HELPER_MUST_NOT_IMPORT')\n")
        if checker:
            for name in bridge.CHECKERS:
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('# synthetic presence fixture, never executed\n')
        sha = commit(repo)
        p = pins()
        p.update(reviewed_head_sha=sha, source_merge_sha=sha, builder_sha=sha,
                 executable_sha256={name: hashlib.sha256((target / name).read_bytes()).hexdigest()
                                    for name in bridge.CLOSURE})
        archive = Path(directory) / 'pack.tar'
        with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT): pass
        p['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        return repo, p, archive

    def test_source_not_in_main_missing_checker_and_later_checker_refuse_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, p, archive = self.fixture(temporary, checker=False)
            with self.assertRaisesRegex(bridge.Refused, 'SELECTED_SOURCE_CHECKER_REQUIRED'):
                bridge.verify_private_pack(p, repo, archive, metadata=metadata(p))
            for name in bridge.CHECKERS:
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('# later checker cannot repair selected merge\n')
            p['builder_sha'] = commit(repo)
            with self.assertRaisesRegex(bridge.Refused, 'SELECTED_SOURCE_CHECKER_REQUIRED'):
                bridge.verify_private_pack(p, repo, archive, metadata=metadata(p))
            p['source_merge_sha'] = '0' * 40
            with self.assertRaisesRegex(bridge.Refused, 'SOURCE_NOT_IN_MAIN'):
                bridge.verify_private_pack(p, repo, archive, metadata=metadata(p))

    def test_executable_closure_and_archive_tamper_refuse_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, p, archive = self.fixture(temporary)
            for name in bridge.CLOSURE:
                changed = copy.deepcopy(p)
                changed['executable_sha256'][name] = '0' * 64
                with self.subTest(module=name), self.assertRaisesRegex(bridge.Refused, 'EXECUTABLE_CLOSURE_MISMATCH'):
                    bridge.verify_private_pack(changed, repo, archive, metadata=metadata(changed))
        with tempfile.TemporaryDirectory() as temporary:
            repo, p, archive = self.fixture(temporary)
            (repo / 'infra/apache-parity/package.py').write_text('# benign drift\n')
            p['builder_sha'] = commit(repo)
            with self.assertRaisesRegex(bridge.Refused, 'EXECUTABLE_CLOSURE_MISMATCH'):
                bridge.verify_private_pack(p, repo, archive, metadata=metadata(p))
        with tempfile.TemporaryDirectory() as temporary:
            repo, p, archive = self.fixture(temporary)
            archive.write_bytes(b'synthetic archive tamper')
            with self.assertRaisesRegex(bridge.Refused, 'ARCHIVE_PIN_MISMATCH'):
                bridge.verify_private_pack(p, repo, archive, metadata=metadata(p))

    def test_hardlinked_archive_refuses_before_private_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, p, archive = self.fixture(temporary)
            alias = Path(temporary) / 'linked.tar'
            os.link(archive, alias)
            with self.assertRaisesRegex(bridge.Refused, 'LOCAL_FILE_REFUSED'):
                bridge.verify_private_pack(p, repo, alias, metadata=metadata(p))

    def test_checkout_validation_cannot_execute_local_git_fsmonitor(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, p, _ = self.fixture(temporary)
            marker, hook = Path(temporary) / 'hook-ran', Path(temporary) / 'fsmonitor.sh'
            hook.write_text('#!/bin/sh\nprintf present > ' + shlex.quote(str(marker)) + '\nprintf "\\0"\n')
            hook.chmod(0o700)
            git(repo, 'config', 'core.fsmonitor', str(hook))
            bridge._checkout(p, repo)
            self.assertFalse(marker.exists(), 'Git repository metadata must not execute an unreviewed hook')

    def test_boolean_attempt_and_ids_are_not_private_provenance(self):
        p = pins()
        p.update(pack_run_id=1, artifact_id=1)
        for area, key in [('run', 'run_attempt'), ('run', 'id'), ('artifact', 'id')]:
            data = metadata(p)
            data[area][key] = True
            with self.subTest(area=area, key=key), self.assertRaises(bridge.Refused):
                bridge.source_metadata_ready(p, data)

    def test_private_process_output_and_deadline_are_hard_bounds_and_never_print(self):
        saved = io.StringIO()
        with contextlib.redirect_stdout(saved):
            with self.assertRaisesRegex(bridge.Refused, 'PRIVATE_PROCESS_OUTPUT_LIMIT'):
                bridge._bounded(['/usr/bin/python3', '-I', '-B', '-c', "print('synthetic-hidden'*10000)"], limit=64)
            with self.assertRaisesRegex(bridge.Refused, 'PRIVATE_PROCESS_DEADLINE'):
                bridge._bounded(['/usr/bin/python3', '-I', '-B', '-c', 'import time; time.sleep(2)'], timeout=.05)
        self.assertEqual('', saved.getvalue())

    def test_closed_stdout_then_sleep_is_a_fixed_bounded_deadline_refusal(self):
        started = bridge.time.monotonic()
        with self.assertRaisesRegex(bridge.Refused, '^PRIVATE_PROCESS_DEADLINE$'):
            bridge._bounded(['/usr/bin/python3', '-I', '-B', '-c',
                             'import os,time; os.close(1); time.sleep(2)'], timeout=.05)
        self.assertLess(bridge.time.monotonic() - started, 1)

    def test_ignored_import_cache_and_extension_artifacts_refuse_before_import(self):
        for extra in ('__pycache__', 'protocol.pyc', 'protocol.so'):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                repo, p, _ = self.fixture(temporary)
                (repo / '.git/info/exclude').write_text('__pycache__/\n*.pyc\n*.so\n')
                path = repo / 'infra/apache-parity' / extra
                if extra == '__pycache__':
                    path.mkdir()
                    path = path / 'synthetic.pyc'
                path.write_bytes(b'benign nonexecutable import-inventory fixture')
                self.assertEqual('', git(repo, 'status', '--porcelain', '--untracked-files=all'))
                with self.assertRaisesRegex(bridge.Refused, 'EXECUTABLE_CLOSURE_MISMATCH'):
                    bridge._checkout(p, repo)

    def test_connection_close_response_keeps_current_remaining_body_timeout(self):
        connection, reply = self.http_fixture()
        class Socket:
            def __init__(self): self.timeout = 1
            def settimeout(self, value): self.timeout = value
        retained = Socket()
        connection.sock = retained
        clock, observed = {'now': 0}, []
        original_read = reply.read1
        def getresponse():
            clock['now'] = .95
            connection.sock = None  # http.client detaches a Connection: close response.
            return reply
        def read1(size):
            observed.append(retained.timeout)
            return original_read(size)
        connection.getresponse, reply.read1 = getresponse, read1
        api = bridge.PublicPolicyApi()
        api.deadline = 1
        with patch.object(bridge.time, 'monotonic', side_effect=lambda: clock['now']), \
             patch.object(bridge.http.client, 'HTTPSConnection', return_value=connection):
            self.assertEqual({}, api.get_json(bridge.PUBLIC_REPO_PATH))
        self.assertTrue(observed)
        self.assertTrue(all(0 < timeout <= .051 for timeout in observed))

    def test_private_import_snapshot_is_owned_exact_and_removed_after_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, p, archive = self.fixture(temporary)
            actual_bounded, observed = bridge._bounded, []
            def run(command, **kwargs):
                if command[0] != '/usr/bin/python3':
                    return actual_bounded(command, **kwargs)
                data = json.loads(kwargs['data'])
                self.assertIn('import_root', data)
                directory = Path(data['import_root'])
                observed.append(directory.parent)
                self.assertNotEqual(repo / 'infra/apache-parity', directory)
                self.assertEqual(0o700, stat.S_IMODE(directory.stat().st_mode))
                self.assertEqual(set(bridge.CLOSURE), {path.name for path in directory.iterdir()})
                for name in bridge.CLOSURE:
                    path = directory / name
                    self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
                    self.assertEqual(p['executable_sha256'][name], hashlib.sha256(path.read_bytes()).hexdigest())
                return 0, b'{"status":"OK","result":{"fixture":"synthetic"}}'
            with patch.object(bridge, '_bounded', side_effect=run):
                self.assertEqual({'fixture': 'synthetic'}, bridge._private_call('verify', p, repo, metadata(p),
                                                                              archive=str(archive)))
            self.assertEqual(1, len(observed))
            self.assertFalse(observed[0].exists())

    def test_source_only_cli_cannot_upload_private_payload_or_access_credentials(self):
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(ROOT / 'scripts/apache_parity_bridge.py')],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
                                env={'APACHE_PARITY_SOURCE_READ_TOKEN': 'synthetic-hidden'})
        self.assertEqual(1, result.returncode)
        self.assertEqual({'status': 'BLOCKED', 'reason': 'TASK1_SOURCE_ONLY_NO_LIVE_CLI'}, json.loads(result.stdout))


class PrivateHelperIntegration(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('JSM_APACHE_REVIEW_ROOT'), 'NOT_RUN: explicit clean private review checkout required')
    def test_actual_unchanged_private_helpers_rebuild_verify_and_prepare_offline(self):
        private = Path(os.environ['JSM_APACHE_REVIEW_ROOT']).resolve()
        frozen = '45f8cc9c264f86c008cf4cd352c1ff5d2a12ca47'
        self.assertEqual(frozen, git(private, 'rev-parse', 'HEAD'))
        self.assertEqual('', git(private, 'status', '--porcelain', '--untracked-files=all'))
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve() / 'source'
            repo.mkdir()
            git(repo, 'init', '-q')
            git(repo, 'remote', 'add', 'origin', 'https://github.com/' + bridge.SOURCE_REPO + '.git')
            target = repo / 'infra/apache-parity'
            target.mkdir(parents=True)
            # These unchanged private Git objects stay in this owned temp only.
            for name in bridge.CLOSURE + ('install.sh', 'binding.example.json', 'conditions.conf'):
                raw = subprocess.check_output(['git', '-C', str(private), 'cat-file', 'blob',
                                               frozen + ':infra/apache-parity/' + name])
                (target / name).write_bytes(raw)
            for name in bridge.CHECKERS:
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('# synthetic selected-merge presence; never executed\n')
            sha = commit(repo)
            p = pins()
            p.update(reviewed_head_sha=sha, source_merge_sha=sha, builder_sha=sha,
                     executable_sha256={name: hashlib.sha256((target / name).read_bytes()).hexdigest()
                                        for name in bridge.CLOSURE})
            data = metadata(p)
            pack = Path(temporary) / 'independent-pack'
            program = ('import json,pathlib,sys; d=json.load(sys.stdin); '
                       'sys.path.insert(0,str(pathlib.Path(d["repo"])/"infra/apache-parity")); '
                       'from activation_pack import build_activation; '
                       'build_activation(pathlib.Path(d["repo"]),d["pr"],d["checks"],d["sha"],pathlib.Path(d["out"]))')
            completed = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', program],
                                       input=json.dumps(dict(repo=str(repo), pr=data['pr'], checks=data['checks'],
                                                             sha=sha, out=str(pack))).encode(),
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
                                       env={'PATH': '/usr/bin:/bin'})
            self.assertEqual(0, completed.returncode)
            inventory = json.loads((pack / 'activation-manifest.json').read_text())
            p.update(bundle_sha256=inventory['bundle_sha256'], payload_sha256=inventory['payload_sha256'],
                     inventory_sha256=hashlib.sha256((pack / 'activation-manifest.json').read_bytes()).hexdigest())
            archive = Path(temporary) / 'actual-helpers.tar'
            with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as output:
                for path in sorted(pack.iterdir()):
                    raw = path.read_bytes()
                    info = tarfile.TarInfo(path.name)
                    info.size, info.mode, info.uid, info.gid = len(raw), 0o600, 0, 0
                    output.addfile(info, io.BytesIO(raw))
            p['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
            saved = io.StringIO()
            with contextlib.redirect_stdout(saved):
                verified = bridge.verify_private_pack(p, repo, archive, metadata=data)
                request = bridge.prepare_request('inspect', p, repo, data)
            self.assertEqual('', saved.getvalue())
            self.assertEqual('EXACT_SOURCE_REBUILD_VERIFIED_NOT_INSTALLED', verified['status'])
            self.assertEqual(bridge.CONTROL_REPO, verified['control_repository'])
            self.assertEqual(bridge.SOURCE_REPO, verified['source_repository'])
            self.assertEqual({'version': 'jsm-apache-parity-v1', 'operation': 'inspect', 'resource': 'hostinger:srv1687281',
                              'domain': 'jsmjapan.com', 'pr': '1905', 'source_sha': sha,
                              'bundle_sha256': p['bundle_sha256'], 'payload_sha256': p['payload_sha256'],
                              'binding_sha256': p['binding_sha256'], 'before_sha256': '-', 'after_sha256': '-',
                              'context_sha256': '-', 'check_sha256': '-', 'expires': 1, 'nonce': '0' * 32}, request)
            self.assertNotIn('source-evidence', json.dumps(verified))
            check_data = dict(data, request=dict(before_sha256='4' * 64, after_sha256='5' * 64,
                                                 context_sha256='6' * 64, check_sha256='-'))
            checked = bridge.prepare_request('check', p, repo, check_data)
            self.assertEqual('check', checked['operation'])
            self.assertEqual('4' * 64, checked['before_sha256'])
            for operation in ('deploy', 'rollback'):
                with self.assertRaisesRegex(bridge.Refused, 'DEPLOYMENT_NOT_AUTHORIZED'):
                    bridge.prepare_request(operation, p, repo, data)
            for name in ('inventory_sha256', 'bundle_sha256', 'payload_sha256'):
                wrong = dict(p)
                wrong[name] = '0' * 64
                with self.subTest(pin=name), self.assertRaisesRegex(bridge.Refused, '(INVENTORY|PAYLOAD)_PIN_MISMATCH'):
                    bridge.verify_private_pack(wrong, repo, archive, metadata=data)
            without_binding = dict(p, binding_sha256=None)
            self.assertEqual(verified, bridge.verify_private_pack(without_binding, repo, archive, metadata=data))
            with self.assertRaisesRegex(bridge.Refused, 'PINS_UNRESOLVED'):
                bridge.prepare_request('inspect', without_binding, repo, data)
            bad = copy.deepcopy(data)
            bad['pr']['merged'] = False
            with self.assertRaisesRegex(bridge.Refused, 'REVIEWED_MERGED_SOURCE_REQUIRED'):
                bridge.verify_private_pack(p, repo, archive, metadata=bad)
            # A reviewed archive hash alone cannot replace independent Git-object rebuilding.
            with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as output:
                for path in sorted(pack.iterdir()):
                    raw = b'synthetic-hidden' if path.name == 'conditions.conf' else path.read_bytes()
                    info = tarfile.TarInfo(path.name)
                    info.size, info.mode, info.uid, info.gid = len(raw), 0o600, 0, 0
                    output.addfile(info, io.BytesIO(raw))
            p['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(bridge.Refused, 'PACK_ARCHIVE_'):
                bridge.verify_private_pack(p, repo, archive, metadata=data)
            self.assertFalse(list(repo.rglob('__pycache__')))


if __name__ == '__main__':
    unittest.main()
