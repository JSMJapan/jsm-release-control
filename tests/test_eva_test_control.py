"""Offline proofs for the protected control path and its exact artifact frame."""

from dataclasses import asdict
from hashlib import sha256
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import eva_test_actions as actions
import eva_test_archive as archive
import eva_test_install as install
import eva_test_receiver as receiver
from article_test_state import canonical

SHA = 'a' * 40
RUN = 'b' * 12
NONCE = 'c' * 32
OWNER = {'login': 'JSMJapan', 'id': actions.OWNER_ID}
BUILD = archive.EvaBuild(SHA, '123', '456', 'd' * 64)


def control_rows():
    repo = {'id': actions.REPO_ID, 'full_name': actions.REPO, 'private': False, 'owner': OWNER}
    environment = {
        'id': 789, 'name': actions.ENVIRONMENT, 'can_admins_bypass': False,
        'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': False,
                              'reviewers': [{'type': 'User', 'reviewer': OWNER}]}],
        'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True},
    }
    policies = {'total_count': 1, 'branch_policies': [{'name': 'main', 'type': 'branch'}]}
    branch = {'name': 'main', 'protected': True, 'commit': {'sha': SHA}}
    work = {'path': actions.WORKFLOW, 'id': 1, 'state': 'active'}
    run = {'path': actions.WORKFLOW, 'workflow_id': 1, 'head_sha': SHA, 'head_branch': 'main',
           'event': 'workflow_dispatch', 'status': 'in_progress', 'id': 123, 'run_attempt': 1,
           'repository': repo, 'head_repository': repo, 'actor': OWNER, 'triggering_actor': OWNER}
    approvals = [{'state': 'approved', 'user': OWNER, 'environments': [environment]}]
    return dict(zip(actions.control_paths('123'), (repo, environment, policies, branch, work, run, approvals)))


def environment():
    return {
        'GITHUB_REPOSITORY': actions.REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR': 'JSMJapan',
        'GITHUB_TRIGGERING_ACTOR': 'JSMJapan', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ATTEMPT': '1',
        'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_API_URL': 'https://api.github.com',
        'GITHUB_JOB': 'install', 'GITHUB_WORKFLOW_REF': actions.REPO + '/' + actions.WORKFLOW + '@refs/heads/main',
        'GITHUB_WORKFLOW_SHA': SHA, 'GITHUB_SHA': SHA, 'APPROVED_SHA': SHA, 'GITHUB_RUN_ID': '123',
    }


def artifact_rows():
    repo = {'id': 12, 'full_name': actions.SOURCE_REPO, 'private': True, 'owner': OWNER}
    run = {'repository': repo, 'head_repository': repo, 'event': 'pull_request', 'id': 123,
           'path': actions.PACKAGE_WORKFLOW, 'status': 'completed', 'conclusion': 'success',
           'head_sha': SHA, 'run_attempt': 1}
    item = {'name': BUILD.artifact_name, 'digest': 'sha256:' + BUILD.archive_sha256, 'id': 456,
            'expired': False, 'size_in_bytes': 1010, 'workflow_run': {'head_sha': SHA, 'id': 123}}
    steps = [{'name': name, 'status': 'completed', 'conclusion': 'success'} for name in actions.ARTIFACT_STEPS]
    job = {'name': 'package', 'status': 'completed', 'conclusion': 'success', 'head_sha': SHA,
           'run_id': 123, 'steps': steps}
    return dict(zip(actions.artifact_paths(BUILD), (repo, run, {'total_count': 1, 'artifacts': [item]},
                                                    {'total_count': 1, 'jobs': [job]}, item)))


class ControlTests(unittest.TestCase):
    def test_owner_approved_exact_main_and_attempt(self):
        rows = control_rows()
        api = Mock()
        api.get_json.side_effect = rows.__getitem__
        actions.authorize(api, environment(), '123', SHA)
        for name, value in (('GITHUB_RUN_ATTEMPT', '2'), ('APPROVED_SHA', '1' * 40),
                            ('GITHUB_REF', 'refs/heads/feature')):
            with self.subTest(name=name), self.assertRaises(archive.EvaRefused):
                actions.authorize(api, {**environment(), name: value}, '123', SHA)
        rows[actions.control_paths('123')[-1]][0]['user'] = {'login': 'JSMJapan', 'id': 9}
        with self.assertRaises(archive.EvaRefused):
            actions.authorize(api, environment(), '123', SHA)

    def test_native_provenance_is_mandatory(self):
        rows = artifact_rows()
        paths = actions.artifact_paths(BUILD)
        api = Mock()
        api.get_json.side_effect = rows.__getitem__
        self.assertEqual(actions.authorize_artifact(api, BUILD), 1010)
        rows[paths[-2]]['jobs'][0]['steps'][4]['conclusion'] = 'skipped'
        with self.assertRaises(archive.EvaRefused):
            actions.authorize_artifact(api, BUILD)

    def test_transport_is_fixed_and_cannot_be_a_shell(self):
        args = install.transport(Path('/tmp/fixture-key'), Path('/tmp/fixture-hosts'))
        self.assertEqual(args[-2:], ['jsm-eva-stage@34.104.157.63', receiver.COMMAND])
        for option in ('StrictHostKeyChecking=yes', 'ClearAllForwardings=yes', 'IdentityAgent=none'):
            self.assertIn(option, args)

    def test_receiver_rejects_old_article_frame_and_different_reviewed_sha(self):
        with patch.object(receiver, 'load_pins', return_value=BUILD):
            good = receiver.prefix('STAGE', RUN, NONCE, SHA, BUILD, 12)
            for data, expected in ((good, SHA), (good, '9' * 40), (b'JSM_ARTICLE_TEST_2760_V1\n' + good, SHA)):
                read, write = os.pipe()
                try:
                    os.write(write, data)
                    os.close(write)
                    if data == good and expected == SHA:
                        self.assertEqual(receiver.frame(read, time.monotonic() + 1, expected)['artifact'], asdict(BUILD))
                    else:
                        with self.assertRaises(archive.EvaRefused):
                            receiver.frame(read, time.monotonic() + 1, expected)
                finally:
                    os.close(read)

    def test_stage_refuses_before_payload_if_expiry_cannot_arm(self):
        class FakeStore:
            path = Path('/tmp/never-used')
            def __init__(self, *_args, **_kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                pass
            def save(self, state):
                self.state = state
            def read(self):
                return self.state
        with (patch.object(receiver, 'State', FakeStore), patch.object(receiver, 'load_pins', return_value=BUILD),
              patch.object(receiver, 'arm_expiry', side_effect=archive.EvaRefused('EVA_STATE_REFUSED')),
              patch.object(receiver, 'receive') as receive, patch.object(receiver, 'clean') as clean):
            with self.assertRaises(archive.EvaRefused):
                receiver.execute({'op': 'STAGE', 'run': RUN}, 0, time.monotonic() + 2)
        receive.assert_not_called()
        clean.assert_called_once()

    def test_receipt_cannot_claim_live_https_or_telegram(self):
        value = {'status': 'STAGED_LOCAL_ONLY', 'protocol': receiver.PROTOCOL, 'run': RUN,
                 'nonce': NONCE, 'expires': int(time.time()) + 30, 'build_sha': SHA,
                 'artifact_sha256': BUILD.archive_sha256, 'pdo': 'BOUND_SYNTHETIC',
                 'https': 'NOT_CONFIGURED', 'telegram': 'NOT_RUN', 'claude': 'NOT_RUN'}
        self.assertEqual(install.project(canonical(value), 'STAGE', RUN, NONCE, BUILD)['pdo'], 'BOUND_SYNTHETIC')
        for name, fake in (('https', 'READY'), ('telegram', 'PASSED'), ('run', '9' * 12)):
            with self.subTest(name=name), self.assertRaises(archive.EvaRefused):
                install.project(canonical({**value, name: fake}), 'STAGE', RUN, NONCE, BUILD)

    def test_archive_checks_fixed_sources_and_inner_members(self):
        fixtures = {'schema.sql': b'fixture-schema', 'seed.sql': b'fixture-seed'}
        fixture_hashes = {name.split('.')[0] + '_sha256': sha256(data).hexdigest() for name, data in fixtures.items()}
        source = {'bridge_commit': archive.BRIDGE, 'bridge_tree': archive.BRIDGE_TREE,
                  'runner_commit': archive.RUNNER, 'runner_tree': archive.RUNNER_TREE, **fixture_hashes}
        members = {'images.tar.gz': b'test', 'runner.tar.gz': b'test', 'build-commit': (SHA + '\n').encode(),
                   'app-image-id': ('sha256:' + '1' * 64 + '\n').encode(),
                   'mysql-image-id': ('sha256:' + '2' * 64 + '\n').encode(), 'source.json': canonical(source),
                   'acceptance.json': canonical({**archive.RECEIPT, **fixture_hashes}), **fixtures}
        checksums = ''.join(f'{sha256(raw).hexdigest()}  {name}\n' for name, raw in sorted(members.items())).encode()
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'test.zip'
            for tampered in (False, True):
                with ZipFile(path, 'w') as target:
                    for name, data in members.items():
                        target.writestr(name, b'not admitted' if tampered and name == 'seed.sql' else data)
                    target.writestr('SHA256SUMS', checksums)
                build = archive.EvaBuild(SHA, '123', '456', sha256(path.read_bytes()).hexdigest())
                if tampered:
                    with self.assertRaises(archive.EvaRefused):
                        archive.inspect_archive(path, build)
                else:
                    checked, metadata = archive.inspect_archive(path, build)
                    self.assertEqual(checked.build.tags, build.tags)
                    self.assertEqual(metadata, fixtures)


class HostTests(unittest.TestCase):
    def test_docker_tag_probe_is_exact_and_only_for_eva(self):
        from eva_test_host import Docker
        docker = object.__new__(Docker)
        identity = 'sha256:' + '1' * 64
        with patch.object(docker, 'run', return_value=(identity + '\n').encode()) as cmd:
            self.assertEqual(docker.image_id(BUILD.tags[0]), identity)
            cmd.assert_called_once_with(('image', 'ls', '--quiet', '--no-trunc', '--filter',
                                         'reference=' + BUILD.tags[0]), limit=256)
            with self.assertRaises(archive.EvaRefused):
                docker.image_id('jsm-article-test:' + SHA)

    def test_interrupted_load_does_not_claim_cleanup_or_remove_recovery(self):
        import eva_test_host as host
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        target = Path(directory.name)
        private = target / 'artifact.zip'
        private.write_bytes(b'synthetic-private-archive')
        store = Mock(run=RUN, path=target)
        docker = Mock()
        docker.image_id.return_value = None
        docker.image_present.return_value = False
        state = {'import_started': True, 'import_complete': False, 'prepared': [],
                 'tags': list(BUILD.tags), 'aliases': [['sha256:' + '1' * 64], ['sha256:' + '2' * 64]]}
        with (patch.object(host.os, 'geteuid', return_value=0),
              patch.object(host, 'Docker', return_value=docker),
              patch.object(host, 'owned_file', return_value=True),
              patch.object(host.shutil, 'rmtree') as remove):
            with self.assertRaisesRegex(archive.EvaRefused, 'EVA_CLEANUP_UNCONFIRMED'):
                host.clean(store, state, time.monotonic() + 1)
        docker.run.assert_not_called()
        remove.assert_not_called()
        self.assertFalse(private.exists())


class ContainerdTests(unittest.TestCase):
    def test_layer_sidecars_require_opt_in_and_exact_graph(self):
        import article_test_images as images
        from article_test_artifact import inspect_archive
        from test_article_test_images import encoded, envelope
        import json

        def augment(rows, manifests, _ids, *, broken):
            for index, entry in enumerate(manifests):
                config = json.loads(rows[entry['Config']])
                descriptors = json.loads(rows['index.json'])['manifests']
                blob_name = 'blobs/sha256/' + descriptors[index]['digest'].split(':')[1]
                layers = json.loads(rows[blob_name])['layers']
                entry['LayerSources'] = dict(zip(config['rootfs']['diff_ids'], layers))
                value = {'id': str(index + 1) * 64, 'os': 'linux', 'created': '2026-01-01T00:00:00Z',
                         'container_config': {}, 'architecture': 'amd64', 'config': config['config']}
                if broken and index == 0:
                    value['parent'] = value['id']
                raw = encoded(value)
                rows['blobs/sha256/' + sha256(raw).hexdigest()] = raw
            rows['manifest.json'] = encoded(manifests)

        with TemporaryDirectory() as folder:
            path = Path(folder) / 'containerd.zip'
            for broken in (False, True):
                packed, build = envelope(oci=True, change=lambda *args: augment(*args, broken=broken))
                path.write_bytes(packed)
                inspected = inspect_archive(path, build)
                with self.assertRaises(images.ImageRefused):
                    images.verify(path, inspected, time.monotonic() + 3)
                if broken:
                    with self.assertRaises(images.ImageRefused):
                        images.verify(path, inspected, time.monotonic() + 3, containerd_layer_sources=True)
                else:
                    self.assertEqual(images.verify(path, inspected, time.monotonic() + 3,
                                                   containerd_layer_sources=True).layers, 1)


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_capsule_accepts_only_bound_new_account_and_key(self):
        import base64
        from eva_test_bootstrap import capsule, verified_key
        payload = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'x' * 32
        text = 'ssh-ed25519 ' + base64.b64encode(payload).decode()
        digest = sha256((text + '\n').encode()).hexdigest()
        public = verified_key(text, digest)
        with self.assertRaises(archive.EvaRefused):
            verified_key(text + ' comment', digest)
        with self.assertRaises(archive.EvaRefused):
            verified_key(text, 'f' * 64)

        # Inspect declarations and the package verifier without executing the host apply.
        from test_api_installed_route_readonly import wrap_root_program
        outer = wrap_root_program(NONCE, capsule(NONCE, public, SHA))
        self.assertLess(len(outer), 119000)
        compile(outer, '<synthetic outer>', 'exec')


class RoutePreflightTests(unittest.TestCase):
    def test_preflight_capsule_is_separate_from_install(self):
        from eva_test_bootstrap import PREFLIGHT_MODULES, preflight_capsule, preflight_receipt
        from eva_test_route_preflight import VERSION
        self.assertNotIn('eva_test_host.py', PREFLIGHT_MODULES)
        source = preflight_capsule(NONCE)
        compile(source, '<synthetic read-only responder>', 'exec')
        self.assertLess(len(source), 110000)
        detail = {'vhost_sha256': '3' * 64, 'certificate_sha256': '4' * 64,
                  'publisher_lock': 'OBSERVED_AND_AVAILABLE', 'provider_ipv4': '1.1.1.1',
                  'log_scope': 'ADMITTED', 'tls': 'LOCAL_SNI_VERIFIED'}
        child = {'version': VERSION, 'nonce': NONCE, 'euid': 0, 'status': 'OBSERVED', 'binding': detail}
        envelope = {'version': 'jsm-test-installed-route-outer-v2', 'nonce': NONCE, 'principal': 'marinagurina',
                    'euid': 10001, 'root_diagnostic': child}
        self.assertEqual(preflight_receipt(canonical(envelope), NONCE)['binding'], detail)
        detail['raw_config'] = 'synthetic private contents'
        with self.assertRaises(archive.EvaRefused):
            preflight_receipt(canonical(envelope), NONCE)

    def test_live_frame_accepts_only_policy_installed_by_exact_preflight(self):
        policy = {'status': 'PINNED', 'ingress': 'existing-apache', 'origin': 'https://eva-isolated-1620.jsmjapan.com',
                  'provider_ipv4': '1.1.1.1', 'certificate_sha256': '4' * 64, 'vhost_sha256': '3' * 64}
        with patch.object(receiver, 'load_pins', return_value=BUILD):
            value = receiver.prefix('STAGE_LIVE', RUN, NONCE, SHA, BUILD, 12, b'synthetic', policy)
            for current in (policy, {**policy, 'vhost_sha256': 'a' * 64}):
                read, write = os.pipe()
                try:
                    os.write(write, value)
                    os.close(write)
                    with patch.object(receiver, 'load_policy', return_value=current):
                        if current == policy:
                            self.assertEqual(receiver.frame(read, time.monotonic() + 1, SHA)['credentials_size'], 9)
                        else:
                            with self.assertRaises(archive.EvaRefused):
                                receiver.frame(read, time.monotonic() + 1, SHA)
                finally:
                    os.close(read)
