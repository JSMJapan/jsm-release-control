"""#2767: execute the real fixed capsule against isolated filesystem fixtures."""
import contextlib
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
NONCE = 'c' * 32
KNOWN = 'synthetic-known-host\n'
PATHS = ('config/articleSeo.js', 'config/client.js', 'config/server.js', 'src/App.tsx',
         'src/pages/MainFlow/BlogArticle/index.tsx', 'src/helpers/articleFirstHtml.js',
         'src/components/ArticleFirstHtml/index.tsx')
VERSION = 'jsm-prod-article-sources-sha-2767-v1'


class ArticleSourcesTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('article_source_reader_fixture',
                                                    ROOT / 'scripts/prod_front_sha_readonly.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def capsule(self):
        self.assertTrue(hasattr(self.module, 'article_remote_program'), 'missing fixed seven-file capsule')
        namespace = {'__name__': 'fixture_only'}
        exec(compile(self.module.article_remote_program(NONCE), '<seven-fixed-reader>', 'exec'), namespace)
        return namespace

    def tree(self, folder):
        for path in PATHS[:5]:
            leaf = Path(folder) / path
            leaf.parent.mkdir(parents=True, exist_ok=True)
            leaf.write_bytes(b'SYNTHETIC_PRIVATE_SOURCE_' + path.encode())

    def local_rows(self, namespace, folder):
        namespace['BASE'] = str(Path(folder).resolve())
        real_open = os.open
        # Only the unavailable Linux file flag is masked in macOS fixtures.
        with patch.object(os, 'open', side_effect=lambda p, f, *a, **kw: real_open(p, f & ~0x40000, *a, **kw)):
            return namespace['read_files']()

    def payload(self):
        rows = [dict(path=p, type='regular', sha256='d' * 64, size=12, missing_component=None) for p in PATHS[:5]]
        rows += [dict(path=p, type='absent', sha256=None, size=None, missing_component=p) for p in PATHS[5:]]
        return dict(version=VERSION, nonce=NONCE, euid=0, files=rows, writes_performed=False)

    def context(self):
        return dict(GITHUB_REPOSITORY='JSMJapan/jsm-release-control', GITHUB_ACTOR='JSMJapan',
                    GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
                    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_RUN_ID='123',
                    GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/prod-article-sources-sha-readonly.yml@refs/heads/main',
                    APACHE_BOOTSTRAP_ADMIN_SSH_KEY='synthetic-private-key', APACHE_BOOTSTRAP_KNOWN_HOSTS=KNOWN)

    def api(self, protected=True):
        fixtures = [dict(full_name='JSMJapan/jsm-release-control', private=False),
                    dict(can_admins_bypass=False, protection_rules=[dict(type='required_reviewers', prevent_self_review=False,
                         reviewers=[dict(type='User', reviewer=dict(login='JSMJapan'))])] if protected else [],
                         deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True)),
                    dict(total_count=1, branch_policies=[dict(name='main', type='branch')])]
        calls = []
        class Api:
            def get_json(inner, host, path, token=None):
                calls.append((host, path, token))
                return fixtures[len(calls) - 1]
        return Api(), calls

    def test_real_five_digests_and_proven_leaf_or_directory_absence(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder)
            (Path(folder) / 'src/helpers').mkdir()
            (Path(folder) / 'src/components').mkdir()
            before = sorted(str(p.relative_to(folder)) for p in Path(folder).rglob('*'))
            rows = self.local_rows(ns, folder)
            self.assertEqual([r['path'] for r in rows], list(PATHS))
            self.assertEqual([r['type'] for r in rows], ['regular'] * 5 + ['absent'] * 2)
            for row in rows[:5]:
                data = b'SYNTHETIC_PRIVATE_SOURCE_' + row['path'].encode()
                self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(row['size'], len(data))
            self.assertEqual([r['missing_component'] for r in rows[5:]],
                             [PATHS[5], 'src/components/ArticleFirstHtml'])
            self.assertEqual(sorted(str(p.relative_to(folder)) for p in Path(folder).rglob('*')), before)
            self.assertNotIn('SYNTHETIC_PRIVATE_SOURCE', json.dumps(rows))

    def test_actual_remote_main_emits_correct_version_and_unprivileged_gate_never_reads(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder); ns['BASE'] = str(Path(folder).resolve()); real_open = os.open
            output = io.StringIO()
            # Only fixture identity/platform facts are replaced; this is not a
            # claim of native root/O_NOATIME execution on this macOS host.
            with patch.object(os, 'O_NOATIME', 0x40000, create=True), patch.object(os, 'geteuid', return_value=0), \
                 patch.object(os, 'open', side_effect=lambda p, f, *a, **kw: real_open(p, f & ~0x40000, *a, **kw)), \
                 contextlib.redirect_stdout(output): ns['main']()
            raw = output.getvalue().encode()
            self.assertEqual(json.loads(raw)['version'], VERSION)
            self.assertEqual(self.module.article_project_remote(raw, NONCE)['status'], 'PROD_FRONT_SEVEN_METADATA_COMPLETE')
            self.assertNotIn(b'SYNTHETIC_PRIVATE_SOURCE', raw)
            output = io.StringIO()
            with patch.object(os, 'O_NOATIME', 0x40000, create=True), patch.object(os, 'geteuid', return_value=1), \
                 patch.dict(ns, {'read_files': lambda: self.fail('non-root must not read files')}), \
                 contextlib.redirect_stdout(output): ns['main']()
            value = json.loads(output.getvalue())
            self.assertEqual(value['euid'], 1)
            self.assertEqual([row['type'] for row in value['files']], ['unreadable'] * 7)

    def test_first_missing_component_is_observed_but_missing_base_is_not_absence(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder)
            rows = self.local_rows(ns, folder)
            self.assertEqual(rows[5]['missing_component'], 'src/helpers')
            self.assertEqual(rows[6]['missing_component'], 'src/components')
            rows = self.local_rows(ns, str(Path(folder) / 'no-base'))
            self.assertTrue(all(r['type'] != 'absent' for r in rows))

    def test_permission_refusal_is_never_absence(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder)
            real_stat = os.stat
            def guarded(path, *args, **kwargs):
                if path == 'helpers' and kwargs.get('dir_fd') is not None:
                    raise PermissionError('SYNTHETIC_PRIVATE_PERMISSION')
                return real_stat(path, *args, **kwargs)
            with patch.object(os, 'stat', side_effect=guarded):
                rows = self.local_rows(ns, folder)
            self.assertEqual(rows[5]['type'], 'unreadable')
            self.assertIsNone(rows[5]['missing_component'])

    def test_permission_during_second_missing_check_is_unreadable_not_absent(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder); real_stat = os.stat; attempts = []
            def guarded(path, *args, **kwargs):
                if path == 'helpers' and kwargs.get('dir_fd') is not None:
                    attempts.append(True)
                    if len(attempts) == 2: raise PermissionError('SYNTHETIC_PRIVATE')
                return real_stat(path, *args, **kwargs)
            with patch.object(os, 'stat', side_effect=guarded): rows = self.local_rows(ns, folder)
            self.assertEqual(rows[5]['type'], 'unreadable')
            self.assertIsNone(rows[5]['missing_component'])

    def test_parent_replacement_during_absence_proof_refuses(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder)
            parent = Path(folder) / 'src/helpers'; parent.mkdir()
            real_stat = os.stat; changed = []
            def raced(path, *args, **kwargs):
                try:
                    return real_stat(path, *args, **kwargs)
                except FileNotFoundError:
                    if path == 'articleFirstHtml.js' and not changed:
                        parent.rename(parent.with_name('old-helpers'))
                        parent.mkdir(); changed.append(True)
                    raise
            with patch.object(os, 'stat', side_effect=raced):
                rows = self.local_rows(ns, folder)
            self.assertEqual(rows[5]['type'], 'unstable')
            self.assertIsNone(rows[5]['missing_component'])

    def test_absence_is_rechecked_and_a_new_component_cannot_be_admitted(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder)
            real_stat = os.stat; attempts = []
            def raced(path, *args, **kwargs):
                if path == 'helpers' and kwargs.get('dir_fd') is not None:
                    attempts.append(True)
                    if len(attempts) == 2:
                        (Path(folder) / 'src/helpers').mkdir()
                return real_stat(path, *args, **kwargs)
            with patch.object(os, 'stat', side_effect=raced):
                rows = self.local_rows(ns, folder)
            self.assertGreaterEqual(len(attempts), 2)
            self.assertEqual(rows[5]['type'], 'unstable')

    def test_missing_ancestor_checks_every_existing_parent_not_only_immediate_one(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder); real_stat = os.stat; changed = []
            def raced(path, *args, **kwargs):
                try: return real_stat(path, *args, **kwargs)
                except FileNotFoundError:
                    if path == 'helpers' and not changed:
                        (Path(folder) / 'src').rename(Path(folder) / 'old-src')
                        (Path(folder) / 'src').mkdir(); changed.append(True)
                    raise
            with patch.object(os, 'stat', side_effect=raced): rows = self.local_rows(ns, folder)
            self.assertEqual(rows[5]['type'], 'unstable')
            self.assertIsNone(rows[5]['missing_component'])

    def test_noatime_denial_has_no_unprotected_retry_and_new_parent_symlink_is_not_absent(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder); real_open = os.open; file_opens = []
            ns['BASE'] = str(Path(folder).resolve())
            def denied(path, flags, *args, **kwargs):
                if not flags & os.O_DIRECTORY:
                    file_opens.append((path, flags))
                    raise PermissionError('synthetic O_NOATIME denial')
                return real_open(path, flags, *args, **kwargs)
            with patch.object(os, 'open', side_effect=denied): rows = ns['read_files']()
            self.assertEqual(len(file_opens), 5)
            self.assertTrue(all(flags & 0x40000 for _, flags in file_opens))
            self.assertEqual([row['type'] for row in rows[:5]], ['unreadable'] * 5)
            (Path(folder) / 'foreign-helpers').mkdir()
            (Path(folder) / 'src/helpers').symlink_to(Path(folder) / 'foreign-helpers')
            rows = self.local_rows(ns, folder)
            self.assertNotEqual(rows[5]['type'], 'absent')

    def test_existing_missing_and_new_existing_are_not_expected_complete(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder)
            (Path(folder) / PATHS[0]).unlink()
            new = Path(folder) / PATHS[5]; new.parent.mkdir(); new.write_bytes(b'foreign existing file')
            rows = self.local_rows(ns, folder)
            self.assertNotEqual(rows[0]['type'], 'absent')
            self.assertEqual(rows[5]['type'], 'regular')
            value = self.payload(); value['files'] = rows
            receipt = self.module.article_project_remote(json.dumps(value).encode(), NONCE)
            self.assertEqual(receipt['status'], 'BLOCKED')

    def test_symlink_hardlink_directory_oversize_and_read_race_refuse(self):
        for case in ('symlink', 'parent_symlink', 'hardlink', 'directory', 'oversize', 'race'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                ns = self.capsule(); self.tree(folder); leaf = Path(folder) / PATHS[0]
                if case == 'symlink': leaf.unlink(); leaf.symlink_to(Path(folder) / PATHS[1])
                if case == 'parent_symlink':
                    leaf.parent.rename(Path(folder) / 'old-config'); leaf.parent.symlink_to(Path(folder) / 'old-config')
                if case == 'hardlink': leaf.unlink(); os.link(Path(folder) / PATHS[1], leaf)
                if case == 'directory': leaf.unlink(); leaf.mkdir()
                if case == 'oversize': leaf.write_bytes(b'x' * (1048576 + 1))
                real_read = os.read; changed = []
                def reading(fd, limit):
                    value = real_read(fd, limit)
                    if case == 'race' and not changed:
                        leaf.write_bytes(b'changed'); changed.append(True)
                    return value
                with patch.object(os, 'read', side_effect=reading): rows = self.local_rows(ns, folder)
                self.assertNotEqual(rows[0]['type'], 'regular')
                self.assertIsNone(rows[0]['sha256']); self.assertIsNone(rows[0]['size'])

    def test_closed_receipt_and_no_whole_release_or_atomic_snapshot_claim(self):
        value = self.module.article_project_remote(json.dumps(self.payload()).encode(), NONCE)
        self.assertEqual(value['status'], 'PROD_FRONT_SEVEN_METADATA_COMPLETE')
        self.assertIsNone(value['installed_release_sha'])
        self.assertEqual(value['deploy_acceptance'], 'NOT_ESTABLISHED')
        self.assertFalse(value['atomic_multi_file_snapshot'])
        for case in ('path', 'nonce', 'uid', 'size', 'extra', 'absent_existing', 'bad_prefix', 'duplicate', 'nonfinite', 'banner', 'oversize'):
            with self.subTest(case=case):
                p = self.payload()
                if case == 'path': p['files'][0]['path'] = '.env'
                if case == 'nonce': p['nonce'] = 'e' * 32
                if case == 'uid': p['euid'] = True
                if case == 'size': p['files'][0]['size'] = True
                if case == 'extra': p['files'][0]['body'] = 'SYNTHETIC_PRIVATE'
                if case == 'absent_existing': p['files'][0].update(type='absent', sha256=None, size=None, missing_component=PATHS[0])
                if case == 'bad_prefix': p['files'][5]['missing_component'] = 'src/../helpers'
                raw = json.dumps(p).encode()
                if case == 'duplicate': raw = raw.replace(b'"euid": 0', b'"euid": 1, "euid": 0')
                if case == 'nonfinite': raw = raw.replace(b'"size": 12', b'"size": NaN', 1)
                if case == 'banner': raw = b'SYNTHETIC_PRIVATE\n' + raw
                if case == 'oversize': raw = b'x' * 4097
                with self.assertRaises(self.module.Refused) as error:
                    self.module.article_project_remote(raw, NONCE)
                self.assertNotIn('SYNTHETIC_PRIVATE', str(error.exception))

    def test_context_policy_key_pin_refuse_before_transport_and_do_not_accept_legacy_workflow(self):
        for case in ('actor', 'trigger', 'workflow', 'sha', 'ref', 'event', 'attempt', 'policy', 'key', 'pin'):
            with self.subTest(case=case):
                env = self.context(); api, _ = self.api(case != 'policy')
                names = {'actor': 'GITHUB_ACTOR', 'trigger': 'GITHUB_TRIGGERING_ACTOR', 'workflow': 'GITHUB_WORKFLOW_REF',
                         'sha': 'GITHUB_WORKFLOW_SHA', 'ref': 'GITHUB_REF', 'event': 'GITHUB_EVENT_NAME',
                         'attempt': 'GITHUB_RUN_ATTEMPT', 'key': 'APACHE_BOOTSTRAP_ADMIN_SSH_KEY', 'pin': 'APACHE_BOOTSTRAP_KNOWN_HOSTS'}
                if case != 'policy': env[names[case]] = ''
                with patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
                     patch.object(self.module, 'article_bounded_ssh') as transport:
                    with self.assertRaises(self.module.Refused): self.module.article_collect(api, env)
                    transport.assert_not_called()
        env = self.context(); env['GITHUB_WORKFLOW_REF'] = env['GITHUB_WORKFLOW_REF'].replace('prod-article-sources-sha', 'prod-front-sha')
        with self.assertRaises(self.module.Refused): self.module.article_context_ready(env)
        with self.assertRaises(self.module.Refused): self.module.context_ready(self.context())

    def test_shared_transport_has_same_fixed_destination_key_only_and_local_temp_cleanup(self):
        api, calls = self.api(); folders = []
        def transport(command, program):
            self.assertEqual(command[-5:], ['root@187.77.118.50', '/usr/bin/python3', '-I', '-B', '-'])
            self.assertEqual(command[command.index('-p') + 1], '17177')
            for option in ('StrictHostKeyChecking=yes', 'IdentityAgent=none', 'BatchMode=yes', 'ClearAllForwardings=yes',
                           'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'PreferredAuthentications=publickey'):
                self.assertIn(option, command)
            identity = Path(command[command.index('-i') + 1]); folders.append(identity.parent)
            self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
            self.assertEqual(identity.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn(b'ARTICLE_PROFILE=True', program)
            self.assertLess(len(program), 16384)
            return json.dumps(self.payload()).encode()
        with patch.object(self.module, 'PIN_SHA256', hashlib.sha256(KNOWN.encode()).hexdigest()), \
             patch.object(self.module.secrets, 'token_hex', return_value=NONCE), \
             patch.object(self.module, 'article_bounded_ssh', side_effect=transport):
            value = self.module.article_collect(api, self.context())
        self.assertEqual(value['status'], 'PROD_FRONT_SEVEN_METADATA_COMPLETE')
        self.assertTrue(all(not folder.exists() for folder in folders))
        self.assertEqual(len(calls), 3)
        self.assertNotIn('synthetic-private-key', json.dumps(value))

    def test_existing_bounded_transport_refuses_oversize_nonreading_child_hang_and_stderr(self):
        import apache_parity_bridge as bridge
        original = bridge._bounded
        def short(command, **kwargs):
            return original(command, **dict(kwargs, timeout=0.15))
        for child in ('import time;time.sleep(5)',
                      'import os;os.close(1);import time;time.sleep(5)',
                      'import sys;sys.stdout.write("x"*4097)',
                      'import sys;sys.stderr.write("SYNTHETIC_PRIVATE");sys.exit(9)'):
            with self.subTest(child=child), patch.object(bridge, '_bounded', side_effect=short):
                with self.assertRaises(self.module.Refused) as error:
                    self.module.article_bounded_ssh([sys.executable, '-B', '-c', child], b'x' * 1048576)
                self.assertNotIn('SYNTHETIC_PRIVATE', str(error.exception))

    def test_fixed_workflow_and_main_redaction_do_not_claim_unobserved_paths(self):
        workflow = json.loads((ROOT / '.github/workflows/prod-article-sources-sha-readonly.yml').read_text())
        self.assertEqual(workflow['on'], {'workflow_dispatch': {}})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(workflow['concurrency'], {'group': 'apache-admin-readonly-probe', 'cancel-in-progress': False})
        self.assertEqual(workflow['jobs']['probe']['environment'], 'apache-parity-bootstrap')
        self.assertEqual(workflow['jobs']['probe']['steps'][-1]['run'], 'python3 -I -B scripts/prod_article_sources_sha_readonly.py')
        self.assertEqual(self.module.ARTICLE_PATHS, PATHS)
        for failure in (RuntimeError('SYNTHETIC_PRIVATE'), self.module.Refused('SYNTHETIC_PRIVATE')):
            output = io.StringIO()
            with patch.dict(os.environ, self.context(), clear=True), patch.object(self.module.sys, 'argv', ['probe.py']), \
                 patch.object(self.module, 'article_collect', side_effect=failure), contextlib.redirect_stdout(output):
                self.assertEqual(self.module.article_main(), 1)
            self.assertNotIn('SYNTHETIC_PRIVATE', output.getvalue())
            value = json.loads(output.getvalue())
            self.assertEqual(value['status'], 'BLOCKED')
            self.assertEqual([row['type'] for row in value['files']], ['not_observed'] * 7)
            self.assertIsNone(value['root_identity'])
            self.assertIsNone(value['installed_release_sha'])
            self.assertEqual(value['source_sha'], 'a' * 40)

    def test_ci_path_coverage_keeps_all_existing_scripts_tests_and_workflows(self):
        source = (ROOT / '.github/workflows/hostinger-readonly-preflight.yml').read_text()
        filters = [set(ast.literal_eval(line.split('paths:', 1)[1].strip()))
                   for line in source.splitlines() if line.strip().startswith('paths:')]
        self.assertEqual(len(filters), 2)
        required = {str(p.relative_to(ROOT)) for folder, pattern in
                    [('scripts', '*.py'), ('tests', 'test_*.py'), ('.github/workflows', '*.yml')]
                    for p in (ROOT / folder).glob(pattern)}
        for paths in filters: self.assertTrue(required <= paths, sorted(required - paths))

    def test_main_rejects_arguments_before_collection_and_complete_receipt_stays_bounded(self):
        output = io.StringIO()
        with patch.object(self.module.sys, 'argv', ['probe.py', '--path=.env']), \
             patch.object(self.module, 'article_collect') as collect, contextlib.redirect_stdout(output):
            self.assertEqual(self.module.article_main(), 1)
            collect.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['reason'], 'NO_ARGUMENTS_OR_INPUTS_ACCEPTED')
        output = io.StringIO()
        value = self.module.article_project_remote(json.dumps(self.payload()).encode(), NONCE)
        with patch.dict(os.environ, self.context(), clear=True), patch.object(self.module.sys, 'argv', ['probe.py']), \
             patch.object(self.module, 'article_collect', return_value=value), contextlib.redirect_stdout(output):
            self.assertEqual(self.module.article_main(), 0)
        self.assertLessEqual(len(output.getvalue().encode()), 4096)
        self.assertIsNone(json.loads(output.getvalue())['installed_release_sha'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual Linux O_NOATIME proof, never silently emulated')
    def test_linux_file_access_times_are_unchanged(self):
        ns = self.capsule()
        with tempfile.TemporaryDirectory() as folder:
            self.tree(folder); before = {}
            for path in PATHS[:5]:
                leaf = Path(folder) / path; os.utime(leaf, ns=(10**18, 10**18)); before[path] = leaf.stat().st_atime_ns
            ns['BASE'] = str(Path(folder).resolve())
            self.assertEqual([r['type'] for r in ns['read_files']()], ['regular'] * 5 + ['absent'] * 2)
            self.assertEqual({p: (Path(folder) / p).stat().st_atime_ns for p in PATHS[:5]}, before)


if __name__ == '__main__': unittest.main()
