"""#2767: execute the real fixed capsule against isolated filesystem fixtures."""
import contextlib
import copy
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
