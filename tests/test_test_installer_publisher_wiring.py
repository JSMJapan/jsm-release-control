from dataclasses import replace
from pathlib import Path
from contextlib import contextmanager
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import test_installer_publisher_wiring as wiring
import test_installer_publisher_guard as guard
from test_db_installer_receipt import ServingGeneration, render_installer_receipt


RUN = wiring.PublisherRun('1' * 40, '2' * 40, '12345')
WINDOW = wiring.ReportWindow(RUN, '3' * 40, 'a' * 64, 100, 130)


def report(window=WINDOW):
    run = window.run
    generation = ServingGeneration(run.requested_site_sha, '4' * 64, '5' * 64, '6' * 64, '7' * 64)
    return render_installer_receipt(
        workflow_sha=run.workflow_sha, requested_site_sha=run.requested_site_sha, run_id=run.run_id,
        run_attempt=1, actor='JSMJapan', triggering_actor='JSMJapan',
        installer_provenance_sha256='3' * 64, observed_from=102, observed_until=106,
        before=generation, after=generation,
    )


class WiringTests(unittest.TestCase):
    def test_runner_accepts_only_approved_owner_workflow(self):
        env = dict(wiring.FIXED_RUNNER, GITHUB_SHA=RUN.workflow_sha, GITHUB_WORKFLOW_SHA=RUN.workflow_sha,
                   GITHUB_RUN_ID=RUN.run_id, DEPLOY_SHA=RUN.requested_site_sha)
        self.assertEqual(wiring.runner_context(env, RUN.workflow_sha), RUN)
        for key in ('GITHUB_ACTOR', 'GITHUB_WORKFLOW_REF', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB'):
            with self.assertRaises(wiring.WiringRefused):
                wiring.runner_context(dict(env, **{key:'different'}), RUN.workflow_sha)
        with self.assertRaises(wiring.WiringRefused):
            wiring.runner_context(env, 'f' * 40)

    def test_independently_expected_request_ties_exact_sha_nonce_and_window(self):
        raw = wiring.request_frame(WINDOW)
        wiring.require_request(raw, WINDOW, RUN.requested_site_sha, 112)
        with self.assertRaises(wiring.WiringRefused):
            wiring.require_request(raw, WINDOW, '9' * 40, 112)
        with self.assertRaises(wiring.WiringRefused):
            wiring.require_request(raw, replace(WINDOW, nonce='b' * 64), RUN.requested_site_sha, 112)
        with self.assertRaises(wiring.WiringRefused):
            wiring.require_request(raw, WINDOW, RUN.requested_site_sha, 131)
        with self.assertRaises(wiring.WiringRefused):
            wiring.require_request(raw+b'\n', WINDOW, RUN.requested_site_sha, 112)

    def test_output_authentication_and_replay_protection(self):
        payload = report()
        encoded = wiring.receipt_frame(WINDOW, payload, 110)
        self.assertEqual(wiring.read_receipt(encoded, WINDOW, 112), payload)
        self.assertNotIn(WINDOW.nonce.encode(), encoded)
        with self.assertRaises(wiring.WiringRefused):
            wiring.read_receipt(encoded, replace(WINDOW, nonce='b' * 64), 112)
        with self.assertRaises(wiring.WiringRefused):
            wiring.read_receipt(encoded, replace(WINDOW, run=replace(RUN, run_id='12346')), 112)
        with self.assertRaises(wiring.WiringRefused):
            wiring.read_receipt(encoded, WINDOW, 109)
        with self.assertRaises(wiring.WiringRefused):
            wiring.read_receipt(encoded+encoded, WINDOW, 112)
        value = json.loads(encoded)
        value['report'] = 'YWJj'
        with self.assertRaises(wiring.WiringRefused):
            wiring.read_receipt(wiring.canonical(value), WINDOW, 112)
        with self.assertRaises(wiring.WiringRefused):
            wiring.receipt_frame(WINDOW, report(replace(WINDOW, run=replace(RUN, run_id='12346'))), 110)
        self.assertIsNone(wiring.read_receipt(wiring.receipt_frame(WINDOW, None, 110), WINDOW, 112))

    def test_bounded_stdin_rejects_incomplete_or_oversized_frames(self):
        raw = wiring.request_frame(WINDOW)
        for data in (b'', raw, raw+b'\n', b'x' * (wiring.INPUT_LIMIT+1)):
            with self.subTest(size=len(data)):
                with tempfile.TemporaryFile() as stream:
                    stream.write(data)
                    stream.seek(0)
                    if data not in (b'', raw):
                        with self.assertRaises(wiring.WiringRefused):
                            wiring.read_request_fd(stream.fileno(), time.monotonic()+1)
                    else:
                        self.assertEqual(wiring.read_request_fd(stream.fileno(), time.monotonic()+1), data or None)
        reader, writer = os.pipe()
        try:
            with self.assertRaises(wiring.WiringRefused):
                wiring.read_request_fd(reader, time.monotonic()+.01)
        finally:
            os.close(reader)
            os.close(writer)

    def test_report_entry_checks_authority_and_holds_the_generation_guard(self):
        called = []

        @contextmanager
        def release_guard(sha):
            self.assertEqual(sha, RUN.requested_site_sha)
            called.append('lock')
            try:
                yield
            finally:
                called.append('unlock')

        def observe(window):
            self.assertEqual(window, WINDOW)
            self.assertEqual(called, ['lock'])
            called.append('observe')
            return report(window)

        def invoke(data, expected_window):
            with tempfile.TemporaryFile() as fd:
                fd.write(data)
                fd.seek(0)
                return wiring.publisher_entry(fd.fileno(), RUN.requested_site_sha, time.monotonic()+1,
                    expected_window=expected_window, release_guard=release_guard, observe=observe, epoch=lambda:112)

        with self.assertRaises(wiring.WiringRefused):
            invoke(b'', WINDOW)
        with self.assertRaises(wiring.WiringRefused):
            invoke(wiring.request_frame(WINDOW), replace(WINDOW, nonce='b'*64))
        self.assertEqual(called, [])
        code, receipt = invoke(wiring.request_frame(WINDOW), WINDOW)
        self.assertEqual(code, 0)
        self.assertEqual(wiring.read_receipt(receipt, WINDOW, 112), report())
        self.assertEqual(called, ['lock','observe','unlock'])

    def test_installer_splice_preserves_exact_legacy_body(self):
        fixture = b'#!/usr/bin/env bash\nset -euo pipefail\nprintf "%s\\n" fixture-deploy\n'
        digest = wiring.sha256(fixture).hexdigest()
        with patch.object(wiring, 'ORIGINAL_SHA256', digest), patch.object(wiring, 'ORIGINAL_SIZE', len(fixture)):
            revised = wiring.splice_installer(fixture)
            self.assertEqual(wiring.unsplice_installer(revised), fixture)
            self.assertEqual(subprocess.run(['/bin/bash','-n'],input=revised).returncode,0)
            with self.assertRaises(wiring.WiringRefused):
                wiring.splice_installer(fixture+b'\n')
            with self.assertRaises(wiring.WiringRefused):
                wiring.unsplice_installer(revised+b'\n')
            # This replaces only the fixed command in a local fixture.
            # No server entry point or application code runs.
            for status in (0,65,78,124,127):
                script = revised.replace(wiring.GATE_COMMAND, ('/bin/bash -c "exit '+str(status)+'" --').encode(),1)
                legacy = subprocess.run(['/bin/bash','-s','--',RUN.requested_site_sha], input=script, capture_output=True)
                self.assertEqual(legacy.stdout,b'fixture-deploy\n')
                self.assertEqual(legacy.returncode,0)
                remote = subprocess.run(['/bin/bash','-s','--','jsm-test-db-report-v1:'+RUN.requested_site_sha],
                                        input=script,capture_output=True)
                self.assertEqual(remote.stdout,b'')
                self.assertEqual(remote.returncode,status)


    def test_wrapper_routes_only_the_exact_report_command(self):
        fixture = b'#!/bin/bash\nprintf "legacy:%s\\n" "$SSH_ORIGINAL_COMMAND"\n'
        digest = wiring.sha256(fixture).hexdigest()
        with patch.object(wiring, 'WRAPPER_SHA256', digest), patch.object(wiring, 'WRAPPER_SIZE', len(fixture)):
            revised = wiring.splice_wrapper(fixture)
            self.assertEqual(wiring.unsplice_wrapper(revised),fixture)
            program = revised.replace(wiring.WRAPPER_COMMAND,b"printf 'report:%s\\n'",1)
            def run(command):
                return subprocess.run(['/bin/bash'],input=program,env={'SSH_ORIGINAL_COMMAND':command},capture_output=True)
            self.assertEqual(run(RUN.requested_site_sha).stdout,f'legacy:{RUN.requested_site_sha}\n'.encode())
            self.assertEqual(run('jsm-test-db-report-v1 '+RUN.requested_site_sha).stdout,
                             f'report:{RUN.requested_site_sha}\n'.encode())
            self.assertTrue(run('jsm-test-db-report-v1 '+RUN.requested_site_sha+';').stdout.startswith(b'legacy:'))

    def test_guard_rejects_wrong_digest_before_sudo(self):
        @contextmanager
        def trusted_fixture(path, **_kw):
            yield -1, lambda: None
        with patch.object(sys, 'argv', ['guard',RUN.requested_site_sha]), \
                patch.object(guard, 'open_trusted_file', trusted_fixture), \
                patch.object(guard.fcntl, 'flock'), patch.object(guard, 'fingerprint',return_value='0'*64), \
                patch.object(guard.subprocess, 'run') as sudo:
            self.assertEqual(guard.main(),65)
            sudo.assert_not_called()

    def test_guard_never_reads_more_than_one_byte_past_expected(self):
        with tempfile.TemporaryFile() as file:
            file.write(b'abcdefgh')
            file.seek(0)
            with self.assertRaises(guard.GuardRefused):
                guard.fingerprint(file.fileno(),4)
            self.assertEqual(file.tell(),5)

    @unittest.skipUnless(hasattr(os,'O_PATH'), 'Linux descriptor anchors')
    def test_guard_refuses_symlinks_and_path_replacements(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(guard, 'trusted', return_value=True):
            path = Path(folder) / 'test-installer'
            path.write_bytes(b'abc')
            with self.assertRaises(guard.GuardRefused):
                with guard.open_trusted_file(str(path), size=3):
                    path.rename(path.with_name('renamed'))
                    path.symlink_to('renamed')
            with self.assertRaises(guard.GuardRefused):
                with guard.open_trusted_file(str(path), size=3):
                    self.fail('did not refuse a symlink')
