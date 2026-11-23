"""Offline render/verify boundaries for the TEST installer evidence interface."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import test_db_installer_receipt as receipt


def canonical(data):
    return (json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def digest(data):
    return sha256(data).hexdigest()


class TestInstallerReceiptTests(unittest.TestCase):
    def setUp(self):
        self.active = receipt.ServingGeneration(installed_site_sha='2' * 40,
            apache_sha256='a' * 64, php_sha256='b' * 64, descriptor_sha256='d' * 64, db_target_sha256='e' * 64)
        self.options = dict(
            workflow_sha='1' * 40, requested_site_sha='2' * 40, run_id='45031411532',
            run_attempt=3, actor='release-runner', triggering_actor=None,
            installer_provenance_sha256='c' * 64, observed_from=1_790_000_000, observed_until=1_790_000_025,
            before=self.active, after=self.active)
        self.raw = receipt.render_installer_receipt(**self.options)
        self.now = 1_790_000_030
        self.pins = receipt.AuthenticatedPins(
            receipt_sha256=digest(self.raw), workflow_sha='1' * 40, requested_site_sha='2' * 40,
            run_id='45031411532', run_attempt=3, actor='release-runner', triggering_actor=None,
            observation_not_before=1_789_999_975, run_finished_at=1_790_000_027, verify_not_after=1_790_000_625,
            installer_provenance_sha256='c' * 64, current_generation=self.active,
            descriptor_sha256='d' * 64, db_target_sha256='e' * 64)

    def verify(self, raw=None, pins=None, now=None):
        return receipt.verify_installer_receipt(
            self.raw if raw is None else raw, pins=self.pins if pins is None else pins,
            now=self.now if now is None else now)

    def test_authenticated_configuration_receipt_still_does_not_establish_actual_peer_or_isolation(self):
        value = json.loads(self.raw)
        self.assertEqual(self.raw, canonical(value))
        self.assertEqual(value['scope'], dict(
            repository='JSMJapan/jsm-storefront', workflow='.github/workflows/sandbox-publish.yml',
            ref='refs/heads/main', event='workflow_dispatch', deployment_environment='sandbox', host='develop.jsmjapan.com', project='dark-berm-508215-d2',
            zone='asia-northeast1-a', vm_id='150919059249400713', vm_name='jsm-sandbox', environment='TEST'))
        result = self.verify()
        self.assertEqual(result, dict(status='VERIFIED_REPORT', reason='CONFIGURATION_VERIFIED',
            configuration_binding='VERIFIED', actual_db_peer='UNKNOWN',
            db_isolation='NOT_ESTABLISHED', db_admission='NOT_ESTABLISHED'))

    def test_missing_separately_authenticated_input_returns_blocked(self):
        for raw, pins in ((None, None), (None, self.pins), (self.raw, None), (self.raw, dict(approved=True))):
            with self.subTest(raw_present=raw is not None):
                result = receipt.verify_installer_receipt(raw, pins=pins, now=self.now)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertEqual(result['configuration_binding'], 'UNKNOWN')

    def test_exact_receipt_and_independently_pinned_identity_must_match(self):
        for pins in (dict(receipt_sha256='f' * 64), dict(requested_site_sha='3' * 40),
                dict(workflow_sha='3' * 40), dict(installer_provenance_sha256='f' * 64), dict(run_id='1234'),
                dict(descriptor_sha256='f' * 64), dict(db_target_sha256='f' * 64), dict(run_attempt=4),
                dict(actor='other-runner'), dict(triggering_actor='other-runner'),
                dict(current_generation=replace(self.active, php_sha256='f' * 64))):
            with self.subTest(field=next(iter(pins))):
                self.assertEqual(self.verify(pins=replace(self.pins, **pins))['status'], 'BLOCKED')

    def test_stale_future_or_changed_serving_generation_cannot_verify(self):
        for now in (True, self.options['observed_until'] - 1, self.pins.verify_not_after + 1):
            with self.subTest(now=now):
                self.assertEqual(self.verify(now=now)['status'], 'BLOCKED')
        with self.assertRaises(ValueError):
            receipt.render_installer_receipt(**dict(self.options, after=replace(self.active, php_sha256='b1' * 32)))
        with self.assertRaises(ValueError):
            receipt.render_installer_receipt(**dict(self.options, after=replace(self.active, descriptor_sha256='f' * 64)))
        with self.assertRaises(ValueError):
            receipt.render_installer_receipt(**dict(self.options, before=replace(self.active, installed_site_sha='3' * 40)))
        with self.assertRaises(ValueError):
            receipt.render_installer_receipt(**dict(self.options, observed_until=self.options['observed_from'] - 1))
        too_early = replace(self.pins, observation_not_before=self.options['observed_from'] + 1)
        too_late = replace(self.pins, run_finished_at=self.options['observed_until'] - 1)
        for pins in (too_early, too_late):
            self.assertEqual(self.verify(pins=pins)['status'], 'BLOCKED')

    def test_malformed_canonical_payload_with_matching_digest_fails_closed(self):
        changed_scope = json.loads(self.raw)
        wrong_attempt_type = json.loads(self.raw)
        wrong_host = json.loads(self.raw)
        wrong_kind = json.loads(self.raw)
        unexpected_field = json.loads(self.raw)
        changed_scope['scope']['workflow'] = 'another.yml'
        wrong_attempt_type['run']['attempt'] = True
        wrong_host['scope']['host'] = 'production.invalid'
        wrong_kind['binding']['path'] = '/admin'
        unexpected_field['binding']['PRIVATE'] = 'raw descriptor private canary'
        for raw in (canonical(changed_scope), canonical(wrong_attempt_type), canonical(wrong_host),
                canonical(wrong_kind), canonical(unexpected_field), self.raw + b' ',
                self.raw.replace(b'"version":', b'"version":"duplicate","version":'),
                b'[' * 4096, self.raw + b' ' * 4096):
            with self.subTest(size=len(raw)):
                result = self.verify(raw=raw, pins=replace(self.pins, receipt_sha256=digest(raw)))
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertNotIn('private canary', str(result))

    def test_exact_peer_proof_has_independent_pin_and_forwarding_requires_both_legs(self):
        for route in ('DIRECT', 'PROXY', 'DNAT'):
            with self.subTest(route=route):
                peer = receipt.PeerEvidence(route=route, php_leg_sha256='3' * 64, db_leg_sha256='4' * 64,
                    db_target_sha256='e' * 64, forwarding_sha256=None if route == 'DIRECT' else '5' * 64)
                raw = receipt.render_installer_receipt(**self.options, peer=peer)
                pins = replace(self.pins, receipt_sha256=digest(raw))
                self.assertEqual(self.verify(raw, pins)['actual_db_peer'], 'UNKNOWN')
                pin = digest(b'jsm-test-db-installer-peer-v1\x00' + raw)
                pins = replace(pins, peer_evidence_sha256=pin)
                result = self.verify(raw, pins)
                self.assertEqual(result['actual_db_peer'], 'VERIFIED')
                self.assertEqual(result['configuration_binding'], 'VERIFIED')
                self.assertEqual(result['db_isolation'], 'NOT_ESTABLISHED')
                self.assertEqual(result['db_admission'], 'NOT_ESTABLISHED')
                later = receipt.render_installer_receipt(**dict(self.options, run_attempt=4), peer=peer)
                later_pins = replace(pins, receipt_sha256=digest(later), run_attempt=4)
                self.assertEqual(self.verify(later, later_pins)['actual_db_peer'], 'UNKNOWN')
                with self.assertRaises(ValueError):
                    receipt.render_installer_receipt(**self.options, peer=replace(peer, db_leg_sha256=None))
                with self.assertRaises(ValueError):
                    receipt.render_installer_receipt(**self.options, peer=replace(peer, db_target_sha256='f' * 64))
                with self.assertRaises(ValueError):
                    receipt.render_installer_receipt(**self.options, peer=replace(peer,
                        forwarding_sha256='5' * 64 if route == 'DIRECT' else None))
