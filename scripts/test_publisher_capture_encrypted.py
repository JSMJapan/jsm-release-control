#!/usr/bin/env python3
"""#2760: one historical TEST publisher wrapper, encrypted before transport."""

from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_installer_capture_encrypted as capture
from test_publisher_capture_capsule import STATUSES, VERSION, has_wrapper_length, render

WORKFLOW = 'test-publisher-capture-encrypted.yml'
CERTIFICATE = Path(__file__).with_name('test_publisher_recipient.pem')
RECIPIENT_SHA256 = '912c7635077e30369028481315b102188279dfc00861d53afb17559eaa9aa7a3'
FILENAME = 'jsm-test-publisher-2760.cms.der'
SOURCE = 'jsm-sandbox-publish'


def context_ready(env):
    capture.context_ready(env, workflow=WORKFLOW, recipient_sha256=RECIPIENT_SHA256)


def project_remote(raw, nonce, pem):
    status, ciphertext = capture.project_remote(raw, nonce, pem, version=VERSION, statuses=STATUSES)
    if status == 'CAPTURED':
        capture.need(has_wrapper_length(ciphertext), 'CAPTURE_RECEIPT_REJECTED')
    return status, ciphertext


def collect(api, env):
    deadline = time.monotonic() + capture.OVERALL_SECONDS
    context_ready(env)
    capture.verify_policy(api)
    pem = capture.recipient(certificate=CERTIFICATE, recipient_sha256=RECIPIENT_SHA256)
    raw, nonce = capture._receive(env, deadline, lambda challenge: render(challenge, pem, RECIPIENT_SHA256))
    status, ciphertext = project_remote(raw, nonce, pem)
    capture.need(status == 'CAPTURED', status)
    return ciphertext


def main():
    return capture._run_capture(
        context_ready, collect, source=SOURCE, version='jsm-test-publisher-capture-2760-v1',
        filename=FILENAME, recipient_sha256=RECIPIENT_SHA256,
        refusals=capture.REFUSALS | {'HISTORICAL_DIGEST_MISMATCH'},
    )


if __name__ == '__main__':
    raise SystemExit(main())
