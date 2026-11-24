#!/bin/sh
# TEST-only provisioning installs this wrapper and an exact sudo command, never a shell key.
set -eu
[ "${SSH_ORIGINAL_COMMAND-}" = 'jsm-eva-test-1620-v1' ] || exit 64
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C /usr/bin/sudo -n     /usr/bin/python3 -I -B -S /usr/local/libexec/jsm-eva-test-1620/eva_test_receiver.py serve
