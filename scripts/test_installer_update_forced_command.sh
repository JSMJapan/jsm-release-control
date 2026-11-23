#!/bin/sh
# Installed root-owned on TEST by the scoped writer's provisioner.
set -eu

[ "${SSH_ORIGINAL_COMMAND-}" = 'jsm-test-installer-update-v1' ] || exit 64
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C /usr/bin/sudo -n \
  /usr/bin/python3 -I -B -S \
  /usr/local/libexec/jsm-test-installer-writer/test_installer_update_receiver.py \
  jsm-test-installer-update-v1
