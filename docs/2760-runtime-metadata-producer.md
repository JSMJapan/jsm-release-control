# TEST runtime metadata producer — preparation

Existing task [#2760](https://github.com/JSMJapan/jsm-storefront/issues/2760).
Base f1f9a0733468d6aede10c6c08cfdfa71d8493bed includes the reused PHP-manifest
reader. Destination remains TEST jsm-sandbox, GCE dark-berm-508215-d2 /
asia-northeast1-a /150919059249400713, develop.jsmjapan.com.

This first source slice implements the bounded, nonce-authenticated private
Python/PHP dialogue. It is not yet an operational producer or a DB proof.
It opens no FPM/DB/site connection, installs no file and changes no protection.
The completed same-task producer must bracket native PDO opening with root
local-listener and actual peer proofs, then permit one fixed metadata SELECT.
Application tables, controllers, sessions and business actions are excluded.

Context must originate in the protected private storefront publisher, not a
control workflow relabelled as that publisher. The existing PR29 scope remains
unchanged. Type checks and the dialogue digest do not authenticate GitHub.
The nonce is not sent in protocol frames; ROOT authenticates first. Frames have
role, sequence and context binding, strict canonical JSON and a4KiB limit.
The absolute3s caller deadline and0.75s per-I/O cap are not refreshed by reads.
Only fixed stages are accepted; malformed/replayed/cross-role frames refuse.

Tests use local socketpair and synthetic frames. PHP syntax/codec tests require
native PHP on Linux CI; local macOS without PHP reports an explicit skip.
Remaining same-task source work: FPM invocation, startup/config shape guards,
native-PDO pause, kernel/cgroup MySQL witness, full coordinator and closed
metadata projection. Installer wiring is coordinated with its separate author.
No manual workflow, TEST call, merge or installation is authorized by this file.
