# #2760: finite clean TEST controller — PREPARATION

Human-approved source preparation: [issue2760](https://github.com/JSMJapan/jsm-storefront/issues/2760). Target only GCE `jsm-sandbox / dark-berm-508215-d2 / asia-northeast1-a / VM150919059249400713`. Existing GitHub protected `test-api-readonly-access` and pinned key-only `marinagurina@34.104.157.63:22` route; no direct local SSH.

This is a separate candidate from unmerged/unselected PR35. Source baseline public control main77154. Reuse main authorization/host-pin/private-key-file primitives. Existing diagnostic4s/131071 limits and old installer/publisher remain unchanged.

First implemented slice verifies an independently authenticated private Actions ZIP digest, exact nine-member inventory, all internal SHA256, reviewed source0184/treeb43, native CI acceptance, build SHA and two image IDs. Internal acceptance/checksums are not a trust anchor. No private app/SQL/image payload is committed to this public repo; tests use unrelated synthetic bytes.

Implemented next slice: fixed authenticated GitHub run/job/native-step/artifact binding, one storage redirect without Authorization, native slow-header deadline fixture, Docker-save legacy/OCI envelope/config/layer-diffID validation without host extraction. Actual producer ZIP/Docker format remains NOT_TESTED until the successful private CI artifact exists.

Remaining in this same candidate: bounded new streaming write capsule; safe Docker-save envelope and image tag collision refusal; create only new synthetic-only DB/app objects in network:none plus the same exact netns; fixed resource limits and own-ID cleanup/2h TTL. No bridge, shared TEST DB, production/provider access, existing Telegram/messages or public ingress changes.

Proposed bounds: ZIP≤2GiB, decompressed Docker TAR≤6GiB, metadata32KiB, resources app+DB each768MiB/128PIDs/0.5CPU with memory-swap=memory and bounded logs; data tmpfs512MiB, app temp64MiB. Disk admission must use measured archive/layer size plus reserve, not a blind8GiB threshold. New finite stage timeout is separate from unchanged read-only profiles. Exact values and complete implementation require review before any run.

External gates before install: final reviewed private PR2780 build/run/artifact digest not yet pinned; public environment currently lacks the future minimal private storefront Actions:read credential; separate HTTPS QA origin/TLS/route is UNKNOWN. STAGED_LOCAL_ONLY will not mean phone QA or release-ready. No hostname is invented and shared develop origin is not redirected.

Status: DRAFT, first source slice only. No merge, manual workflow, VM, SQL, image loading or deployment performed. Root owns issue/journal and will coordinate final artifact pins, two independent whole-candidate reviews, exact CI, and a separate explicit owner install approval.

Implemented host slice (still no runtime admission): exclusively owned run-state/lock with closed metadata schema; timeout-aware stdin/stdout Docker pump; fixed create-by-image-ID DB/app with none/same-container netns, readback of resource/mount/network constraints before each new-schema SQL step; separate schema/seed and SELECT-only reader; local/private five-page+2real404 smoke; saved-intent cleanup for a lost create response, own-ID/tag-only removal and temporary two-hour systemd expiry timer. Tests exercise actual ZIP/TAR readers plus a simulated Engine and real local subprocesses. This is not a native Docker/VM test. Streaming protected delivery/workflow and final real artifact validation remain incomplete. No deployment is available yet.
