# 21.11.2026 — positive systemd socket binding before the same GET, child v5

**SOURCE CANDIDATE / RUNTIME NOT_RUN / DB ADMISSION BLOCKED.**
[Approved plan7061948273](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7061948273),
[owner CODE READY7061957410](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7061957410).
Base control main `dc0557240759e8b98f9129e7f9cf7b7308c7b355`; only the existing
GCE TEST jsm-sandbox/develop.jsmjapan.com target. Actual prior PEER_REFUSED/GET0
proves neither its UID/PID cause nor socket activation. No new runtime occurred.

The existing protected entry requests child v5. Pure v2/detailed v3/discovery v4
remain supported; the new code-owned `binding=False` default preserves the
exact-MainPID gate. v5 adds closed `docker_binding` diagnostics and requests
`binding=True`. The outer DB scope receipt and terminal SQL BLOCKED are unchanged.

## One connection, not a fallback/retry

The same existing `_docker_begin` performs exactly one fixed socket connection
and one peer credential read. On that connected fd, default v4 requires root
peer/exact typed Docker MainPID as before. In v5, the same direct case requires
no new association query. Only an observed root peer PID1 may enter a new positive
association branch. Other UID/PID, invalid credentials or unavailable facts do
not send GET. There is no reconnect, retry, CLI, TCP or PID1-only acceptance.

Before the fixed existing GET, the new branch requires all of:

- loaded/active docker.socket, SubState=listening, Accept=no, exactly one
  `/run/docker.sock (Stream)` and Triggers=docker.service; reciprocal loaded/
  active/running docker.service with TriggeredBy=docker.socket. One fixed query
  shape Id/LoadState/ActiveState/SubState/Accept/Listen/Triggers/TriggeredBy uses
  the existing bounded systemctl transport. No unit file, ExecStart or Env read.
- Fixed PID1 executable exactly `/lib/systemd/systemd` or
  `/usr/lib/systemd/systemd`, and typed Docker MainPID executable exactly
  `/usr/bin/dockerd`. Other native paths/layouts remain UNKNOWN. No executable
  is run. Starttime/exe and net/mnt/PID namespace identities must be stable and
  match the observer's namespaces; no namespace enter or guard exception.
- One valid AF_UNIX STREAM LISTEN row for the fixed path. Protocol must be zero;
  duplicate/malformed target rows refuse. Legitimate connected rows with the
  same path are not duplicate LISTENs. Old PHP/MySQL Unix parser is unchanged.
- The LISTEN **kernel socket inode** must belong to bounded FD sets of both
  PID1 and the typed Docker MainPID. It is never compared with filesystem inode.
  Each role retains stable identity around its scan; both retain the same
  listener capability before/after. Unrelated FD churn is permitted. Existing
 128FD/process and64KiB/proc caps remain. No other processes/config/argv/env or
  file/volume contents are scanned.
- Existing root/no-follow filesystem socket guards and stamps, together with
  unit/process/namespace/listener identities, remain stable. Same connected fd
  performs the same single GET `/containers/json?all=1&size=0&limit=9` only after
  prechecks pass; postchecks compare against that private captured proof.

The activation branch carries its original absolute until=min(rootdeadline,
start+.75s) through the posthook. It never resets the deadline after proof/GET.
The direct/default path retains its prior rootdeadline finish semantics.
Existing total child3s/root4s/outer5s, systemctl0.7s/4096B, header8KiB/body64KiB,
8containers/9sentinel, output and SSH bounds remain unchanged. If proof cannot
finish within these bounds, return UNKNOWN rather than widen them.

## Honest phases and closed output

The public binding packet contains only fixed mode/state/peer-kind/reason enums
and boolean/null precondition axes. No raw PID, UID, executable/ns/FD links,
listener inode, unit text, paths or API summary are published or saved. Axes
record pre-GET observations; combined namespaces are true only after both roles
are validated. Before_proved is set only after the final pre-GET socket guard.
After_stable is unset when no postcheck ran. SKIPPED means the association was
not entered; UNKNOWN is a refused/incomplete proof; PROVED requires stable end
checks. Container projection requires PROVED. Binding and HTTP parsing facts
are independent: a proven association can still receive refused HTTP data.

Any ambiguity before GET preserves attempted=false/GET0. Drift or deadline
**after** GET discards containers and preserves attempted=true/UNKNOWN; it
cannot retroactively promise zero GET. A late successful old Unix stage cannot
repair an earlier refused snapshot; the new proof uses its own bounded samples,
without retry. These are sampled checks, not atomic or exclusive-handler proof.
No observed identity becomes a trusted DB baseline. DB identity, API→DB,
grants/provenance/isolation remain NOT_ESTABLISHED; SQL is never attempted.

Offline tests cover fixed reciprocity, unknown peer axes, protocol/duplicate
LISTENs, exe/ns/FD refusal, pre/post drift,128FD guards inherited from the reused
reader, absolute deadline and unrelated FD churn; actual one-connect/one-GET
behavior, strict projection, v5 and old routes, null-port privacy regressions.
The Linux-only inherited-listener fixture exercises native peer creator PID,
shared kernel FD and AF_UNIX wire. Root UID/fixed role PID/exe/ns/unit metadata
are explicit synthetic mappings, not host PID1/root or TEST acceptance. It
SKIPs on Mac and requires Linux CI. No real daemon/server/SQL/provider calls.

One focused adjacent binding module reuses existing OS/path/socket/HTTP/root
transport helpers. Only a fourth fixed systemctl query shape and v5 dispatch/
closed projection were added; policy, keys, environments, workflow jobs/inputs/
action pins and old namespace barriers stay unchanged. Two new source/test
paths were added to both existing offline CI filters. Exact preservation audit,
file sizes, frozen SHA, full tests/CI and root+B reviews belong in PR20.

Merge and one actual run require a new exact owner decision after two non-author
SOURCE PASS and exact CI. This CODE READY does not authorize either. Source
rollback is a normal revert; root alone maintains the issue/release journal.

# 21.11.2026 — bounded passive Docker discovery, child v4

**SOURCE CANDIDATE / RUNTIME NOT_RUN / DB ADMISSION BLOCKED.**
[Approved plan7061532578](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7061532578),
[owner CODE READY7061596354](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7061596354).
Base control main `256c539cabaa6a58ea6facb258aa5cc0bf37e31e`; only GCE TEST
`dark-berm-508215-d2 / asia-northeast1-a / jsm-sandbox / 150919059249400713`,
configured develop.jsmjapan.com /34.104.157.63:22. These are existing configured
pins, not new provider identity or installed application evidence.

The same protected profile now requests child v4; pure default v2 and detailed
v3 observer/projection routes remain available and unchanged in meaning. v4
adds only `docker_discovery`; its existing 22 OS stages and SQL terminal barrier
remain. No new workflow, inputs, permissions, credentials or environment.

- One fixed AF_UNIX connection to `/run/docker.sock` and exactly one
  `GET /containers/json?all=1&size=0&limit=9` (HTTP/1.0, Connection: close).
  No TCP, Docker CLI/context/auth configuration, version negotiation, retries,
  fallback endpoints, inspect, logs or container execution.
- Existing no-follow parent traversal/stamp/typed systemd readers are reused.
  Parents must be root-owned directories without group/world write; leaf must
  be a root-owned Unix socket without world write (normal root:docker0660 is
  supported). Parent/leaf symlinks or changed socket metadata refuse the read.
- Before GET, Linux SO_PEERCRED uid must be0 and peer PID must equal the typed
  active Docker MainPID from the already authorized fixed unit lookup. Docker
  unit metadata and socket stamps are compared again at the end. Observations
  are sampled, not atomic. No process/env/argv/FD scan of container or Docker
  PIDs is added. A systemd/inherited listener may report PID1 or its creator;
  that layout deliberately returns UNKNOWN/PEER_REFUSED, even with uid0. No
  PID1 fallback, new rights or namespace admission exception exists.
- One absolute0.75s request deadline (including path/connect/peer/HTTP work),
  header≤8192B, body≤65536B. Existing total child3s/root timeout4s/outer5s,
  SSH≤15s/output16384B and root output12288B stay unchanged. Extra observations
  can exhaust the old budget: PARTIAL/DEADLINE is honest, never an empty PASS.
  Only bounded200 JSON is accepted. Chunked/transfer-encoding, redirects,
  duplicate/folded headers, conflicting lengths, truncation, duplicate JSON
  keys/IDs or malformed response shapes refuse. No raw error is forwarded.
- Up to8 typed container IDs, immutable ImageIDs and reference-family enums
  mysql/mariadb/other/unknown; TCP3306 exposed/published and loopback/nonloopback
  booleans only. Published means container TCP3306 is mapped to any host port;
  raw IP/port/name/tag values are not emitted. Image family describes only the
  summary reference, not a verified image binary or DB service. Missing or
  unsupported image/port facts remain null/unknown and INCOMPLETE. A ninth
  entry is LIMIT_EXCEEDED/INCOMPLETE, never evidence of zero containers.
- Summary Command/Labels/Mounts/Names and references may arrive in capped
  private parser memory; they are discarded without report extraction,
  serialization, logs or files. No inspect/Env/Args/health logs/configuration,
  DB credentials, volume contents, SQL, Yii/application/provider requests,
  installations, lifecycle changes or server writes are implemented.

`docker_discovery` has a closed state/attempted/error/containers schema. Its
attempt flag is set immediately before sendall (including partial/failed sends).
A changed daemon/socket invalidates results, including the ninth-entry case.
OBSERVED means only this guarded metadata observation; observed IDs never become
an independent expected baseline. Whole installed source, effective API→DB,
DB identity/principals/grants, synthetic provenance and isolation remain
NOT_ESTABLISHED; outer receipt is always BLOCKED/exit1 and SQL NOT_ATTEMPTED.
Existing Apache/PHP namespace mismatch is not accepted or bypassed.

Offline checks exercise actual parser/connector/projection functions with
synthetic OS/socket fixtures: private canaries,8/9 limit, invalid types/ports,
peer refusal before GET, absolute slowloris deadline, path/daemon/socket drift,
framing limits and legacy v2/v3 behavior. Two Linux-only AF_UNIX fixtures check
real transport and inherited-listener creator PID semantics; root uid/path
positive metadata are synthetic doubles, not actual root/TEST acceptance.
They explicitly SKIP on macOS; Linux CI is separately required. No real Docker
socket, server, database or provider is contacted by the tests. Exact counts,
frozen SHA, CI and two independent non-author reviews belong in PR19.

Reuse search found no existing AF_UNIX Docker summary/peer reader. A focused
adjacent `scripts/test_db_docker_metadata.py` holds this responsibility, rather
than a new architecture or generic command/client API. Existing protected
transport, root wrapper, policy gates and operational workflow remain reused.
Only its two source/test paths were added to both existing offline CI filters;
coverage checks require all current scripts/tests to trigger CI.

Merge and a new one-shot require separate exact owner approval after two
non-author frozen-head PASS and CI. This source preparation authorizes neither.
Source rollback is a normal revert. Root alone maintains the issue/journal;
the old v1–v3 history below does not change the new runtime NOT_RUN status.

# 21.11.2026 — уточнение fixed TEST OS metadata, child v3
**SOURCE CANDIDATE / RUNTIME NOT_RUN / DB ADMISSION BLOCKED.** Продолжение
[плана7060941419](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7060941419),
[owner CODE READY7060980311](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7060980311).
Среда только GCE TEST `dark-berm-508215-d2 / asia-northeast1-a / jsm-sandbox`,
resource `150919059249400713`, develop.jsmjapan.com,34.104.157.63:22;
[управление](https://github.com/JSMJapan/jsm-release-control/settings/environments)
`test-api-readonly-access`. Это configured pins, не новый provider identity proof.

Новый dispatch формирует child `jsm-test-db-os-2760-v3`. Прежний v2 decoder,
его18stages/enum и default offline observer сохранены как compatibility branch.
Outer scope receipt по-прежнему v2, status BLOCKED/exit1, SQL NOT_ATTEMPTED;
OS facts не допускают БД. Никаких изменений в prod reader, общем CI, workflow,
host/key/owner/main/attempt1/environment, sudo wrapper и runtime version.

Добавлено ровно два fixed service metadata lookups — mariadb.service и
docker.service, только Id/LoadState/ActiveState/MainPID. Новый код не читает
proc/FD этих PID, не заменяет mysql role на MariaDB и не делает Docker API,
container inspect или process/container scan. MainPID остаётся внутренним
typed integer: выводятся только closed load/active states, pid_available и
совпадение metadata начала/конца. Docker active не означает DB container.

Только apache2.service/php7.4-fpm.service получают отдельный fixed show
Id/PrivateTmp/PrivateMounts/PrivateNetwork. Буквальные yes/no становятся
boolean, неизвестная/отсутствующая форма — null/UNKNOWN, без raw значений.
PrivateTmp=true не отменяет существующее сравнение net/mnt namespace и не
позволяет FD reading после mismatch. Три code-owned query shapes проверяются
до subprocess; произвольных units/properties/paths из args/env/input нет.

Child v3 добавляет два поля: additional_services (mariadb,docker) и
namespace_settings (apache,php), плюс4фиксированных stage records (22 total).
Чтение начала/конца не является atomic snapshot. stable=false/null и unknown
properties не превращаются в OBSERVED; extra/raw PID/setting/ошибки отказывают
на strict projection. Даже полный OS OBSERVED сохраняет все DB/API identity,
grants, synthetic provenance и isolation NOT_ESTABLISHED.

На прежних fixed socket/datadir/proc-Unix readers добавлены closed причины:
NOT_FOUND, PERMISSION_REFUSED, UNSAFE_LINK_OR_KIND, SIZE_LIMIT,
CHANGED_DURING_READ, PARSER_REFUSED. Существующие DEADLINE/OS_REFUSED и прочие
guard reasons сохраняются. Никаких raw exceptions/paths/config/credentials.
Malformed/duplicate matching Unix rows в v3 — parser refusal, а не доказанное
отсутствие listener. Прежний v2 parser contract не расширяется этими причинами.

Сохранены общий3с OS budget,0.7с/4096B на systemctl, root4с/outer5с,
SSH≤15с/16384B, overall60с и root output≤12288B. Дополнительные fixed reads
могут завершиться PARTIAL/DEADLINE, лимиты ради зелёного статуса не увеличены.
Не добавлены SQL, PHP/Yii, HTTP/provider calls, конфигурация/DB credentials,
datadir contents, seed/migrations или операции записи/установки/reload.

RED: отсутствующие approved parsers/reason helpers и v3 observer dispatch.
GREEN: actual observer с synthetic systemd/proc/filesystem fixtures, все22
stage failure branches, strict legacy-v2/v3 projection и terminal BLOCKED;
проверки родных FD/namespace/size/change guards не ослаблены. Точные команды,
итог последнего SHA, CI и два независимых review — в PR. Merge/новый один run
требуют отдельных точных допусков; CODE READY их не разрешает.

Возврат source — revert будущего control PR. Runtime не запускался, серверные
изменения не выполнялись. Root ведёт STATE и existing journal. Ниже сохранена
история прежних v1/v2 кандидатов и их исходных условий; её старые NOT_RUN
не являются новым runtime статусом уже выполненных запусков.

# #2760: фиксированный OS metadata observer TEST, цель БД ещё не допущена

Задача: [JSMJapan/jsm-storefront#2760](https://github.com/JSMJapan/jsm-storefront/issues/2760).
Подготовка кода разрешена [решением владельца](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7030574514). Это не разрешение запуска.
Основа: control main `0f32c5cba72acdc5e9b17579a7ce72b4438012f6`.

## План минимального source-only ремонта после one-shot

Основа ремонта `6f6a0efdcfea0e5b907b3f9978fc59f731ce1a99`,
[record7035066291](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7035066291).
One-shot44705731325 израсходован; этот план не разрешает новый runtime.

- [x] RED: synthetic namespace mismatch + refused Unix parser показывает
  skipped/attempted ambiguity; independent fixed socket/datadir metadata
  должны оставаться наблюдаемыми внутри прежнего3с budget.
- [x] Изменить только `test_db_os_metadata.py`, strict projection в
  `test_db_metadata_readonly.py` и их existing tests: fixed ordered stage IDs,
  attempted/completed booleans +closed error enums; separate already-read
  net/mnt booleans и validated load/active/pid_available. Versioned v2 schema,
  no raw errors/paths/PIDs, no new paths/properties/commands/credentials.
- [x] GREEN/adversarial: отказы всех18 fixed stages не дают fake complete, deadline
  не допускает новых syscall после budget; namespace mismatch не допускается
  для FD ownership. Старый installed-route payload invariant, original
  transport/complete/SQL admission guards остаются проверены existing tests.
- [ ] Normal push/draft PR, exact-head two non-author reviews +offline CI.
  Отдельный будущий owner run approval остаётся обязательным.

v1 one-shot44705731325 дал SSH/root OBSERVED, Apache/PHP exe match +combined
namespace mismatch, остальные metadata UNKNOWN; global early refusal не
различал skipped и attempted. v2 добавляет18 фиксированных stage records:
`attempted/completed` — boolean, `error` — закрытый enum без raw exception.
Attempt означает вход в прежний фиксированный probe, не успешное чтение.
`completed=false`/UNKNOWN не означают отсутствия сервиса/сокета/каталога.
`net_namespace_matches` и `mount_namespace_matches` лишь разделяют уже
прочитанное сравнение; combined namespace acceptance не меняется.
Validated unit load/active/pid_available не содержат raw PID или unit config.
Отказ Unix read/parser не блокирует независимые уже разрешённые filesystem
socket/datadir metadata, пока не истёк прежний budget. Связь listener/FD при
неизвестном Unix snapshot или namespace mismatch не утверждается.
Первый repair chunk:176 local tests,173 PASS+3 SKIP. Frozen repair:179 local
tests,176 PASS+3 SKIP; все18 actual-observer stage refusal packets проходят
strict v2 projection как PARTIAL. Проверены full/namespace-partial packet и
противоречие attempted=true/error=NOT_ATTEMPTED (отклоняется).
Новый v2 runtime NOT_RUN; exact frozen CI и два non-author reviews ещё gates.
`pid_available` означает только валидный positive MainPID, не service health.
`STABILITY_NOT_CONFIRMED` не утверждает изменение процесса/объекта;
`DEADLINE` различается attempted flag до/после входа в probe. Отсутствующий
dependency не выдаётся за наблюдённое изменение filesystem/listener.

**SCOPE PREPARED / DB PROOF BLOCKED_TARGET_ADMISSION / SQL_NOT_ATTEMPTED.**
Кандидат содержит фиксированное OS-наблюдение: три фиксированных
systemd MainPID, ожидаемые exe/net/mnt namespaces, bounded FD/socket relationships
и metadata фиксированного `/var/lib/mysql`/covering mount. Данные берутся только
из OS metadata, без SQL/конфигурации/учётных данных/содержимого datadir.
Существующий защищённый GitHub/key-only транспорт переносит этот capsule без
установки файлов на TEST. Это подготовка phase1 OS evidence, не готовая
диагностика БД и не разрешение запуска. v1 one-shot PARTIAL описан выше;
новая v2 observation ещё NOT_RUN.

Это намеренно не SQL-runner. Нет текущего независимого доверенного baseline,
который разрешал бы подключение. Код не принимает runtime baseline, DSN, пути,
команды или SQL из argument/env/HTTP. Он проверяет существующую публичную
GitHub policy, затем проверяет прежний host pin и только после этого использует
protected SSH key для OS-наблюдения. Закрытый receipt всегда BLOCKED/exit1:
даже OS OBSERVED не допускает SQL. PHP/Yii, конфигурация приложения, DB
credentials и подключения к БД отсутствуют. OS audit/SSH/sudo bookkeeping и
доступы к metadata могут оставить обычные OS записи.

## Цель и существующий канал

- TEST: `develop.jsmjapan.com`, Google Cloud project `dark-berm-508215-d2`,
  VM `jsm-sandbox`, resource `gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713`,
  ожидаемый транспорт `34.104.157.63:22`. Это целевые pins, не наблюдение текущей VM.
- [Управление VM](https://console.cloud.google.com/compute/instancesDetail/zones/asia-northeast1-a/instances/jsm-sandbox?project=dark-berm-508215-d2).
- GitHub environment `test-api-readonly-access`: прежний owner reviewer,
  main-only branch policy, first attempt, запрет admin bypass. Код повторно
  проверяет ровно три публичных policy GET через существующий `TestPolicyApi`
  и неизменённый `policy_ready`, включая ID владельца `327623967`.
- Новый manual workflow `test-db-metadata-readonly.yml` не имеет inputs.
  Он использует прежнее protected environment и существующий
  `TEST_API_ADMIN_SSH_KEY`/`TEST_API_KNOWN_HOSTS`, без новых credentials/прав.
  Existing SSH key-only options, pin, временные0700/0600 private files и лимиты
  сохранены. Общий sudo wrapper выделен в `wrap_root_program`: generated bytes
  прежнего installed-route capsule проверены на неизменность.
- Общий deadline60с; SSH timeout≤15с/output≤16384B, outer deadline5с,
  root timeout4с/own deadline3с/output≤12288B. Cleanup убивает process group.
  Фиксированный typed receipt, strict JSON без duplicate/nonfinite/extra fields.
  Никаких raw exceptions,
  DSN, grants, customer data или содержимого файлов в stdout/artifacts.

## Точная граница phase1 OS evidence

- Только `apache2.service`, `php7.4-fpm.service`, `mysql.service`; systemctl
  whitelist `Id/LoadState/ActiveState/MainPID`, ≤4096B. MainPID — typed positive
  integer, inactive/zero/custom/missing не заменяются scan/alternate process.
- Только ожидаемые exe `/usr/sbin/apache2`, `/usr/sbin/php-fpm7.4`,
  `/usr/sbin/mysqld`; net/mnt namespace equality относительно observer.
  `/proc/PID/stat` field22 защищает от PID reuse. `/proc/PID/fd` ≤128 numeric
  entries: readlink privately удерживает только kernel socket inode numbers.
  Никаких proc environ/cmdline, process args, PHP config или socket connection.
- Только `/run/php/php7.4-fpm.sock` и `/run/mysqld/mysqld.sock`:
  bounded `/proc/observerPID/net/unix` ≤64KiB связывает listening stream path
  с kernel inode, затем FD выбранного MainPID. Filesystem socket inode не
  сравнивается с kernel inode. Наличие listener не доказывает API route.
- Только nofollow directory metadata `/var/lib/mysql` и covering mount из
  bounded observer mountinfo ≤64KiB. Нет listing/contents/DB files. Directory
  symlink → UNKNOWN; block filesystem/device match не доказывает, что mysqld
  использует этот datadir или что это ожидаемый TEST disk. Mount/FD private
  paths не публикуются, даже в виде hashes.
- Начало/конец перепроверяют units/PID/start/exe/namespaces/listener/FD relation,
  socket/dir identity и mount snapshot. Это ограниченное неатомарное
  наблюдение, не гарантия непрерывности. Неподдерживаемая Docker/custom layout,
  изменение, отказ/oversize/deadline → PARTIAL/UNKNOWN, без альтернативного
  discovery, подключения, конфигурации или SQL.

Публично выводятся только фиксированные role enums, boolean/null и закрытые
states. Raw PID/starttime/exe/ns/FD/socket/mount strings/private hashes не
выходят из root capsule. Даже полный OS OBSERVED сохраняет
`effective_api_binding/test_disk_identity/db_target_identity/db_grants/`
`db_data_provenance/db_isolation/egress_isolation=NOT_ESTABLISHED`,
`sql=NOT_ATTEMPTED`, `db_proof=BLOCKED_TARGET_ADMISSION`.

Phase receipt различает `ssh=NOT_ATTEMPTED` до вызова транспорта,
`ATTEMPTED_NOT_CONFIRMED` при его ошибке/timeout/malformed output и `OBSERVED`
только после strict outer principal/nonce validation. Internal phase state
сохраняется при SIGALRM; ошибка не стирает уже проверенную protection policy.

## Какие доказательства нужны до отдельной SQL-реализации

Ни одно поле ниже сейчас не заполнено и не принято кодом. Это контракт для
следующего отдельно проверенного admission, а не произвольный вход профиля.
Доверенный record должен иметь независимый источник, привязку к exact SHA и
зафиксированное решение владельца; значения, взятые из проверяемого config,
не становятся эталоном для того же config.

| Record | Обязательные связи и проверка |
| --- | --- |
| Authority | Existing GitHub repository/path или artifact ID; producer workflow/run/attempt и control SHA; SHA256 оригинального receipt; review IDs; owner comment/approval, прямо допускающий этот target и scope. Подпись/attestation — только существующего проверенного механизма с установленным trust anchor. Отсутствующую подпись или доверие нельзя заменить полем `approved:true`. |
| Target identity | Та же фиксированная VM/host pin; independently approved MySQL server identity и ожидаемое transport binding. `localhost`, socket path или `jsm_sandbox` без доказательства daemon/namespace/forwarding boundary недостаточны. Проверяемый DSN не может сам сформировать expected target. |
| Effective API binding | Exact installed source/runtime/build fingerprints; активный `/api` vhost/include graph, PHP entry/FPM binding и effective override chain; конфигурация, реально выбранная этим API. sites-available, current.json, строка Alias, source hash и file literal не доказывают loaded binding. Неразрешённый Include/conditional/rewrite/handler/FPM environment/`.user.ini`/auto_prepend/динамический PHP → STOP, без SQL. |
| Principals/grants | Диагностический principal отдельно от application principal; независимо утверждённая область прав для нужной TEST БД и способ metadata-only исполнения без создания/расширения grant. Raw grants/auth hashes/DSN/passwords остаются приватными и не включаются в receipt. Признаки production-доступа или неоднозначность → STOP. |
| Synthetic provenance | Fresh loader/admission receipt: exact synthetic schema/fixture hashes, release ID, привязка к той же DB server/database identity и результат загрузки из доверенного producer. Название базы, пустая выборка, schema или counts не доказывают synthetic origin. Этот профиль не создаёт loader, БД, пользователей или seed. |
| Isolation/egress | Проверяемые permissions/network/namespace bindings и установленный trust baseline, ограничивающие production и внешние побочные эффекты. Отсутствие алармов и health200 не доказательство. |

Без effective API binding нельзя обещать, что отдельное PDO-подключение
проверяет именно БД обслуживаемого API. Не запускать Yii bootstrap/autoload или
business actions, чтобы обойти этот пробел. Reference `api/web/index.php`
содержит `LEGACY_REFERENCE_ONLY`; runtime entry/config отдельно не допущены.

## Где искать существующий baseline и чего эти ссылки не доказывают

1. [ENV-01 #2](https://github.com/JSMJapan/jsm-storefront/issues/2),
   runtime history [#31](https://github.com/JSMJapan/jsm-storefront/issues/31)
   / [#33](https://github.com/JSMJapan/jsm-storefront/pull/33): искать конкретный
   trusted build/start/loader receipt, а не текст «стенд работает».
2. [Tracker #1380](https://github.com/JSMJapan/jsm-storefront/issues/1380),
   история [#314](https://github.com/JSMJapan/jsm-storefront/issues/314) и
   [#136](https://github.com/JSMJapan/jsm-storefront/issues/136): исторические
   заявления не являются свежим DB identity/grants/provenance admission.
   #2760 — новая маленькая задача, не восстановление закрытых задач как READY.
3. [Synthetic data source](https://github.com/JSMJapan/jsm-storefront/tree/main/infra/sandbox/data)
   и runtime ENV-01 contract: фиксируют ожидаемые source/schema/fixtures,
   но не доказывают загрузку этой БД в текущую VM. Нужен execution receipt,
   связанный с тем же сервером и database identity.
4. [db-stand.yml](https://github.com/JSMJapan/jsm-storefront/blob/main/.github/workflows/db-stand.yml)
   — disposable MySQL5.7/8.0 внутри GitHub Actions. Это не `develop.jsmjapan.com`.
   Миграции up/down/up не входят в #2760 и этим профилем не запускаются.
5. [Existing static reader](https://github.com/JSMJapan/jsm-release-control/blob/0f32c5cba72acdc5e9b17579a7ce72b4438012f6/scripts/test_api_installed_route_readonly.py)
   возвращает DB identity/grants/provenance/isolation `NOT_ESTABLISHED` даже
   при полном OBSERVED. Literal DSN и его hash не повышаются до admission.
6. Найденные [исторический run38199198780](https://github.com/JSMJapan/jsm-storefront/actions/runs/38199198780)
   и [first GCE run37890318314](https://github.com/JSMJapan/jsm-storefront/actions/runs/37890318314)
   — только forced publisher, без artifacts и DB/loader/provision receipt.
   [#1021](https://github.com/JSMJapan/jsm-storefront/issues/1021) даёт VM/disk
   identity, не DB baseline; [#932](https://github.com/JSMJapan/jsm-storefront/issues/932)
   содержал seed FAIL/UNKNOWN. Они не разрешают SQL в phase1.

Если подходящий signed/attested current receipt не найден, записать точное
отсутствующее свидетельство. Не создавать вместо него dummy baseline,
не подключаться к production для сравнения и не расширять задачу до loader,
DB migration, нового пользователя или сетевых/permission изменений.

## Контракт будущего metadata-only чтения — НЕ реализован и НЕ разрешён

После отдельного source review/admission, exact CI и конкретного owner run
approval допустимый набор должен быть заново заморожен как один whitelist:

- служебные server/database/connection-principal/privilege-principal identity;
- только privately parsed grant metadata для утверждённой области прав;
- closed boolean/hash/status receipt с проверенной привязкой к ожидаемому
  target. Наблюдённый target не становится собственным эталоном;
- отказ при неподдерживаемой версии/конфигурации, неверной identity,
  отказе auth, timeout, неоднозначном/oversized/malformed ответе; без fallback;
- никаких application rows, `COUNT`, aggregates, table statistics, procedures,
  migrations, DDL/DML, grants, orders/payments/mail, provider/AI calls.

Конкретные SQL statements и DB driver намеренно не добавлены: без независимого
target/version/principal admission такой executor был бы фиктивным или опасным.
Сейчас нет SQL capability; native DB acceptance и все связанные поля остаются
NOT_ESTABLISHED. Synthetic provenance и egress требуют отдельных доказательств,
даже если будущая metadata identity когда-либо пройдёт.

## Проверка и дальнейший допуск

Baseline base0f32: 141 тест, 138 PASS +3 explicit SKIP на этом Mac:
2 private opt-ins и Linux-only O_NOATIME syscall proof. Новый полный локальный
run исходного phase1:170 тестов,167 PASS +те же3 SKIP. Actual v1 OS-only
one-shot выполнен отдельно; SQL/application/DB credentials не использовались.
Current v2 repair local:179 тестов,176 PASS +те же3 SKIP, новый runtime NOT_RUN.
Новые офлайн adversarial проверки ловят forged env baseline/SQL/DSN, actor/ref/
attempt/workflow drift, policy/owner/branch drift, private exception leakage и
продвижение неподтверждённых полей до DB proof. Проверены actual bounded reader
на synthetic local files: proc size0, oversize, symlink parent/leaf, invalidPID,
FD129/nonnumeric/denied/oversized target, directory no-list. Positive OS case,
PID/start/ns/FD/listener/fs/mount changes и protected key-only transport
проверены offline synthetic fixtures, без локальных SSH/SQL/server requests.

```bash
python3 -B -m unittest discover -s tests -p 'test_test_db_metadata_readonly.py'
python3 -B -m unittest discover -s tests -p 'test_test_db_os_metadata.py'
python3 -B -m unittest discover -s tests -p 'test_*.py'
```

Runtime manual job намеренно завершится BLOCKED/exit1, а не зелёным DB PASS.
Сейчас запуск не требуется и не разрешён. Два non-author frozen-head PASS,
exact CI и отдельное owner activation/run approval обязательны. Existing
environment approval также сохраняется. Отдельный будущий one-shot может
наблюсти новые OS facts; его BLOCKED DB status не означает неудачу metadata
transport и никогда не является DB PASS. Ни dispatch, ни merge этим source
решением не разрешены. Для SQL остаётся отдельный admission/implementation gate.

Возврат кода — revert этого control PR. Existing transports/environments/
credentials не меняются; DB rollback не требуется, записей нет. Root сохраняет
итог в #2760/#2738 и existing journal PR126 с прочтением сохранённой записи.
