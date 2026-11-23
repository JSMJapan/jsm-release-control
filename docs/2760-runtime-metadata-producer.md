# #2760: configured-runtime metadata producer — PREPARATION

Назначение: TEST `develop.jsmjapan.com`, GCE `jsm-sandbox`, GitHub-only. Ветка подготовки не устанавливает и не запускает этот пакет. Задача: https://github.com/JSMJapan/jsm-storefront/issues/2760 . PR: https://github.com/JSMJapan/jsm-release-control/pull/35 .

## Реализованный путь

Root producer принимает контекст **аутентифицированного частного publisher**, использует существующий стабильный FPM snapshot и отправляет один локальный FastCGI request к фиксированному PHP entry вне webroot. Синтаксическая проверка контекста не заменяет его аутентификацию. PR29 scope остаётся `JSMJapan/jsm-storefront/.github/workflows/sandbox-publish.yml@main`, environment `sandbox`; public control workflow не подставляется вместо него.

ROOT первым подписывает HELLO; PHP не передаёт nonce по каналу. Закрытый HMAC-протокол связывает context, role, sequence и строгий payload schema. ROOT проверяет SO_PEERCRED worker, стабильную принадлежность FPM, затем безопасный TCP target из той же стандартной Yii Connection. PHP не вызывает Application::run, controller/session, Connection::open/initConnection или Yii Command.

До PDO connect root использует прежний один Docker summary GET и его прежние socket/systemd guards. Только один mysql-family candidate с единственным loopback mapping; точный container ID связывается с фиксированным cgroup-v2 `/sys/fs/cgroup/system.slice/docker-<ID>.scope/cgroup.procs`. Максимум 16 PID; каждый обязан иметь именно это cgroup membership. Никаких inspect/top/argv/environ/volume contents. Поддерживается DIRECT либо единственный docker-proxy из фиксированного docker.service cgroup; остальные layouts закрыто отказываются.

После native PDO connect ROOT проверяет фактические owned TCP endpoints: PHP и ingress в одном net namespace; DIRECT reciprocal либо две однозначные proxy legs до MySQL. Только затем разрешает один фиксированный metadata SELECT. До ACK связь проверяется повторно. Старые FD caps128, read4096/64KiB, Docker .75s и общий producer3s не увеличены; нет retry/skip.

## Source/доверие и ограничения

Проверяются стабильные owner/mode/inode app-файлы (root либо штатный publisher `jsm`, без group/world write), literal config grammar до выполнения, pins уже проверенных api entry/main/bootstrap, стандартный Application/Connection, отсутствие неизвестных startup/event/behavior/failover/PDO hooks. Исходные четыре config definitions объединяются в обычном порядке, без удаления/замены DB definition.

**Установленный Composer loader, его eager files и ленивые Yii/Dotenv классы — явная dependency trust boundary, а не новая аттестация vendor.** PHP8 dependency lock не назначается baseline TEST PHP7.4. OPcache/произвольный пользовательский HTTP request не объявляются проверенными. Profile доказывает только configured-runtime FPM→наблюдённое local DB connection, при успешном выполнении всех guards.

Native PDO сохраняет исходные target/credentials внутри PHP и не экспортирует DSN/password/env. Diagnostic request-local connect/read timeout обязателен; init command, persistent/custom PDO, failover и autocommit=false запрещены. Query: `SELECT DATABASE(), CURRENT_USER(), VERSION(), @@read_only` с фиксированными aliases; результат только schema-match, principal/version class и read-only boolean. Никаких application rows/aggregates/DDL/DML/SHOW GRANTS/provider calls. **Synthetic provenance, grants и egress isolation остаются UNKNOWN.**

## Статус

Реализованы protocol/kernel/private PHP/native PDO/root coordinator и synthetic behavior fixtures. Локально native PHP отсутствует: Linux CI обязан выполнить syntax + реальные PHP coordinator/codec tests; fake PDO fixtures не доказывают соединение с TEST DB. Исходный feature-absence RED сохранён отдельно; новые практические отказы покрываются actual helpers/координатором.

Пакет ещё **DRAFT / NOT READY**: требуется окончательная wiring/rollback договорённость с автором installer, полнота adversarial tests, exact-head native CI и два независимых review. Никакого ручного workflow, установки или SQL runtime не выполнялось. Код READY не даёт разрешения run. После изменения source старое review не переносится на новый SHA.
