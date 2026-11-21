# #2767 — семь метаданных файлов перед выпуском пяти статей

**SOURCE CANDIDATE / NOT_RUN / NOT_DEPLOYED.** 21.11.2026.
Назначение — узнать фактические типы, SHA256 и размеры пяти существующих файлов
и доказать отсутствие двух новых путей перед подготовкой frontend carrier.
[Задача2767](https://github.com/JSMJapan/jsm-storefront/issues/2767),
[CODE READY7060860711](https://github.com/JSMJapan/jsm-storefront/issues/2767#issuecomment-7060860711).
Источник будущего изменения — [2765/PR2766](https://github.com/JSMJapan/jsm-storefront/pull/2766),
source merge `b83df56ff0cc270bab2b36825f41aa12de5de875` по задаче; это не установленная версия.

Среда: Hostinger `srv1687281`, `jsmjapan.com`, `187.77.118.50:17177`.
Управление: [control Actions](https://github.com/JSMJapan/jsm-release-control/actions),
[защищённые окружения](https://github.com/JSMJapan/jsm-release-control/settings/environments).
Операционный вход только GitHub. Локального SSH/provider terminal нет.

## Ровно один фиксированный профиль

| Относительно `/var/www/jsmjapan.com-front` | Условие полноты наблюдения |
| --- | --- |
| `config/articleSeo.js` | regular single-link, SHA256 и размер |
| `config/client.js` | то же |
| `config/server.js` | то же |
| `src/App.tsx` | то же |
| `src/pages/MainFlow/BlogArticle/index.tsx` | то же |
| `src/helpers/articleFirstHtml.js` | доказанное отсутствие |
| `src/components/ArticleFirstHtml/index.tsx` | доказанное отсутствие |

Это ожидаемые **категории**, не утверждение о production. Для пяти SHA нет
подставленных source/model/исторических expected. Если новый путь уже существует,
его regular SHA/размер сохраняются, но общий статус BLOCKED; автоматически
перезаписывать его нельзя.

Entry point `scripts/prod_article_sources_sha_readonly.py` принимает только
нулевое число аргументов. Manual `prod-article-sources-sha-readonly.yml` не имеет
inputs, owner/triggering actor JSMJapan, main, attempt1 и точный workflow SHA.
Используются прежние `apache-parity-bootstrap`, approval, host pin и credential;
код не создаёт и не меняет ключи, environments, права и подписи. Public policy
проверяется до credential и transport. Concurrency group прежняя, cancel=false;
другие deploy writers этим не блокируются.

## Повторное использование и защита чтения

Поиск `prod_front_sha|seven.*sha|2767` нашёл существующий трёхфайловый reader.
Расширен его descriptor engine и выделен общий policy/key/host/transport путь.
Исторические три paths/EXPECTED/schema/status/CLI/workflow сохранены; новые
поля и absence admission включаются только новым фиксированным entry point.
Нет monkeypatch guards, подмены GITHUB_WORKFLOW_REF или путей из inputs/env.

Каждый parent открыт FD-relative с O_NOFOLLOW; переданный namespace capsule
содержит только code constants. Regular файл single-link и не больше 1 MiB,
открывается O_NOFOLLOW/O_NONBLOCK и обязательным Linux O_NOATIME. Сверяются
descriptor/name binding, dev/inode/mode/nlink/size/mtime/ctime до и после чтения;
у нового профиля также проверяется исходный root FD. Source bytes остаются
только в памяти remote Python и не передаются runner. Никакого PHP/Node
приложения, HTTP, API/БД/SQL, build, install, reload/restart, provider/AI запросов.

Для новых путей ABSENT разрешён только после первого явного ENOENT от no-follow
stat **после существующей базы**. Фиксируется первый отсутствующий компонент
относительно базы. Вся существующая открытая цепочка/root FD и name bindings
проверяются до повторного ENOENT и после него. Подмена/появление компонента,
missing base, EACCES/EPERM/ENOTDIR или отказ open/read не становятся ABSENT.
Серверные каталоги/файлы не создаются, доступ не исправляется автоматически.

Больший capsule использует существующий tempfile-backed `_bounded` из bridge,
15 секунд, stdout максимум4096 B, stderr discard, cleanup process group.
Нечитающий stdin child не может заблокировать синхронную передачу capsule.
Исторический transport трёх файлов не меняется. Общий timer60с/workflow2мин
сохраняется. Temporary identity/known_hosts0700/0600 создаются только на runner.

## Closed receipt

Version `jsm-prod-article-sources-sha-2767-v1`; семь fixed ordered rows:
`path,type,sha256,size,missing_component`. Regular имеет SHA256/size; ABSENT —
только допустимый первый missing prefix. Другие row states закрыты:
missing/missing_parent/not_regular/unsafe/unstable/oversize/unreadable.
Malformed/duplicate/nonfinite/extra JSON, wrong nonce/uid/path/count/size отказывают
без публикации raw stdout/exception. При отсутствии подтверждённого remote
receipt outer failure содержит семь `not_observed`, root_identity=null.

Пять regular и две proven ABSENT дают `PROD_FRONT_SEVEN_METADATA_COMPLETE`,
иначе BLOCKED/exit1. Это **не** сравнение с исходниками кандидата и не допуск
выпуска. Даже полный receipt сохраняет installed_release_sha=null,
atomic_multi_file_snapshot=false, deploy_acceptance=NOT_ESTABLISHED. Source SHA
означает control workflow, а не SHA установленного сайта. Включены time/run и
fixed resource/domain/IP/port/host-pin digest. Только закрытые метаданные;
исходников, ключей, cookies, env и данных покупателей в output/artifacts нет.

## Проверка и оставшиеся gates

Первый RED — отсутствующий seven-file capsule/projector. GREEN — настоящий
capsule на synthetic temporary files: digest/size, leaf/ancestor ENOENT,
missing base, permission на первой/повторной проверке, parent/name replacement,
появление missing component, symlink/hardlink/directory/oversize/read race.
Отдельно closed receipt, owner/policy/hostpin до transport, fixed command,
temp cleanup, non-reading child/closed-stdout hang/output cap/stderr redaction.
Linux-only тест syscall O_NOATIME явно SKIP на macOS, а не PASS по эмуляции.
Исторический reader и полный control offline suite выполняются отдельно.

Локально `python3 -B -m unittest discover -s tests -p 'test_*.py'`:
198 total/194PASS/4SKIP (2 private integration, 2 Linux syscall) на macOS.
CI/runtime PASS не предполагаются заранее.
AST historical `main`, `project_remote`, `remote_program` и
EXPECTED проверены неизменными относительно ee94; CI path filters только
расширены, старые script/test/workflow paths сохранены. Actual wire-main version,
root/platform refusal и новый no-input workflow дополнительно покрыты.

Два независимых неавторских infrastructure review и exact CI ещё обязательны.
CODE READY не разрешает merge/dispatch. После проверки нужны отдельные точные
merge и один main run с прежним environment approval; результат читает и
записывает координатор в существующий journal PR126/#2765. TEST API/DB/isolation,
клиентская QA и реальные устройства этим reader не подтверждаются.

Откат source — обычный revert будущего PR. Сервер не менялся; возврат на нём
не репетировался. STATE и канонический журнал ведёт координатор.
