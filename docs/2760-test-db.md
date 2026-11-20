# #2760: фиксированный OS metadata observer TEST, цель БД ещё не допущена

Задача: [JSMJapan/jsm-storefront#2760](https://github.com/JSMJapan/jsm-storefront/issues/2760).
Подготовка кода разрешена [решением владельца](https://github.com/JSMJapan/jsm-storefront/issues/2760#issuecomment-7030574514). Это не разрешение запуска.
Основа: control main `0f32c5cba72acdc5e9b17579a7ce72b4438012f6`.

**SCOPE PREPARED / DB PROOF BLOCKED_TARGET_ADMISSION / SQL_NOT_ATTEMPTED.**
Текущий первый draft содержит полезное ядро OS-наблюдения: три фиксированных
systemd MainPID, ожидаемые exe/net/mnt namespaces, bounded FD/socket relationships
и metadata фиксированного `/var/lib/mysql`/covering mount. Данные берутся только
из OS metadata, без SQL/конфигурации/учётных данных/содержимого datadir.
До подключения проверенного транспортного wrapper это SOURCE CORE ONLY.
Бесполезный policy-only operational workflow не добавляется. Интеграция с
существующим GitHub-only key-only транспортом готовится следующим коммитом;
этот draft не является готовой диагностикой или разрешением запуска.

Это намеренно не SQL-runner. Нет текущего независимого доверенного baseline,
который разрешал бы подключение. Код не принимает runtime baseline, DSN, пути,
команды или SQL из argument/env/HTTP. Он проверяет существующую публичную
GitHub policy и выдаёт закрытый BLOCKED receipt с exit1. Доступ к ключу, SSH,
PHP/Yii, конфигурации приложения и БД не выполняется. Нет fictitious positive
connector, который работал бы только на офлайн doubles.

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
  Он использует прежнее protected environment, но не передаёт неиспользуемый
  секрет процессу. Existing SSH programs, key-only options, host pin, временные
  private files и лимиты не изменены. SSH в этом кандидате вообще недостижим.
- Общий deadline60с, фиксированный bounded receipt. Никаких raw exceptions,
  DSN, grants, customer data или содержимого файлов в stdout/artifacts.

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
run: 150 тестов, 147 PASS + те же3 SKIP; actual DB/runtime не запускались.
Новые офлайн adversarial проверки ловят forged env baseline/SQL/DSN, actor/ref/
attempt/workflow drift, policy/owner/branch drift, private exception leakage и
продвижение неподтверждённых полей до DB proof. При admitted GitHub policy
credential/SSH/SQL boundary всё равно не достигается.

```bash
python3 -B -m unittest discover -s tests -p 'test_test_db_metadata_readonly.py'
python3 -B -m unittest discover -s tests -p 'test_*.py'
```

Runtime manual job намеренно завершится BLOCKED/exit1, а не зелёным DB PASS.
Сейчас запуск не требуется и не разрешён. Два non-author frozen-head PASS,
exact CI и отдельное owner activation/run approval обязательны. Existing
environment approval также сохраняется. При неизвестном target admission
не запускать профиль только ради повторения уже известного BLOCKED.

Возврат кода — revert этого control PR. Existing transports/environments/
credentials не меняются; DB rollback не требуется, записей нет. Root сохраняет
итог в #2760/#2738 и existing journal PR126 с прочтением сохранённой записи.
