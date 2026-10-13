# secret-scan-ci

CLI-сканер рабочего дерева и собранного бандла на утечки ключей. Главная особенность — **он никогда не печатает само значение секрета**. В отчёте только файл, строка, класс находки, длина значения и 12-символьный sha256-отпечаток, поэтому лог CI можно публиковать открыто и прикладывать к issue.

Зависимостей нет, нужен Node 18+. В npm пакет пока не выложен — ставится клоном:

```bash
git clone https://github.com/dhhdhdxhxhx252-alt/secret-scan-ci.git
cd secret-scan-ci && npm link     # появляется команда secret-scan
```

## Быстрый старт

```bash
secret-scan .                          # проверить текущий проект
secret-scan . dist --fail-on critical  # вместе со сборкой
node src/cli.js fixtures/leaks         # демо на выдуманных секретах (npm run scan:demo)
```

Код возврата `1`, если есть находки не ниже `--fail-on`, `2` при неверных аргументах. `--fail-on` считает по максимуму: `note < medium < high < critical`.

## Пример вывода

Это реальный прогон по `fixtures/leaks/`, значения там выдуманные:

```
CRITICAL fixtures/leaks/id_ed25519  ssh-key-file  (ssh private key file)
CRITICAL fixtures/leaks/leaky-config.js:2  github-token  (github token, длина 36, sha256/c93b39dec696)
CRITICAL fixtures/leaks/leaky-config.js:3  aws-access-key  (aws access key id, длина 20, sha256/2600cc16ada0)
CRITICAL fixtures/leaks/leaky-config.js:4  supabase-service-key  (supabase service_role key, длина 34, sha256/3e38cc93b200)
CRITICAL fixtures/leaks/leaky-config.js:6  jwt  (jwt with service_role claims, длина 85, sha256/e87b14eb7ad9)
CRITICAL fixtures/leaks/leaky.pem:1  private-key  (pem private key, длина 31, sha256/8bcac7908eb9)
CRITICAL fixtures/leaks/release.keystore  keystore-file  (signing keystore)
HIGH     fixtures/leaks/prod.env:1  env-assignment  (credential in env-style line, длина 24, sha256/e275cc46a5c8)

проверено файлов: 5  |  находок: 9  (critical: 7, high: 2)
```

## Что ищет

| Правило | Уровень | Примечание |
| --- | --- | --- |
| `private-key` | critical | `-----BEGIN ... PRIVATE KEY-----` |
| `supabase-service-key` | critical | `sb_secret_...` |
| `github-token` | critical | `ghp_ / gho_ / ghu_ / ghs_ / gpr_ / github_pat_` |
| `aws-access-key` | critical | `AKIA... / ASIA...` |
| `slack-token` | critical | `xoxb- / xoxp- ...` |
| `jwt` | critical | Разбирает payload и читает `role`. `anon` и `authenticated` понижаются до `medium`: такие ключи публикуются в клиенте намеренно, это не утечка |
| `credential-assignment` | high | `api_key = "..."` — значения только в кавычках. Без кавычек минифицированный JS даёт ложные срабатывания на фрагментах кода |
| `env-assignment` | high | Строка вида `DEPLOY_ACCESS_TOKEN=...` без кавычек, как в `.env` |
| `pii-email` | medium | Адрес почты в исходниках; `noreply@`, `example.com` и т.п. игнорируются |
| `supabase-project-ref` | note | `https://<ref>.supabase.co` — сам по себе не секрет, но полезно знать, где он лежит |
| `keystore-file` | critical | `.jks`, `.keystore`, `.p12`, `.pfx` по имени файла |
| `env-file` | high | `.env` и `.env.*` в дереве (`.env.example` не считается) |
| `ssh-key-file` | critical | `id_rsa`, `id_ed25519` и т.д. по имени файла |

Общее значение, попавшее и под узкое правило, и под общее (`credential-assignment` / `env-assignment`), репортится один раз — узким правилом, у него больше информации.

## Флаги

```
--json                вывод списком объектов
--fail-on <level>     note | medium | high | critical (по умолчанию high)
--ignore <regex>      дополнительный фильтр путей, повторяемо
--max-size <bytes>    пропускать файлы больше этого размера (по умолчанию 8388608)
--help
```

Строки длиннее 20 000 символов пропускаются: это почти всегда минифицированный бандл или встроенный ассет, разбирать который руками бесполезно. Файлы с NUL в первых 8 КБ считаются бинарными, симлинки не обходятся. По умолчанию игнорируются `.git`, `node_modules`, `.venv`, `__pycache__`, `.gradle` и лок-файлы пакетных менеджеров.

## Ложные срабатывания

Тесты и фикстуры сами содержат выдуманные ключи. Чтобы не исключать весь файл, поставьте маркер в ту же строку:

```js
const DEMO_KEY = "Zx9Kq7Lm2Wp4Rt8Yu6Ia0Sd3Fg7Hb1Nc" // secret-scan:allow
```

Строка, содержащая `secret-scan:allow`, не проверяется. Для каталога удобнее `--ignore "fixtures/"`.

## В GitHub Actions

```yaml
- name: Redaction scan перед публикацией
  run: node src/cli.js . dist --fail-on high
```

Самопроверка этого репозитория — в `.github/workflows/ci.yml`: три версии Node, юнит-тесты, прогон по дереву и по `fixtures/leaks/` с требованием, что ни одно значение не попало в отчёт.

## fixtures/leaks

`npm run fixtures` генерирует каталог с выдуманными секретами (в `.gitignore`), `npm run scan:demo` прогоняет по ним сканер. Значения собираются из частей в `fixtures/make-leaks.mjs` и нигде не лежат в репозитории целиком — иначе GitHub Secret Scanning находит паттерны в дереве и блокирует пуш.

## Ограничения

- Это не проверка истории коммитов и не замена GitHub Secret Scanning: инструмент смотрит текущее дерево. Для истории берите `gitleaks` или `trufflehog`.
- Отпечаток — 12 hex-символов от sha256 значения: позволяет сверить «утёкший» ключ с найденным, но не восстановить его. У почты отпечатка нет вовсе — её можно подобрать по хешу.
- Энтропийный порог 3.2 отсекает заглушки, но может пропустить короткий настоящий ключ. `--fail-on medium` и `--json` помогают разобрать спорные случаи.

## Тесты

```bash
npm test
```

Отдельный тест гарантирует, что сериализованный отчёт не содержит значение секрета, и что почта не получает отпечатка.

## License

MIT — см. [LICENSE](LICENSE).
