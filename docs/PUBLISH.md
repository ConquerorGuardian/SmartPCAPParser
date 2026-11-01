# Как выложить проект на GitHub

Чек-лист на случай, если публиковать будете вы сами (или чтобы одобрить
публикацию агенту). Всё уже подготовлено: git-история, тесты, сборка exe,
workflow для Releases.

Если **github.com не открывается** — сначала короткая инструкция
[GITHUB-ACCESS.md](GITHUB-ACCESS.md): WARP/VPN, git через SSH-порт 443,
перенос проекта bundle-файлом.

Самый короткий путь, когда доступ есть:

```powershell
.\tools\publish.ps1 -Repo https://github.com/Whitemoneydealer/SmartPCAPParser.git
```

Скрипт проверит чистоту репозитория и сеть, поставит remote, отправит `main`
и тег `v1.9.1`; тег запустит сборку и релиз.

## 1. Создать пустой репозиторий

На github.com → **New repository** → имя `SmartPCAPParser` → **без** README,
`.gitignore` и лицензии (они уже в проекте) → **Create**.

## 2. Привязать remote и запушить

```bash
cd SmartPCAPParser
git remote add origin https://github.com/Whitemoneydealer/SmartPCAPParser.git
git branch -M main
git push -u origin main
```

Если git попросит пароль — нужен **Personal Access Token** (Settings →
Developer settings → Tokens → Fine-grained, права `Contents: read/write`),
обычный пароль GitHub больше не принимает.

## 3. Проверить, что тесты прошли

Вкладка **Actions** → workflow `tests` должен быть зелёным
(ruff + 175 проверок с xvfb).

## 4. Выпустить версию (это и есть «скачать с GitHub»)

```bash
git tag -a v1.9.1 -m "Smart PCAP Parser 1.9.1"
git push origin v1.9.1
```

Тег запускает `build-windows`: тесты → сборка **одного exe** и папки →
самопроверка обеих сборок → публикация в **Releases** вместе с
`SHA256SUMS.txt` и текстом «Как запустить».

Через ~5 минут на странице
`https://github.com/Whitemoneydealer/SmartPCAPParser/releases` появится
релиз, откуда один файл `SmartPCAPParser.exe` скачивается одним кликом.

## 5. Оформить страницу репозитория

- **Description**: `Фильтры Wireshark из обычных слов: анализ pcap/pcapng без tshark и ИИ`
- **Topics**: `pcap`, `pcapng`, `wireshark`, `network-analysis`, `python`,
  `customtkinter`, `traffic-analysis`, `security`
- **Website** — ссылку на Releases.
- README уже содержит картинку, скачивание, ограничения и историю изменений.

## Что проверить после публикации

- [ ] `git clone` в чистую папку и `python main.py` запускаются
- [ ] `pip install -r requirements.txt` ставит только `customtkinter`
- [ ] exe из Releases запускается и открывает дамп
- [ ] `SmartPCAPParser.exe --selftest` возвращает 0
- [ ] README на GitHub показывает скриншот и таблицу скачивания
- [ ] `LICENSE` и `CHANGELOG.md` видны в репозитории

## Если что-то пошло не так

| Симптом | Что делать |
| --- | --- |
| Actions падает на тестах | локально `python -m tests.run_all` — там же ошибка |
| Релиз без файлов | проверить, что тег начинается с `v` и workflow `build-windows` зелёный |
| exe не запускается у скачавшего | попросить `--selftest` и прислать `%TEMP%\smartpcap_selftest.txt` |
| SmartScreen ругается | это ожидаемо: exe не подписан, в README есть пояснение |

Проект не публикуется автоматически и никуда не отправляется без
разрешения владельца.
