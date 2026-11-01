# Как выложить на GitHub

Публикация это один тег. Всё остальное уже настроено: репозиторий, Actions,
скрипты.

Если github.com не открывается или не пускает в аккаунт, сначала
[GITHUB-ACCESS.md](GITHUB-ACCESS.md).

## Одной командой

```powershell
.\tools\publish.ps1 -Repo https://github.com/Whitemoneydealer/SmartPCAPParser.git
```

Скрипт проверит чистую рабочую папку, что порт 443 отвечает, поставит
`origin`, если его нет, запушит `main` и поставит тег `v1.9.1`. Дальше
GitHub Actions прогонит тесты, соберёт exe и папку, проверит их и создаст
релиз с файлами и суммами.

Потом откройте страницу релиза, вставьте текст из
[RELEASE-NOTES.md](RELEASE-NOTES.md), при желании приложите скриншот.

## Руками

Репозиторий на GitHub создайте пустым: без README, лицензии и `.gitignore`.

```bash
git remote add origin https://github.com/Whitemoneydealer/SmartPCAPParser.git
git branch -M main
git push -u origin main
git tag -a v1.9.1 -m "Smart PCAP Parser 1.9.1"
git push origin v1.9.1
```

Тег и есть спусковой крючок для CI. Если поставить его раньше `main` или
дважды, сборка либо не увидит коммит, либо перезапишет релиз. Порядок такой:
сначала `main`, потом тег.

## После публикации

- вкладка Actions: оба workflow зелёные, exe в артефактах релиза;
- страница релиза: exe, zip и `SHA256SUMS.txt` на месте;
- README на GitHub отрисовывается со скриншотом;
- прямая ссылка `.../releases/latest/download/SmartPCAPParser.exe` скачивает
  последнюю версию;
- скачанный exe запускается, `--selftest` даёт код 0.

## Если CI упал

Логи в Actions. Частые причины: тег без коммита, не хватает секрета
`GITHUB_TOKEN` (в публичном репозитории он есть по умолчанию), тест на
корпусе полез в сеть (он пропускается, если `samples/` нет).

Пересобрать локально и сравнить:

```bash
python tools/build_exe.py --both
python tools/check_exe.py dist/SmartPCAPParser.exe dist/SmartPCAPParser/SmartPCAPParser.exe
```

## Откат

```bash
git tag -d v1.9.1                 # локально
git push origin :refs/tags/v1.9.1 # на GitHub
```

Релиз удаляется кнопкой на странице релиза. Те, кто уже скачал файл, ничего
не заметят, поэтому лучше выпустить 1.9.2, чем переписывать 1.9.1.
