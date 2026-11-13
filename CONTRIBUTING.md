# Участие

Ошибки, идеи и правки в словаре протоколов приветствуются.

## Собрать и запустить

```bash
git clone https://github.com/ConquerorGuardian/SmartPCAPParser.git
cd SmartPCAPParser
pip install -r requirements-dev.txt
python main.py
```

Нужен Python 3.11 или новее. Запустить без установки: `python main.py --demo`.

## Проверить

```bash
python -m tests.run_all      # 200 проверок
ruff check .                 # линтер, строки до 100 символов
python tools/build_exe.py --both   # один файл и папка с zip
```

Тест это функция `test_*` с `assert`. Новый тест нужно добавить в список в
конце модуля, иначе раннер его не увидит.

Тесты пишут настройки во временную папку, ваш `~/.smartpcapapp` не трогают.
`tests/test_docs.py` дополнительно сверяет таблицы команд в README и
`docs/EXAMPLES.md` с движком: поправили фразу, поправьте и таблицу.

Картинки для `docs/` пересобираются из живого окна:

```bash
python tools/make_screenshots.py
```

Нужен экран и Pillow (`pip install -r requirements-dev.txt`). Скрипт снимает
главное окно, статистику, детали, поток, вердикт, простой режим и светлую
тему, а настройки после себя возвращает как были.

## Куда смотреть

- новый протокол: `PROTOCOL_FILTERS` в `parser/engine.py` и тест в
  `tests/test_engine.py`
- новое поле фильтра: `parser/matcher.py` и `tests/test_matcher.py`
- тексты интерфейса: `gui/help_text.py`
- находки вердикта: `parser/verdict.py`

Парсер не доверяет файлу: длины проверяются, на битом дампе приложение не
падает. Комментарии по-русски, имена по-английски.

## Pull request

Одна задача, ветка от `main`. В описании что было, что стало и как проверить.
Если меняется поведение, допишите `CHANGELOG.md`.
