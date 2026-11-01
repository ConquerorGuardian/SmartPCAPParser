# Устройство кода

Коротко о том, что где лежит и почему сделано так.

## Путь данных

```
фраза -> engine -> filters -> matcher -> pcap_handler -> gui
                          \-> stats / verdict / streams
```

`parser/engine.py` разбирает фразу и достаёт адреса, порты, MAC, имена и
протоколы. `parser/filters.py` собирает из них display filter.
`parser/matcher.py` компилирует фильтр и считает его на пакетах, без
Wireshark. `parser/pcap_handler.py` применяет фильтр к списку пакетов и
готовит страницы для таблицы. Дальше окно.

## Модули

| Модуль | Что делает |
| --- | --- |
| `parser/pcap_reader.py` | pcap и pcapng: заголовки, интерфейсы, linktype, Ethernet, VLAN, IP, TCP, UDP, ICMP, ARP, defrag, имена из TLS, HTTP и DNS |
| `parser/engine.py` | словарь протоколов и групп, разбор фраз, падежи, отрицания, направления, готовые фильтры Wireshark |
| `parser/filters.py` | сборка фильтра, имена сайтов через `http.host`, `tls.sni`, `dns.qry.name` |
| `parser/matcher.py` | разбор и вычисление фильтров: `and`, `or`, `not`, сравнения, `in {…}`, `contains`, имена протоколов |
| `parser/pcap_handler.py` | загрузка с прогрессом и отменой, фильтрация, страницы, лимиты |
| `parser/streams.py` | поток TCP по sequence number, обмен UDP |
| `parser/stats.py` | график по времени, иерархия, разговоры, узлы, сайты |
| `parser/verdict.py` | текст по файлу и находки |
| `parser/settings.py` | `~/.smartpcapapp/settings.json` |
| `gui/app.py` | окно: загрузка, команды, тема, настройки, статусы |
| `gui/layout.py` | виджеты и сетка |
| `gui/table_view.py` | таблица, поиск, сортировка, страницы |
| `gui/stats_view.py`, `gui/chart.py` | вкладка статистики и график |
| `gui/dialogs.py`, `gui/help_text.py` | справка, детали, поток, вердикт |
| `main.py` | GUI, консольные режимы, `--selftest`, `--version` |

## Почему так

Только стандартная библиотека. Ни scapy, ни pyshark, ни dpkt: exe не должен
тянуть tshark и десятки мегабайт. Разбираем ровно те протоколы, которые
показываем. Внешняя зависимость одна, `customtkinter`.

Свой вычислитель фильтров. Фильтр нужно не только показать, но и применить
без Wireshark, поэтому `matcher.py` умеет считать подмножество синтаксиса
Wireshark на своих пакетах. Незнакомое поле даёт сообщение со списком
поддерживаемых, а не тихие нули.

Заголовки в памяти, тела по требованию. Все пакеты читаются сразу, payload
хранится до порога (25 МБ файл, 64 МБ на поток). Отсюда быстрый старт на
больших дампах и предсказуемая память.

Настройки в домашней папке, рядом с exe ничего не пишется. exe работает с
флешки и из `Program Files` без прав администратора.

Версия объявлена один раз, в `parser/__init__.py`. Её читают `pyproject.toml`,
заголовок окна, справка и файл версии для exe.

## Как добавить протокол

```python
# parser/engine.py
PROTOCOL_FILTERS = {
    ...,
    "mongodb": ["mongodb", "монго", "mongo"],
}
```

Имя фильтра для Wireshark задаётся там же, если оно отличается от слова
(`netbios` даёт `nbns`). Дальше:

- `parser/matcher.py`, словарь `PROTOCOL_NAMES`;
- тест в `tests/test_engine.py`;
- строка в `docs/EXAMPLES.md` и в `gui/help_text.py`.

## Тесты

```
tests/
├── run_all.py            раннер, список модулей
├── test_engine.py        фразы и словарь
├── test_reader.py        pcap, pcapng, битые файлы, linktype
├── test_matcher.py       поля, операторы, ошибки
├── test_handler.py       загрузка, фильтр, лимиты
├── test_streams.py       TCP и UDP
├── test_stats.py         агрегаты
├── test_verdict.py       находки
├── test_settings.py      сохранение настроек
├── test_golden.py        CLI, версия, selftest
├── test_corpus.py        реальные дампы, если скачаны
├── test_full_pipeline.py файл, фильтр, таблица
└── test_gui_smoke.py     окно и основные сценарии
```

Тесты не ходят в сеть и не оставляют файлов в проекте. Временные файлы идут
в `%TEMP%` или `tests/_*`, они в `.gitignore`.

## Скорость

`tools/bench.py` генерирует дамп нужного размера. На 40 МБ и 237 000 пакетов
разбор занимает около 2.5 с, фильтр 0.3 с, сборка потока 0.09 с. Узкие места
при профилировании: разбор TLS и HTTP из данных и реконструкция TCP.
