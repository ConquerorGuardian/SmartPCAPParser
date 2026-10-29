"""
Графический интерфейс Smart PCAP Parser.

Раскладка: боковая панель + рабочая область с вкладками.

Боковая панель (слева):
1. Название приложения.
2. Карточка файла: имя, число пакетов, кнопка «Открыть файл».
3. Карточка команды: ввод обычными словами + «Применить».
4. Быстрые фильтры: десять частых протоколов в один клик.
5. Примеры команд: клик подставляет текст, адрес выделен — просто печатайте.
6. История команд: повторный запуск одним кликом.
7. Переключатель темы.

Рабочая область (справа):
8. Строка display-фильтра Wireshark и кнопки действий.
9. Вкладки «Пакеты» и «Статистика».
10. Таблица пакетов: отдельные колонки портов, сортировка по клику,
    цвет фона по транспорту, окно деталей пакета по двойному клику.
11. Статистика: иерархия протоколов, разговоры, узлы.
12. Строка состояния.

Чтение файла выполняется в отдельном потоке, чтобы окно не зависало
на больших дампах.
"""

import queue
import re
import threading
from pathlib import Path
import sys

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

# Корень проекта в sys.path, чтобы запускать и как модуль, и как скрипт.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.engine import NaturalLanguageFilterEngine            # noqa: E402
from parser.filters import generate_filter                       # noqa: E402
from parser.matcher import FilterError, compile_filter           # noqa: E402
from parser.pcap_handler import COLUMNS, PcapHandler, PcapResult  # noqa: E402
from parser.pcap_reader import read_payloads                     # noqa: E402
from parser.validators import (                                  # noqa: E402
    is_valid_ipv6,
    is_valid_mac_address,
)
from parser.stats import (                                       # noqa: E402
    conversations,
    endpoints,
    format_bytes,
    format_duration,
    hosts,
    protocol_hierarchy,
    summary,
    timeline,
)
from parser.verdict import build_verdict, format_verdict          # noqa: E402
from parser.settings import load_settings, save_settings          # noqa: E402
from gui.chart import TrafficChart                               # noqa: E402
from parser.streams import (                                     # noqa: E402
    MODE_HEX,
    MODE_TEXT,
    VIEW_BOTH,
    VIEW_CLIENT,
    VIEW_SERVER,
    conversation_frames,
    follow_datagram_flow,
    follow_stream,
    format_endpoint,
    render_stream,
    summarize,
)

APP_TITLE = "Smart PCAP Parser"
APP_SUBTITLE = "Фильтры Wireshark обычными словами"

# Сколько строк таблица рисует сразу. До VIEW_LIMIT показываем всё без
# «Показать все»: 50 000 строк заполняются за доли секунды. Выше — первая
# страница, чтобы окно не подвисало на гигантских дампах.
VIEW_LIMIT = 50_000
PREVIEW_COUNT = 5_000
SIDEBAR_WIDTH = 340
HISTORY_LIMIT = 12
HEX_LIMIT = 64 * 1024

# ---------------------------------------------------------------------------
# Палитры: одна точка правки для обеих тем.
# ---------------------------------------------------------------------------
DARK_THEME = {
    "bg": "#0f1216",
    "panel": "#161b21",
    "card": "#1b2128",
    "border": "#28303a",
    "row": "#131920",
    "row_alt": "#171e26",
    "head": "#212a35",
    "text": "#e7ecf2",
    "muted": "#8d99a8",
    "accent": "#3ddc97",
    "accent_hover": "#5ae8a9",
    "accent_text": "#07130d",
    "button": "#232b34",
    "button_hover": "#2d3742",
    "danger": "#ff7b72",
    "mono": "#e7ecf2",
}

LIGHT_THEME = {
    "bg": "#eef2f7",
    "panel": "#ffffff",
    "card": "#ffffff",
    "border": "#d5dde8",
    "row": "#ffffff",
    "row_alt": "#f2f6fb",
    "head": "#e4ebf4",
    "text": "#111820",
    "muted": "#5a6a7d",
    "accent": "#0f9d63",
    "accent_hover": "#12b571",
    "accent_text": "#ffffff",
    "button": "#e4ebf4",
    "button_hover": "#d3ddea",
    "danger": "#c0392b",
    "mono": "#111820",
}

# Фон строки по протоколу: (чётная, нечётная).
TINTS = {
    "dark": {
        "TCP": ("#132430", "#101d27"),
        "UDP": ("#1c1730", "#171228"),
        "ICMP": ("#252011", "#1e1a0e"),
        "ARP": ("#251b13", "#1f160f"),
    },
    "light": {
        "TCP": ("#e8f2fb", "#f2f8fe"),
        "UDP": ("#f1ecfb", "#f7f3fd"),
        "ICMP": ("#fdf5dd", "#fef9ee"),
        "ARP": ("#fdeade", "#fef3ec"),
    },
}

THEME = dict(DARK_THEME)
PROTOCOL_TINTS = TINTS["dark"]

COLUMN_WIDTHS = {
    "Frame": 64,
    "Time": 96,
    "Protocol": 78,
    "Source": 148,
    "Src Port": 74,
    "Destination": 148,
    "Dst Port": 74,
    "Length": 64,
    "Info": 320,
}

# Выравнивание: числа — вправо, текст — влево.
COLUMN_ANCHORS = {
    "Frame": "e",
    "Time": "e",
    "Src Port": "e",
    "Dst Port": "e",
    "Length": "e",
}

# Как сортировать колонку: (поле PacketRow, тип).
SORT_KEYS = {
    "Frame": ("frame", "int"),
    "Time": ("time", "float"),
    "Protocol": ("protocol", "str"),
    "Source": ("source", "str"),
    "Src Port": ("src_port", "int"),
    "Destination": ("destination", "str"),
    "Dst Port": ("dst_port", "int"),
    "Length": ("length", "int"),
    "Info": ("info", "str"),
}

# Быстрые фильтры: частые протоколы в один клик.
QUICK_FILTERS = [
    ("TCP", "покажи tcp трафик"),
    ("UDP", "покажи udp трафик"),
    ("ICMP", "покажи icmp трафик"),
    ("DNS", "покажи dns трафик"),
    ("DHCP", "покажи dhcp трафик"),
    ("ARP", "покажи arp трафик"),
    ("HTTP", "покажи http трафик"),
    ("TLS", "покажи tls трафик"),
    ("QUIC", "покажи quic трафик"),
    ("SSH", "покажи ssh трафик"),
    ("SMB", "покажи smb трафик"),
    ("RDP", "покажи rdp трафик"),
    ("NTP", "покажи ntp трафик"),
    ("FTP", "покажи ftp трафик"),
    ("SMTP", "покажи smtp трафик"),
    ("IPv6", "покажи ipv6 трафик"),
    ("SQL", "покажи базы данных"),
    ("Прокси", "покажи прокси"),
    ("Сайты", "покажи сайты"),
    ("Туннели", "покажи туннели"),
    ("ICMPv6", "покажи icmpv6"),
    ("LLMNR", "покажи llmnr"),
]

# Примеры команд: их видно в боковой панели, клик подставляет текст.
# Чем больше разных формулировок, тем быстрее человек находит свою.
EXAMPLE_COMMANDS = [
    # адреса и направления
    "покажи пакеты с айпи 192.168.1.1",
    "пакеты от 10.0.0.5",
    "пакеты к 8.8.8.8",
    "айпи 2001:db8::1",
    "пакеты с айпи 192.168.1.100 на порт 8080",
    "айпи 192.168.1.0",
    # порты
    "покажи пакеты на порт 80",
    "порты 80 и 443",
    "порты 1024-65535",
    "порт от 20 до 23",
    "tcp порт 443",
    "не на порт 22",
    # протоколы
    "http трафик",
    "dns запросы",
    "tls трафик",
    "пинг",
    "https трафик",
    "покажи quic",
    "общая папка",
    "удалённый рабочий стол",
    "базы данных",
    "почта",
    "мониторинг оборудования",
    "умный дом",
    "файловые серверы",
    "покажи принтер",
    # комбинации
    "покажи http трафик с айпи 192.168.1.10",
    "dns с айпи 192.168.1.10",
    "tcp не на порт 80",
    # исключения
    "не http",
    "всё кроме 8.8.8.8",
    "не dns и не http",
    # мак
    "мак адрес aa:bb:cc:dd:ee:ff",
    "покажи пакеты с мак адресом 00:11:22:33:44:55",
    # разговорные формулировки
    "глянь что там на порту 443",
    "хочу увидеть трафик к 1.1.1.1",
    "что за устройства в сети",
    "ищу зашифрованный трафик",
    "грепни почтовый сервер",
]

EXAMPLES_VISIBLE = 5
VERDICT_FINDINGS = 3

# Файлы больше этого размера читаются без тела TCP: иначе «Поток TCP» съест
# память целиком. Поток для них недоступен, о чём честно пишем в статусе.
MAX_PAYLOAD_FILE = 25 * 1024 * 1024
# Сколько данных потока максимум подгружаем из большого файла по требованию.
STREAM_PAYLOAD_LIMIT = 64 * 1024 * 1024

# Флаги TCP: бит -> подпись.
TCP_FLAGS = [
    (0x100, "CWR"),
    (0x080, "ECE"),
    (0x040, "URG"),
    (0x020, "ACK"),
    (0x010, "PSH"),
    (0x008, "RST"),
    (0x004, "SYN"),
    (0x002, "FIN"),
    (0x001, "NS"),
]


def format_count(value: int) -> str:
    """9123 -> «9 123»: в статусе так читается легче."""
    return "{:,}".format(value).replace(",", " ")


def table_limit(total: int) -> int:
    """Сколько строк рисовать сразу (-1 — все).

    До VIEW_LIMIT показываем всё — «в файле 9 000 пакетов, а в таблице 200»
    выглядело как потеря данных. Выше лимита рисуем первую страницу, чтобы
    окно не подвисало, и честно пишем об этом в статусе.
    """
    return -1 if total <= VIEW_LIMIT else PREVIEW_COUNT


def _safe_stem(text: str) -> str:
    """Имя файла без символов, недопустимых в Windows."""
    cleaned = "".join(
        char if char.isalnum() or char in "-_." else "_" for char in text
    )
    return cleaned.strip("._") or "stream"


def decode_tcp_flags(flags: int) -> str:
    """0x18 -> 'PSH, ACK'."""
    names = [name for bit, name in TCP_FLAGS if flags & bit]
    return ", ".join(names) if names else "нет"


def hex_dump(data: bytes, width: int = 16) -> str:
    """Классический hex-дамп: смещение, байты, печатные символы."""
    if not data:
        return ""

    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join("{:02x}".format(byte) for byte in chunk)
        text_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        lines.append(
            "{:08x}  {:<47}  {}".format(offset, hex_part, text_part)
        )
    return "\n".join(lines)


HELP_TEXT = """КАК ПОЛЬЗОВАТЬСЯ — ТРИ ШАГА
════════════════════════════════════════════════════════════

  1. Откройте файл .pcap или .pcapng.
     Кнопка «Открыть файл» слева или Ctrl+O.
     Под именем файла появится число пакетов.

  2. Напишите, что искать, обычными словами.
     Поле «Команда» слева. Например: http трафик с айпи 10.0.0.5

  3. Нажмите Enter.
     В строке сверху появится фильтр Wireshark, ниже — найденные пакеты.


ПОДСКАЗКИ ПРЯМО В ОКНЕ
════════════════════════════════════════════════════════════

  Строка под полем команды показывает, что понято, пока вы печатаете:
    зелёным   → http and ip.addr==192.168.1.10
    красным   не понял: нужен адрес, порт, мак или протокол

  Карточка «ПРИМЕРЫ» — готовые команды. Клик подставляет текст, адрес
  или порт уже выделены: печатайте поверх, заменяя значение.
  «другие ⟳» показывает следующую пятёрку примеров.

  Двадцать две кнопки быстрых фильтров: TCP, UDP, ICMP, DNS, DHCP, ARP,
  HTTP, TLS, QUIC, SSH, SMB, RDP, NTP, FTP, SMTP, IPv6, базы данных,
  прокси, сайты, туннели, ICMPv6, LLMNR.
  Остальные протоколы — словами: telnet, pop3, imap, ldap, mysql, mdns,
  sip, snmp, tftp, vnc, mqtt, kerberos, syslog, stun, openvpn, socks, nfs,
  memcached, mssql (tds), postgresql (pgsql), mongodb (mongo), redis,
  icmpv6, igmp, gre, ospf, esp, ipsec (ike, isakmp), l2tp, llmnr, ssdp,
  dhcpv6, radius, netbios (nbns), bgp, xmpp, irc.


ЧТО ПИСАТЬ В КОМАНДУ
════════════════════════════════════════════════════════════

  Адреса и порты
    покажи пакеты с айпи 192.168.1.1     →  ip.addr==192.168.1.1
    пакеты от 10.0.0.5                   →  ip.src==10.0.0.5
    пакеты к 8.8.8.8                     →  ip.dst==8.8.8.8
    айпи 2001:db8::1                     →  ipv6.addr==2001:db8::1
    выведи пакеты на порт 80             →  tcp.port==80
    порты 80 и 443                       →  tcp.port==80,443
    порты 1024-65535                     →  tcp.port in {1024..65535}
    порты от 20 до 23                    →  tcp.port in {20..23}
    порт номер 22                        →  tcp.port==22
    мак адрес aa:bb:cc:dd:ee:ff          →  eth.addr==aa:bb:cc:dd:ee:ff

  Исключения (отрицание)
    не http                              →  not (http)
    покажи всё кроме 8.8.8.8             →  not (ip.addr==8.8.8.8)
    пакеты не на порт 80                 →  not (tcp.port==80)
    покажи tcp трафик не на порт 22      →  not (tcp.port==22) and tcp
    не dns и не http                     →  not (http or dns)

  Протоколы
    http, http/2 (h2), dns, tls (ssl, https), quic, tcp, udp, icmp, arp,
    ssh, ftp, smtp, ntp, dhcp, telnet, pop3, imap, ldap,
    smb (cifs, шара), rdp (удалённый рабочий стол), mysql,
    mdns (bonjour, принтер), sip, snmp, tftp, vnc, mqtt,
    kerberos, syslog, stun, openvpn (vpn), socks (прокси),
    nfs, memcached, mssql (sql server), postgresql, mongodb, redis,
    icmpv6 (icmp6), igmp, gre, ospf, esp, ipsec (ike), l2tp, llmnr,
    ssdp (upnp), dhcpv6, radius, netbios (nbns), bgp, xmpp, irc

  Что приложение видит по данным, а не по порту: http/2 (префикс
  соединения), http (GET/POST/…), tls, ssh (баннер), sip (INVITE/
  REGISTER/… и «SIP/2.0»), mqtt (пакет CONNECT), dns поверх tcp
  (длина сообщения + заголовок DNS).

  Собирательные фразы (сразу несколько протоколов)
    базы данных        →  mysql, tds, pgsql, mongo, redis, memcached
    почта              →  smtp, pop3, imap
    удалённый доступ   →  rdp, ssh, vnc, telnet
    видеосвязь         →  sip, stun
    мониторинг         →  snmp, syslog
    сетевые папки      →  smb, nfs
    файловые серверы   →  ftp, smb, nfs
    сайты              →  http, tls, dns
    туннели            →  openvpn, l2tp, ipsec, gre
    локальная сеть     →  arp, llmnr, netbios, ssdp, mdns
    маршрутизация      →  bgp, ospf, icmp, igmp

  Имена сайтов и хостов
    покажи сайт example.com   →  (http.host contains "example.com" or
                                  tls.handshake.extensions_server_name contains
                                  "example.com" or dns.qry.name contains
                                  "example.com")
    не сайт example.com       →  not (…) — то же с отрицанием
    покажи сайты              →  (http or tls or dns)
    Имена (HTTP Host, TLS SNI, DNS) видны в колонке Info после протокола:
    «HTTP · example.com», «TLS · example.com», «DNS · example.com».
    Их же видно в статистике («Сайты и хосты»), в деталях пакета и в вердикте.

  Фильтры из интернета тоже работают
    frame.len > 100           →  пакеты длиннее 100 байт
    ip.ttl < 64               →  маленький TTL
    tcp.flags.syn==1 and tcp.flags.ack==0   →  только SYN
    tcp.len > 0               →  пакеты с данными
    udp.length, tcp.window_size, icmp.type  →  числовые поля
    http.host contains "example"            →  поиск по имени сайта
    http.host                               →  пакеты, где имя есть
    tcp contains "HTTP"                     →  поиск текста в данных
    Фильтр можно вставить и в поле «Фильтр Wireshark» справа сверху.

  Окончания не важны: «телефонию», «почту», «шару» понимаются так же,
  как «телефония», «почта», «шара» — можно писать в любом падеже.

  Комбинации
    покажи http трафик с айпи 192.168.1.10
    пакеты с айпи 192.168.1.100 на порт 8080

  Действия        покажи · выведи · найди · глянь · дай · отфильтруй
  Направление     «от …» / «к …», «отправитель» / «получатель»
  Бытовые слова   «общая папка» → smb, «почта» → smtp, «пинг» → icmp,
                  «синхронизация времени» → ntp, «айпишник» → адрес


КАК ЧИТАТЬ ТАБЛИЦУ ПАКЕТОВ
════════════════════════════════════════════════════════════

  Frame         номер кадра в файле
  Time          время от первого пакета, секунды
  Protocol      TCP, UDP, ICMP или ARP — как в Wireshark
  Source        адрес отправителя
  Src Port      порт отправителя
  Destination   адрес получателя
  Dst Port      порт получателя
  Length        длина кадра
  Info          подробности: флаги TCP и прикладной протокол (HTTP, DNS…)

  Цвет фона строки — транспорт:
    синеватый   TCP
    фиолетовый  UDP
    жёлтый      ICMP
    оранжевый   ARP

  Клик по заголовку сортирует таблицу, повторный клик — в обратную
  сторону. Двойной клик открывает детали пакета. Ctrl+C копирует строку.

  В таблицу попадает весь файл: до 50 000 пакетов показываются сразу.
  Если файл больше, в статусе будет «показаны первые N» и кнопка
  «Показать все». Строка статуса всегда говорит, сколько пакетов
  в файле и сколько сейчас в таблице.


ВЕРДИКТ ПО ФАЙЛУ
════════════════════════════════════════════════════════════

  Сразу после загрузки над таблицей появляется короткий вывод словами:
  сколько пакетов, каких больше, кто с кем общался. Под ним — находки:

    Подключения без ответа   много SYN без ответа — похоже на скан
    Сбросы соединений        соединения рвут RST
    DNS без ответа           имена не разрешаются
    Много ARP                шум, конфликт адресов или петля
    Обращения к SMB/RDP/…    из локальной сети наружу

  У находки есть кнопка «Показать» — она сразу применяет нужный фильтр.
  «Подробнее» открывает весь текст вердикта, его можно скопировать.

  Вердикт строится по всему файлу, а не по отфильтрованным строкам.

  Нет своего дампа? Кнопка «Открыть пример дампа» в карточке файла
  откроет встроенный пример — всё сразу видно.


ПРАВАЯ КНОПКА МЫШИ ПО СТРОКЕ
════════════════════════════════════════════════════════════

  Детали пакета          то же, что двойной клик
  Поток TCP              склеить данные соединения
  Только от …            фильтр по адресу отправителя
  Только к …             фильтр по адресу получателя
  Только порт …          фильтр по порту
  Только TCP/UDP/…       фильтр по протоколу
  Копировать строку      в буфер обмена

  Это быстрее, чем набирать команду: клик по адресу — и таблица сузилась.


ДЕТАЛИ ПАКЕТА
════════════════════════════════════════════════════════════

  Двойной клик по строке или правая кнопка → «Детали пакета».

  Сверху — поля по слоям: Frame, Ethernet, IP, TCP/UDP, приложение.
  Для TCP показываются порты, sequence number и расшифровка флагов
  (SYN, ACK, PSH…). Снизу — hex-дамп полезной нагрузки, если она есть
  в захвате. Данные грузятся только для TCP и только до 64 КБ.


СТАТИСТИКА (вторая вкладка)
════════════════════════════════════════════════════════════

  Вкладка «Статистика» рядом с «Пакеты».

    График трафика        интенсивность по времени: переключатель
                          «Байты / Пакеты», при наведении — время
                          и объём интервала
    Иерархия протоколов   сколько пакетов и байт у каждого протокола,
                          доля от всех пакетов; прикладные протоколы
                          вложены в транспортные
    Сайты и хосты         имена из HTTP Host, TLS SNI и DNS с числом
                          пакетов, байт и источником имени
    Разговоры             пары узлов: сколько пакетов и байт между ними
    Узлы                  адреса и объём отправленного и полученного

  Переключатель «Все пакеты / Найденные» выбирает, что считать: весь
  файл или только строки, прошедшие текущий фильтр. Кнопка «Обновить»
  пересчитывает вручную — автоматически статистика обновляется после
  каждой команды.


ТЕМА И НАСТРОЙКИ
════════════════════════════════════════════════════════════

  Переключатель «Светлая тема» внизу боковой панели или Ctrl+L.
  Файл, фильтр и история при смене темы сохраняются.

  Между запусками запоминаются: тема, размер окна, ширина колонок,
  история команд, последняя папка и область статистики. Файл настроек —
  ~/.smartpcapapp/settings.json (в домашней папке, не в проекте).
  Если он повреждён, приложение возьмёт значения по умолчанию.


КНОПКИ И ГОРЯЧИЕ КЛАВИШИ
════════════════════════════════════════════════════════════

  Открыть файл    Ctrl+O    выбрать .pcap или .pcapng
  Применить       Enter     выполнить команду из поля слева
  Поиск           Ctrl+F    искать по видимым строкам: адрес, порт,
                            протокол или текст колонки Info. Счётчик
                            справа показывает «сколько из скольких»,
                            Esc или «Сбросить» — снять поиск
  Копировать                скопировать фильтр Wireshark — вставьте его
                            в строку фильтра Wireshark
  Показать все              вывести все совпадения, если строк слишком много
  Поток TCP       Ctrl+T    склеить данные TCP-соединения выбранного
                            пакета: запросы, ответы, тело файлов
                            (для UDP-пакета — «Поток UDP»)
  Экспорт CSV               сохранить в файл всё по текущему фильтру;
                            если включён поиск — только найденные строки
  Сброс фильтра   Esc       вернуть все пакеты: очищает поле команды
                            и снимает фильтр. То же самое — просто
                            стереть текст в поле команды
  Тема            Ctrl+L    тёмная или светлая
  Справка         F1        это окно
  Правая кнопка             меню на строке: детали, поток TCP, копировать


ПОТОК TCP И UDP (FOLLOW STREAM)
════════════════════════════════════════════════════════════

  Выделите TCP-пакет и нажмите «Поток TCP» или Ctrl+T. Откроется окно
  с содержимым соединения. Для UDP-пакета та же кнопка открывает
  «Поток UDP»: датаграммы одного обмена в порядке захвата.

  Данные TCP склеиваются по sequence number: порядок пакетов в файле
  и ретрансмиссии не важны. Байты, потерянные при захвате, помечаются
  как «[пропущено N байт]».

  Большие файлы: тела пакетов не держатся в памяти — при открытии
  потока приложение дочитывает из файла только кадры этого соединения
  (до 64 МБ).

  Переключатели в окне:
    Оба / Клиент → сервер / Сервер → клиент   какое направление показать
    Текст / HEX                               вид данных
    Копировать / Сохранить в файл             забрать результат


ФРАГМЕНТЫ IP
════════════════════════════════════════════════════════════

  Фрагменты IPv4 и IPv6 складываются в целую датаграмму, после чего
  разбирается TCP/UDP. В строке видно «собран из N фрагментов»,
  а неполные фрагменты подписаны «Фрагмент IPv4 (offset N)».

  Это значит: фильтры по портам и именам работают и для трафика,
  который был раздроблен на части.


ЧЕГО ПРИЛОЖЕНИЕ НЕ ДЕЛАЕТ
════════════════════════════════════════════════════════════

  Не требует Wireshark и tshark: pcap читается и фильтруется внутри.
  Не использует ИИ и нейросети: только регулярные выражения и словари.
  Не собирает потоки в реальном времени — только по сохранённому файлу.
  Не поддерживает весь синтаксис Wireshark: tcp.analysis.* и
  http.response.* не разбираются (вычислитель скажет об этом прямо).
"""


class SmartPcapApp(ctk.CTk):
    """Главное окно приложения."""

    def __init__(self) -> None:
        global THEME, PROTOCOL_TINTS

        # Настройки читаем до построения интерфейса: тема и история
        # должны примениться сразу, без мигания.
        self.settings = load_settings()
        self.theme_name = self.settings["theme"]
        THEME = dict(LIGHT_THEME if self.theme_name == "light" else DARK_THEME)
        PROTOCOL_TINTS = TINTS[self.theme_name]

        ctk.set_appearance_mode("light" if self.theme_name == "light" else "dark")
        ctk.set_default_color_theme("dark-blue")

        super().__init__()

        self.title(APP_TITLE)
        self.geometry(self.settings["geometry"] or "1380x820")
        self.minsize(1080, 620)
        self.configure(fg_color=THEME["bg"])

        self.engine = NaturalLanguageFilterEngine()
        self.handler = PcapHandler(preview_count=PREVIEW_COUNT)
        self.packets: list = []
        self.packet_index: dict = {}
        self.pcap_path: Path | None = None
        self.current_filter = ""
        self.current_result: PcapResult | None = None
        self._load_queue: "queue.Queue" = queue.Queue()
        self._busy = False
        self._history: list[str] = list(self.settings["history"])
        self._last_dir = self.settings["last_dir"]
        self._rows: list = []
        self._row_texts: list[str] = []
        self._sort_column: str | None = None
        self._sort_reverse = False
        self._search_text = ""
        self._current_view = "packets"
        self._last_details_window = None

        self._build_ui()
        self._apply_columns(self.settings.get("columns") or {})
        self.stats_scope.set(self.settings.get("stats_scope", "Все пакеты"))
        self._set_status("Откройте файл .pcap или .pcapng, затем опишите трафик словами.")
        self.bind("<Control-o>", lambda event: self._open_file())
        self.bind("<Control-t>", lambda event: self._follow_selected_stream())
        self.bind("<Control-l>", lambda event: self._toggle_theme())
        self.bind("<Control-f>", self._focus_search)
        self.bind("<F1>", lambda event: self._show_help())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Построение интерфейса
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=0, minsize=SIDEBAR_WIDTH)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()

    # -- боковая панель -------------------------------------------------
    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, fg_color=THEME["panel"], corner_radius=0, width=SIDEBAR_WIDTH
        )
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(0, weight=1)

        # Панель прокручивается: на ноутбучных 768 px по высоте иначе
        # обрезались нижние карточки и переключатель темы.
        self.sidebar_scroll = ctk.CTkScrollableFrame(
            sidebar,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=THEME["border"],
            scrollbar_button_hover_color=THEME["accent_hover"],
        )
        self.sidebar_scroll.grid(row=0, column=0, sticky="nsew")
        self.sidebar_scroll.grid_columnconfigure(0, weight=1)

        content = self.sidebar_scroll

        brand = ctk.CTkFrame(content, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 10))
        ctk.CTkLabel(
            brand,
            text=APP_TITLE,
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=THEME["text"],
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand,
            text=APP_SUBTITLE,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=THEME["muted"],
            anchor="w",
            wraplength=300,
            justify="left",
        ).pack(anchor="w", pady=(3, 0))

        self._build_file_card(content, row=1)
        self._build_command_card(content, row=2)
        self._build_quick_card(content, row=3)
        self._build_examples_card(content, row=4)
        self._build_history_card(content, row=5)

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.grid(row=1, column=0, sticky="ew", padx=18, pady=(6, 14))
        footer.grid_columnconfigure(0, weight=1)

        self.theme_switch = ctk.CTkSwitch(
            footer,
            text="Светлая тема",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=THEME["muted"],
            progress_color=THEME["accent"],
            button_color=THEME["text"],
            button_hover_color=THEME["accent_hover"],
            command=self._toggle_theme,
        )
        self.theme_switch.grid(row=0, column=0, sticky="w")
        if self.theme_name == "light":
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()

    def _card(self, parent) -> ctk.CTkFrame:
        """Карточка с рамкой — общий вид блоков боковой панели."""
        return ctk.CTkFrame(
            parent,
            fg_color=THEME["card"],
            corner_radius=12,
            border_width=1,
            border_color=THEME["border"],
        )

    def _card_title(self, card, text: str) -> ctk.CTkLabel:
        label = ctk.CTkLabel(
            card,
            text=text,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=THEME["muted"],
            anchor="w",
        )
        label.pack(anchor="w", padx=14, pady=(12, 2))
        return label

    def _build_file_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "ФАЙЛ")

        self.file_label = ctk.CTkLabel(
            card,
            text="Файл не выбран",
            anchor="w",
            justify="left",
            wraplength=280,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=THEME["text"],
        )
        self.file_label.pack(anchor="w", padx=14, pady=(0, 2))

        self.packet_label = ctk.CTkLabel(
            card,
            text="",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=THEME["muted"],
        )
        self.packet_label.pack(anchor="w", padx=14, pady=(0, 10))

        ctk.CTkButton(
            card,
            text="Открыть файл   Ctrl+O",
            height=36,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            text_color=THEME["accent_text"],
            command=self._open_file,
        ).pack(fill="x", padx=14, pady=(0, 6))

        ctk.CTkButton(
            card,
            text="или открыть пример дампа",
            height=26,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent",
            hover_color=THEME["button_hover"],
            text_color=THEME["accent"],
            command=self._load_sample,
        ).pack(fill="x", padx=14, pady=(0, 12))

    def _build_command_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "КОМАНДА")

        self.command_entry = ctk.CTkEntry(
            card,
            height=38,
            placeholder_text="покажи http трафик с айпи 10.0.0.5",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=THEME["panel"],
            border_color=THEME["border"],
            text_color=THEME["text"],
        )
        self.command_entry.pack(fill="x", padx=14, pady=(0, 4))
        self.command_entry.bind("<Return>", self._apply_command)
        self.command_entry.bind("<KeyRelease>", self._on_command_key)
        self.command_entry.bind("<Escape>", self._clear_command)

        # Живая расшифровка: что программа поняла из введённых слов.
        self.hint_label = ctk.CTkLabel(
            card,
            text="Наберите команду — покажу, какой фильтр получится.",
            anchor="w",
            justify="left",
            wraplength=280,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=THEME["muted"],
        )
        self.hint_label.pack(fill="x", padx=14, pady=(0, 8))

        ctk.CTkButton(
            card,
            text="Применить   Enter",
            height=34,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            text_color=THEME["accent_text"],
            command=self._apply_command,
        ).pack(fill="x", padx=14, pady=(0, 14))

    def _on_command_key(self, event=None) -> None:
        """Показывает подсказку; стёрли команду — возвращает все пакеты."""
        self._update_command_hint()
        if not self.command_entry.get().strip():
            self._reset_filter()

    def _clear_command(self, event=None) -> None:
        """Esc: очистить ввод и вернуться ко всем пакетам."""
        self.command_entry.delete(0, "end")
        self._update_command_hint()
        self._reset_filter()

    def _reset_filter(self) -> None:
        """Снимает фильтр: в таблицу возвращаются все пакеты файла."""
        if not self.packets:
            return

        if not self.current_filter:
            # Фильтра и не было — просто напоминаем, что показано всё.
            return

        self.current_filter = ""
        self._set_filter_text("")
        limit = table_limit(len(self.packets))
        self._render(self.handler.apply(self.packets, "", limit=limit))
        self._refresh_stats()
        shown = len(self._rows)
        if shown < len(self.packets):
            self._set_status(
                "Фильтр снят: показаны первые {} из {} пакетов.".format(
                    format_count(shown), format_count(len(self.packets))
                )
            )
        else:
            self._set_status(
                "Фильтр снят: показаны все пакеты файла ({}).".format(
                    format_count(len(self.packets))
                )
            )

    def _update_command_hint(self, event=None) -> None:
        """Показывает пользователю, что понято из команды, ещё до Enter."""
        text = self.command_entry.get().strip()
        if not text:
            self.hint_label.configure(
                text="Наберите команду — покажу, какой фильтр получится.",
                text_color=THEME["muted"],
            )
            return

        query = self.engine.parse(text)
        if query.intent == "help":
            self.hint_label.configure(
                text="Открою справку по Enter.", text_color=THEME["accent"]
            )
            return

        filter_string = generate_filter(query)
        reason = self._why_not_understood(text)

        if reason:
            self.hint_label.configure(text=reason, text_color=THEME["danger"])
        elif filter_string:
            self.hint_label.configure(
                text="→ {}".format(filter_string), text_color=THEME["accent"]
            )
        else:
            self.hint_label.configure(
                text="Не нашёл адрес, порт, мак или протокол. "
                     "Пример: «http трафик с айпи 10.0.0.5».",
                text_color=THEME["danger"],
            )

    @staticmethod
    def _why_not_understood(text: str) -> str:
        """Объясняет причину, а не просто «не понял»."""
        for match in re.finditer(r"\d{1,3}(?:\.\d{1,3}){3}", text):
            address = match.group()
            if any(int(part) > 255 for part in address.split(".")):
                return "Адрес {} некорректен: каждый октет 0–255.".format(address)

        for token in re.split(r"[\s,;()]+", text):
            candidate = token.strip(".,;!?«»\"'")
            if candidate.count(":") < 2:
                continue
            if is_valid_mac_address(candidate):
                continue
            if not is_valid_ipv6(candidate):
                return "Адрес {} похож на IPv6, но записан с ошибкой.".format(candidate)

        for match in re.finditer(r"\b\d{1,5}\b", text):
            value = int(match.group())
            if not 1 <= value <= 65535:
                return "Порт {} вне диапазона 1–65535.".format(value)

        return ""

    def _build_quick_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "БЫСТРЫЕ ФИЛЬТРЫ")

        grid = ctk.CTkFrame(card, fg_color="transparent")
        grid.pack(fill="x", padx=10, pady=(4, 12))
        for column in range(3):
            grid.grid_columnconfigure(column, weight=1)

        for index, (label, command) in enumerate(QUICK_FILTERS):
            button = ctk.CTkButton(
                grid,
                text=label,
                height=26,
                width=70,
                font=ctk.CTkFont(family="Segoe UI", size=11),
                fg_color=THEME["button"],
                hover_color=THEME["button_hover"],
                text_color=THEME["text"],
                command=lambda cmd=command: self._run_quick_filter(cmd),
            )
            button.grid(
                row=index // 3, column=index % 3, padx=3, pady=3, sticky="ew"
            )

    def _build_examples_card(self, parent, row: int) -> None:
        """Готовые команды: клик подставляет текст, менять нужно только адрес."""
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=14, pady=(12, 2))
        ctk.CTkLabel(
            head,
            text="ПРИМЕРЫ",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=THEME["muted"],
            anchor="w",
        ).pack(side="left")
        ctk.CTkButton(
            head,
            text="другие ⟳",
            width=70,
            height=20,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            fg_color="transparent",
            hover_color=THEME["button_hover"],
            text_color=THEME["accent"],
            command=self._shuffle_examples,
        ).pack(side="right")

        self.examples_frame = ctk.CTkFrame(card, fg_color="transparent")
        self.examples_frame.pack(fill="x", padx=10, pady=(0, 12))
        self.examples_frame.grid_columnconfigure(0, weight=1)
        self._shuffle_examples(first=True)

    def _shuffle_examples(self, first: bool = False) -> None:
        for child in self.examples_frame.winfo_children():
            child.destroy()

        if first:
            self._examples_pool = list(EXAMPLE_COMMANDS)
            self._examples_shown = self._examples_pool[:EXAMPLES_VISIBLE]
            self._examples_offset = EXAMPLES_VISIBLE
        else:
            self._examples_offset += EXAMPLES_VISIBLE
            pool = EXAMPLE_COMMANDS
            start = self._examples_offset % len(pool)
            self._examples_shown = [
                pool[(start + index) % len(pool)]
                for index in range(EXAMPLES_VISIBLE)
            ]

        for index, command in enumerate(self._examples_shown):
            button = ctk.CTkButton(
                self.examples_frame,
                text=command,
                height=26,
                anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                fg_color="transparent",
                hover_color=THEME["button_hover"],
                text_color=THEME["text"],
                command=lambda cmd=command: self._use_example(cmd),
            )
            button.grid(row=index, column=0, sticky="ew", padx=2, pady=1)

    def _use_example(self, command: str) -> None:
        """Подставляет пример и выделяет то, что пользователю нужно заменить."""
        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, command)
        self.command_entry.focus_set()

        start, end = self._variable_span(command)
        if start is not None:
            self.command_entry.select_range(start, end)
            self.command_entry.icursor(end)

        self._update_command_hint()

    @staticmethod
    def _variable_span(command: str):
        """Границы адреса или порта в примере — их и выделяем."""
        match = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", command)
        if match:
            return match.span()
        match = re.search(r"aa:bb:cc:dd:ee:ff", command)
        if match:
            return match.span()
        match = re.search(r"\b\d{1,5}\b", command)
        if match:
            return match.span()
        return None, None

    def _build_history_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "ИСТОРИЯ")

        self.history_frame = ctk.CTkScrollableFrame(
            card,
            fg_color="transparent",
            height=150,
            scrollbar_button_color=THEME["button"],
            scrollbar_button_hover_color=THEME["button_hover"],
        )
        self.history_frame.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        self.history_frame.grid_columnconfigure(0, weight=1)
        self._rebuild_history()

    # -- основная область -----------------------------------------------
    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        self._build_toolbar(main, row=0)
        self._build_tabbar(main, row=1)

        content = ctk.CTkFrame(main, fg_color="transparent")
        content.grid(row=2, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self.content = content

        self.packets_view = ctk.CTkFrame(content, fg_color="transparent")
        self.packets_view.grid(row=0, column=0, sticky="nsew")
        self.packets_view.grid_columnconfigure(0, weight=1)
        self.packets_view.grid_rowconfigure(2, weight=1)

        self.stats_view = ctk.CTkFrame(content, fg_color="transparent")
        self.stats_view.grid(row=0, column=0, sticky="nsew")
        self.stats_view.grid_columnconfigure(0, weight=1)
        self.stats_view.grid_rowconfigure(2, weight=1)
        self.stats_view.grid_remove()

        self._build_verdict(self.packets_view, row=0)
        self._build_search(self.packets_view, row=1)
        self._build_table(self.packets_view, row=2)
        self._build_stats(self.stats_view)
        self._build_status(main, row=3)

    def _secondary_button(self, parent, text: str, command, width: int = 128):
        return ctk.CTkButton(
            parent,
            text=text,
            width=width,
            height=34,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=THEME["button"],
            hover_color=THEME["button_hover"],
            text_color=THEME["text"],
            command=command,
        )

    def _build_toolbar(self, parent, row: int) -> None:
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=row, column=0, sticky="ew", padx=16, pady=(16, 8))
        bar.grid_columnconfigure(0, weight=1)

        self.filter_entry = ctk.CTkEntry(
            bar,
            height=34,
            font=ctk.CTkFont(family="Consolas", size=13),
            state="readonly",
            fg_color=THEME["panel"],
            border_color=THEME["border"],
            text_color=THEME["accent"],
            placeholder_text="здесь появится фильтр Wireshark",
        )
        self.filter_entry.grid(row=0, column=0, sticky="ew")

        self._secondary_button(bar, "Копировать", self._copy_filter, width=112).grid(
            row=0, column=1, padx=(8, 0)
        )
        self._secondary_button(bar, "Показать все", self._show_all).grid(
            row=0, column=2, padx=(8, 0)
        )
        self._secondary_button(bar, "Поток TCP", self._follow_selected_stream).grid(
            row=0, column=3, padx=(8, 0)
        )
        self._secondary_button(bar, "Экспорт CSV", self._export_csv).grid(
            row=0, column=4, padx=(8, 0)
        )
        self._secondary_button(bar, "Справка", self._show_help, width=92).grid(
            row=0, column=5, padx=(8, 0)
        )
        self._secondary_button(bar, "Сброс фильтра", self._clear_command, width=120).grid(
            row=0, column=6, padx=(8, 0)
        )

    def _build_tabbar(self, parent, row: int) -> None:
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 6))
        bar.grid_columnconfigure(1, weight=1)

        self.view_switch = ctk.CTkSegmentedButton(
            bar,
            values=["Пакеты", "Статистика"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=THEME["accent"],
            selected_hover_color=THEME["accent_hover"],
            text_color=THEME["text"],
            fg_color=THEME["button"],
            command=self._switch_view,
        )
        self.view_switch.set("Пакеты")
        self.view_switch.grid(row=0, column=0, sticky="w")

    # -- вердикт по файлу ------------------------------------------------
    def _build_verdict(self, parent, row: int) -> None:
        panel = ctk.CTkFrame(
            parent,
            fg_color=THEME["card"],
            corner_radius=12,
            border_width=1,
            border_color=THEME["border"],
        )
        panel.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 8))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_remove()
        self.verdict_panel = panel

        head = ctk.CTkFrame(panel, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 0))
        head.grid_columnconfigure(1, weight=1)

        self.verdict_dot = ctk.CTkLabel(
            head,
            text="●",
            width=12,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=THEME["accent"],
        )
        self.verdict_dot.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self.verdict_title = ctk.CTkLabel(
            head,
            text="",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=THEME["text"],
        )
        self.verdict_title.grid(row=0, column=1, sticky="w")

        ctk.CTkButton(
            head,
            text="Подробнее",
            width=110,
            height=26,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=THEME["button"],
            hover_color=THEME["button_hover"],
            text_color=THEME["text"],
            command=self._show_verdict_window,
        ).grid(row=0, column=2, sticky="e")

        self.verdict_overview = ctk.CTkLabel(
            panel,
            text="",
            anchor="w",
            justify="left",
            wraplength=980,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=THEME["muted"],
        )
        self.verdict_overview.grid(row=1, column=0, sticky="ew", padx=14, pady=(4, 6))

        self.verdict_findings = ctk.CTkFrame(panel, fg_color="transparent")
        self.verdict_findings.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 10))
        self.verdict_findings.grid_columnconfigure(1, weight=1)

    def _render_verdict(self, verdict) -> None:
        """Показывает короткий вывод словами и кнопки «показать»."""
        self.verdict = verdict
        self.verdict_panel.grid()

        colors = {
            "critical": THEME["danger"],
            "warning": "#ffb86b",
            "info": THEME["accent"],
        }
        self.verdict_dot.configure(
            text_color=colors.get(verdict.worst_severity, THEME["accent"])
        )
        self.verdict_title.configure(text=verdict.headline)
        self.verdict_overview.configure(text=verdict.overview)

        for child in self.verdict_findings.winfo_children():
            child.destroy()

        for index, finding in enumerate(verdict.findings[:VERDICT_FINDINGS]):
            row = ctk.CTkFrame(self.verdict_findings, fg_color="transparent")
            row.grid(row=index, column=0, columnspan=2, sticky="ew", pady=1)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(
                row,
                text="•",
                width=14,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=colors.get(finding.severity, THEME["muted"]),
            ).grid(row=0, column=0, sticky="nw")

            ctk.CTkLabel(
                row,
                text="{} — {}".format(finding.title, finding.detail),
                anchor="w",
                justify="left",
                wraplength=880,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=THEME["text"],
            ).grid(row=0, column=1, sticky="w")

            if finding.command:
                ctk.CTkButton(
                    row,
                    text="Показать",
                    width=96,
                    height=24,
                    font=ctk.CTkFont(family="Segoe UI", size=11),
                    fg_color=THEME["button"],
                    hover_color=THEME["button_hover"],
                    text_color=THEME["accent"],
                    command=lambda cmd=finding.command: self._run_quick_filter(cmd),
                ).grid(row=0, column=2, sticky="e", padx=(8, 0))

        hidden = len(verdict.findings) - VERDICT_FINDINGS
        if hidden > 0:
            ctk.CTkLabel(
                self.verdict_findings,
                text="… и ещё {} — откройте «Подробнее»".format(hidden),
                anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=THEME["muted"],
            ).grid(row=VERDICT_FINDINGS, column=0, columnspan=2, sticky="w", pady=(4, 0))

    def _refresh_verdict(self) -> None:
        if not self.packets:
            return
        self._render_verdict(build_verdict(self.packets))

    def _show_verdict_window(self) -> None:
        verdict = getattr(self, "verdict", None)
        if verdict is None:
            self._set_status("Вердикт появится после загрузки файла.")
            return

        window = ctk.CTkToplevel(self)
        window.title("Вердикт по файлу")
        window.geometry("780x600")
        window.transient(self)
        window.configure(fg_color=THEME["bg"])

        textbox = ctk.CTkTextbox(
            window,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            wrap="word",
            fg_color=THEME["panel"],
            border_color=THEME["border"],
            border_width=1,
            text_color=THEME["text"],
        )
        textbox.pack(fill="both", expand=True, padx=14, pady=12)
        textbox.insert("1.0", format_verdict(verdict))
        textbox.configure(state="disabled")

        def copy_text() -> None:
            window.clipboard_clear()
            window.clipboard_append(format_verdict(verdict))
            self._set_status("Вердикт скопирован в буфер обмена.")

        ctk.CTkButton(
            window,
            text="Копировать",
            width=130,
            height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            text_color=THEME["accent_text"],
            command=copy_text,
        ).pack(pady=(0, 12))

        window.verdict_textbox = textbox
        window.after(50, window.lift)

    def _build_search(self, parent, row: int) -> None:
        """Строка поиска по видимым строкам таблицы (Ctrl+F)."""
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 6))
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            bar,
            text="ПОИСК",
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            text_color=THEME["muted"],
        ).grid(row=0, column=0, padx=(2, 8))

        self.search_entry = ctk.CTkEntry(
            bar,
            height=30,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=THEME["panel"],
            border_color=THEME["border"],
            text_color=THEME["text"],
            placeholder_text="Ctrl+F: адрес, порт, протокол или текст из колонки Info",
        )
        self.search_entry.grid(row=0, column=1, sticky="ew")
        self.search_entry.bind("<KeyRelease>", self._apply_search)
        self.search_entry.bind("<Return>", self._apply_search)
        self.search_entry.bind("<Escape>", self._clear_search)

        self.search_label = ctk.CTkLabel(
            bar,
            text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=THEME["muted"],
            width=90,
        )
        self.search_label.grid(row=0, column=2, padx=(8, 0))

        self._secondary_button(bar, "Сбросить", self._clear_search, width=96).grid(
            row=0, column=3, padx=(8, 0)
        )

    def _build_table(self, parent, row: int = 0) -> None:
        container = ctk.CTkFrame(
            parent,
            fg_color=THEME["panel"],
            corner_radius=12,
            border_width=1,
            border_color=THEME["border"],
        )
        container.grid(row=row, column=0, sticky="nsew", padx=16, pady=(0, 8))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)
        self.table_container = container

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Smart.Treeview",
            background=THEME["row"],
            fieldbackground=THEME["row"],
            foreground=THEME["text"],
            rowheight=27,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Smart.Treeview.Heading",
            background=THEME["head"],
            foreground=THEME["muted"],
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Smart.Treeview.Heading",
            background=[("active", THEME["button_hover"])],
            foreground=[("active", THEME["text"])],
        )
        style.map(
            "Smart.Treeview",
            background=[("selected", THEME["accent"])],
            foreground=[("selected", THEME["accent_text"])],
        )

        self.tree = ttk.Treeview(
            container,
            columns=COLUMNS,
            show="headings",
            style="Smart.Treeview",
            selectmode="browse",
        )
        for column in COLUMNS:
            anchor = COLUMN_ANCHORS.get(column, "w")
            self.tree.heading(
                column,
                text=column,
                anchor=anchor,
                command=lambda col=column: self._on_heading_click(col),
            )
            self.tree.column(
                column,
                width=COLUMN_WIDTHS.get(column, 120),
                anchor=anchor,
                stretch=(column == "Info"),
            )

        for protocol, (even, odd) in PROTOCOL_TINTS.items():
            self.tree.tag_configure("{}_even".format(protocol), background=even)
            self.tree.tag_configure("{}_odd".format(protocol), background=odd)
        self.tree.tag_configure("other_even", background=THEME["row_alt"])
        self.tree.tag_configure("other_odd", background=THEME["row"])

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)

        y_scroll = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        y_scroll.grid(row=0, column=1, sticky="ns", pady=10, padx=(0, 6))
        self.tree.configure(yscrollcommand=y_scroll.set)

        self.tree.bind("<Double-1>", self._show_packet_details)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Control-c>", self._copy_selected_row)

        self._build_empty_state(container)

        self._context_menu = tk.Menu(
            self,
            tearoff=0,
            bg=THEME["card"],
            fg=THEME["text"],
            activebackground=THEME["accent"],
            activeforeground=THEME["accent_text"],
            borderwidth=0,
        )
        self._context_menu.add_command(
            label="Детали пакета (двойной клик)", command=self._show_packet_details
        )
        self._context_menu.add_command(
            label="Поток TCP (Ctrl+T)", command=self._follow_selected_stream
        )
        self._context_menu.add_command(
            label="Копировать строку (Ctrl+C)", command=self._copy_selected_row
        )

    def _build_empty_state(self, container) -> None:
        """Подсказка вместо пустой таблицы, пока файл не открыт."""
        frame = ctk.CTkFrame(
            container,
            fg_color=THEME["panel"],
            corner_radius=0,
        )
        frame.grid(row=0, column=0, columnspan=2, sticky="nsew")

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            inner,
            text="Начните с файла",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=THEME["text"],
        ).pack(pady=(0, 10))

        steps = [
            ("1", "Откройте .pcap или .pcapng — кнопка слева или Ctrl+O"),
            ("2", "Напишите команду обычными словами в поле «Команда»"),
            ("3", "Нажмите Enter — фильтр и таблица появятся сами"),
        ]
        for number, text in steps:
            line = ctk.CTkFrame(inner, fg_color="transparent")
            line.pack(anchor="w", pady=3)
            ctk.CTkLabel(
                line,
                text=number,
                width=24,
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                text_color=THEME["accent"],
            ).pack(side="left")
            ctk.CTkLabel(
                line,
                text=text,
                font=ctk.CTkFont(family="Segoe UI", size=13),
                text_color=THEME["muted"],
            ).pack(side="left")

        ctk.CTkLabel(
            inner,
            text="Например: «покажи http трафик с айпи 192.168.1.10»",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=THEME["muted"],
        ).pack(pady=(14, 0))

        ctk.CTkButton(
            inner,
            text="Открыть пример дампа",
            width=200,
            height=34,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=THEME["button"],
            hover_color=THEME["button_hover"],
            text_color=THEME["text"],
            command=self._load_sample,
        ).pack(pady=(12, 0))

        self.empty_state = frame

    # -- статистика ------------------------------------------------------
    def _build_stats(self, parent) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(0, 6))
        header.grid_columnconfigure(0, weight=1)

        self.stats_summary_label = ctk.CTkLabel(
            header,
            text="Статистика появится после загрузки файла.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=THEME["muted"],
            anchor="w",
        )
        self.stats_summary_label.grid(row=0, column=0, sticky="w")

        self.stats_scope = ctk.CTkSegmentedButton(
            header,
            values=["Все пакеты", "Найденные"],
            font=ctk.CTkFont(family="Segoe UI", size=11),
            selected_color=THEME["accent"],
            selected_hover_color=THEME["accent_hover"],
            text_color=THEME["text"],
            fg_color=THEME["button"],
            command=lambda value: self._refresh_stats(),
        )
        self.stats_scope.set("Все пакеты")
        self.stats_scope.grid(row=0, column=1, padx=(8, 0))

        self._secondary_button(
            header, "Обновить", self._refresh_stats, width=100
        ).grid(row=0, column=2, padx=(8, 0))

        body = ctk.CTkFrame(parent, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 8))
        body.grid_columnconfigure(0, weight=2, uniform="stats")
        body.grid_columnconfigure(1, weight=3, uniform="stats")
        body.grid_rowconfigure(1, weight=1)

        chart_panel = self._panel(body, "ГРАФИК ТРАФИКА")
        chart_panel.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        chart_panel.grid_columnconfigure(0, weight=1)

        self.chart_metric = ctk.CTkSegmentedButton(
            chart_panel,
            values=["Байты", "Пакеты"],
            font=ctk.CTkFont(family="Segoe UI", size=10),
            selected_color=THEME["accent"],
            selected_hover_color=THEME["accent_hover"],
            text_color=THEME["text"],
            fg_color=THEME["button"],
            command=lambda value: self._refresh_chart(),
        )
        self.chart_metric.set("Байты")
        self.chart_metric.grid(row=0, column=1, sticky="e", padx=(0, 10), pady=(8, 0))

        self.chart = TrafficChart(chart_panel, height=150)
        self.chart.set_theme(THEME)
        self.chart.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(0, weight=2, uniform="left")
        left.grid_rowconfigure(1, weight=2, uniform="left")

        proto_panel = self._panel(left, "ИЕРАРХИЯ ПРОТОКОЛОВ")
        proto_panel.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        self.proto_tree = self._stats_tree(
            proto_panel,
            columns=("packets", "bytes", "share"),
            headings=("Пакеты", "Байты", "Доля"),
            widths=(80, 90, 70),
            show="tree headings",
            tree_width=180,
        )

        host_panel = self._panel(left, "САЙТЫ И ХОСТЫ")
        host_panel.grid(row=1, column=0, sticky="nsew")
        self.host_tree = self._stats_tree(
            host_panel,
            columns=("packets", "bytes", "source"),
            headings=("Пакеты", "Байты", "Источник"),
            widths=(70, 80, 70),
            show="tree headings",
            tree_width=170,
        )

        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=1, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=3, uniform="right")
        right.grid_rowconfigure(1, weight=2, uniform="right")

        conv_panel = self._panel(right, "РАЗГОВОРЫ")
        conv_panel.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        self.conv_tree = self._stats_tree(
            conv_panel,
            columns=("packets", "bytes"),
            headings=("Пакеты", "Байты"),
            widths=(90, 100),
            show="tree headings",
            tree_width=280,
        )

        endpoint_panel = self._panel(right, "УЗЛЫ")
        endpoint_panel.grid(row=1, column=0, sticky="nsew")
        self.endpoint_tree = self._stats_tree(
            endpoint_panel,
            columns=("sent", "received", "bytes"),
            headings=("Отправлено", "Получено", "Всего"),
            widths=(100, 100, 100),
            show="tree headings",
            tree_width=180,
        )

    def _panel(self, parent, title: str) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(
            parent,
            fg_color=THEME["panel"],
            corner_radius=12,
            border_width=1,
            border_color=THEME["border"],
        )
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            panel,
            text=title,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=THEME["muted"],
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 2))
        return panel

    def _stats_tree(self, panel, columns, headings, widths, show, tree_width):
        tree = ttk.Treeview(
            panel,
            columns=columns,
            show=show,
            style="Smart.Treeview",
            selectmode="browse",
        )
        if show.startswith("tree"):
            tree.heading("#0", text="", anchor="w")
            tree.column("#0", width=tree_width, anchor="w")
        for name, heading, width in zip(columns, headings, widths):
            tree.heading(name, text=heading, anchor="e")
            tree.column(name, width=width, anchor="e", stretch=True)
        tree.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        return tree

    def _build_status(self, parent, row: int) -> None:
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 14))
        bar.grid_columnconfigure(1, weight=1)

        self.status_dot = ctk.CTkLabel(
            bar,
            text="●",
            width=12,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=THEME["accent"],
        )
        self.status_dot.grid(row=0, column=0, padx=(0, 6), sticky="w")

        self.status_label = ctk.CTkLabel(
            bar,
            text="",
            anchor="w",
            justify="left",
            wraplength=880,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=THEME["muted"],
        )
        self.status_label.grid(row=0, column=1, sticky="ew")

    # ------------------------------------------------------------------
    # Вкладки
    # ------------------------------------------------------------------
    def _switch_view(self, value: str) -> None:
        self._show_view("stats" if value == "Статистика" else "packets")

    def _show_view(self, name: str) -> None:
        self._current_view = name
        if name == "stats":
            self.packets_view.grid_remove()
            self.stats_view.grid()
            self._refresh_stats()
        else:
            self.stats_view.grid_remove()
            self.packets_view.grid()

    # ------------------------------------------------------------------
    # Статистика: расчёт и отрисовка
    # ------------------------------------------------------------------
    def _stats_scope_packets(self) -> list:
        if not self.packets:
            return []
        if self.stats_scope.get() == "Найденные" and self.current_filter:
            try:
                predicate = compile_filter(self.current_filter)
            except (FilterError, Exception):        # noqa: B014
                return self.packets
            return [packet for packet in self.packets if predicate(packet)]
        return self.packets

    def _refresh_chart(self) -> None:
        """Перерисовывает график по текущей области статистики."""
        packets = self._stats_scope_packets()
        metric = "packets" if self.chart_metric.get() == "Пакеты" else "bytes"
        self.chart.set_theme(THEME)
        self.chart.set_data(timeline(packets), metric, THEME)

    def _refresh_stats(self) -> None:
        packets = self._stats_scope_packets()
        self._refresh_chart()

        for tree in (self.proto_tree, self.host_tree, self.conv_tree, self.endpoint_tree):
            tree.delete(*tree.get_children())

        if not packets:
            self.stats_summary_label.configure(
                text="Пока нечего считать: откройте файл или ослабьте фильтр."
            )
            return

        data = summary(packets)
        self.stats_summary_label.configure(text=(
            "Пакетов {} · {} · длительность {} · узлов {} · протоколов {}".format(
                data["packets"],
                format_bytes(data["bytes"]),
                format_duration(data["duration"]),
                data["addresses"],
                data["protocols"],
            )
        ))

        parents: dict[str, str] = {}
        for row in protocol_hierarchy(packets):
            values = (row.packets, format_bytes(row.bytes), "{:.1f}%".format(row.share))
            if row.level == 0:
                node = self.proto_tree.insert("", "end", text=row.name, values=values)
                if row.name != "Всего":
                    parents[row.name] = node
            else:
                self.proto_tree.insert(
                    parents.get(row.parent, ""), "end", text=row.name, values=values
                )

        for host in hosts(packets, limit=40):
            self.host_tree.insert(
                "",
                "end",
                text=host.name,
                values=(host.packets, format_bytes(host.bytes), host.source),
            )

        for conversation in conversations(packets, limit=40):
            self.conv_tree.insert(
                "",
                "end",
                text="{}  ↔  {}".format(conversation.endpoint_a, conversation.endpoint_b),
                values=(conversation.total_packets, format_bytes(conversation.total_bytes)),
            )

        for node in endpoints(packets, limit=40):
            self.endpoint_tree.insert(
                "",
                "end",
                text=node.address,
                values=(
                    node.packets_sent,
                    node.packets_received,
                    format_bytes(node.total_bytes),
                ),
            )

    # ------------------------------------------------------------------
    # Работа с файлом
    # ------------------------------------------------------------------
    def _open_file(self) -> None:
        if self._busy:
            return

        path = filedialog.askopenfilename(
            title="Открыть файл захвата",
            initialdir=self._last_dir or None,
            filetypes=[
                ("Файлы захвата", "*.pcap *.pcapng *.cap"),
                ("Все файлы", "*.*"),
            ],
        )
        if not path:
            return

        self._load_path(Path(path))

    def _load_path(self, path: Path) -> None:
        """Читает файл в фоне — общая точка для диалога и кнопки «пример»."""
        self._last_dir = str(path.parent)
        self._set_busy(True)
        self._set_status("Читаю файл, это может занять несколько секунд...")
        threading.Thread(target=self._load_worker, args=(path,), daemon=True).start()
        self.after(100, self._poll_load)

    def _load_sample(self) -> None:
        """Открывает встроенный пример дампа — посмотреть, как всё работает."""
        if self._busy:
            return

        sample = PROJECT_ROOT / "tests" / "sample_traffic.pcap"
        if not sample.exists():
            self._set_status("Файл примера не найден рядом с приложением.")
            return

        self._load_path(sample)

    def _load_worker(self, path: Path) -> None:
        # Тело TCP нужно для «Поток TCP» и hex в деталях, но на большом файле
        # это лишние гигабайты памяти — тогда читаем без него.
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        keep_payload = size <= MAX_PAYLOAD_FILE
        packets, error = self.handler.load(path, keep_payload=keep_payload)
        self._load_queue.put((path, packets, error))

    def _poll_load(self) -> None:
        try:
            path, packets, error = self._load_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_load)
            return

        self._set_busy(False)

        if error:
            self._set_status("Не удалось прочитать файл: {}".format(error))
            messagebox.showerror(APP_TITLE, "Не удалось прочитать файл:\n\n{}".format(error))
            return

        self.pcap_path = path
        self.packets = packets
        self.packet_index = {packet.number: packet for packet in packets}
        self.current_filter = ""
        self._set_filter_text("")
        self.file_label.configure(text=path.name)
        self.packet_label.configure(text="{} пакетов · {}".format(
            len(packets), path.suffix))

        if hasattr(self, "empty_state"):
            self.empty_state.grid_remove()

        self._set_status("Читаю {} пакетов...".format(format_count(len(packets))))
        limit = table_limit(len(packets))
        self._render(self.handler.apply(packets, "", limit=limit))
        self._refresh_verdict()
        self._refresh_stats()

        try:
            big = path.stat().st_size > MAX_PAYLOAD_FILE
        except OSError:
            big = False

        shown = len(self._rows)
        status = "Файл загружен: {} пакетов.".format(format_count(len(packets)))
        if shown < len(packets):
            status += (
                " В таблице первые {} — нажмите «Показать все» или задайте "
                "фильтр.".format(format_count(shown))
            )
        else:
            status += " Показаны все. Введите команду, например: «покажи http трафик»."
        if big:
            status += (" Файл большой — тела TCP подгружаются по требованию, "
                       "когда открываете поток.")
        self._set_status(status)

    # ------------------------------------------------------------------
    # Команды и фильтры
    # ------------------------------------------------------------------
    def _apply_command(self, event=None) -> None:
        if self._busy:
            return

        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        command = self.command_entry.get().strip()
        if not command:
            self._reset_filter()
            self._set_status(
                "Поле команды пустое — показаны все пакеты. "
                "Введите команду, например: \"покажи пакеты на порт 80\"."
            )
            return

        query = self.engine.parse(command)
        if query.intent == "help":
            self._show_help()
            return

        filter_string = generate_filter(query)
        if not filter_string:
            self._set_status(
                "Не нашёл сетевых индикаторов в команде. Укажите IP, порт, MAC "
                "или протокол: например \"покажи dns трафик\"."
            )
            return

        self._push_history(command)
        self.current_filter = filter_string
        self._set_filter_text(filter_string)

        limit = table_limit(len(self.packets))
        result = self.handler.apply(self.packets, filter_string, limit=limit)
        if result.error:
            self._set_status("Ошибка фильтра: {}".format(result.error))
            return

        self._render(result)
        self._refresh_stats()

        if result.matched_packets == 0:
            self._set_status(
                "По фильтру \"{}\" ничего не найдено. Проверьте адрес или порт.".format(
                    filter_string
                )
            )
        elif result.matched_packets > len(result.rows):
            self._set_status(
                "Найдено {} из {} пакетов, в таблице первые {}. "
                "Нажмите \"Показать все\", чтобы увидеть остальные.".format(
                    format_count(result.matched_packets),
                    format_count(result.total_packets),
                    format_count(len(result.rows)),
                )
            )
        else:
            self._set_status(
                "Найдено {} из {} пакетов. Фильтр: {}.".format(
                    format_count(result.matched_packets),
                    format_count(result.total_packets),
                    filter_string,
                )
            )

    def _run_quick_filter(self, command: str) -> None:
        """Кнопка-чип: подставляет готовую команду и применяет её."""
        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, command)
        self._apply_command()

    def _push_history(self, command: str) -> None:
        if not command:
            return
        if command in self._history:
            self._history.remove(command)
        self._history.insert(0, command)
        del self._history[HISTORY_LIMIT:]
        self._rebuild_history()

    def _rebuild_history(self) -> None:
        for child in self.history_frame.winfo_children():
            child.destroy()

        if not self._history:
            ctk.CTkLabel(
                self.history_frame,
                text="Здесь появятся выполненные команды.",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=THEME["muted"],
                anchor="w",
                justify="left",
                wraplength=250,
            ).grid(row=0, column=0, sticky="w", padx=6, pady=6)
            return

        for index, command in enumerate(self._history):
            button = ctk.CTkButton(
                self.history_frame,
                text=command,
                height=28,
                anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                fg_color="transparent",
                hover_color=THEME["button_hover"],
                text_color=THEME["text"],
                command=lambda cmd=command: self._run_quick_filter(cmd),
            )
            button.grid(row=index, column=0, sticky="ew", padx=2, pady=1)

    def _show_all(self) -> None:
        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        filter_string = self.current_filter
        result = self.handler.apply(self.packets, filter_string, limit=-1)
        if result.error:
            self._set_status("Ошибка фильтра: {}".format(result.error))
            return

        self._render(result)
        if filter_string:
            self._set_status(
                "Показаны все совпадения: {} из {} пакетов. Фильтр: {}.".format(
                    result.matched_packets, result.total_packets, filter_string
                )
            )
        else:
            self._set_status("Показаны все пакеты в файле: {}.".format(result.total_packets))

    def _export_csv(self) -> None:
        if not self.packets:
            self._set_status("Нечего экспортировать: сначала откройте файл.")
            return

        # Экспортируем весь результат фильтра (не только первые 5 000 строк
        # превью), и если включён поиск — только совпавшие строки. Иначе
        # «нашёл 12 строк» и «в файле 200» — неприятный сюрприз.
        result = self.handler.apply(self.packets, self.current_filter, limit=-1)
        if result.error:
            self._set_status("Ошибка фильтра: {}".format(result.error))
            return

        rows = result.rows
        if self._search_text:
            needle = self._search_text.lower()
            rows = [row for row in rows if needle in self._row_text(row).lower()]

        if not rows:
            self._set_status("Нет строк для экспорта.")
            return

        default_name = "smartpcap_result.csv"
        if self.pcap_path is not None:
            default_name = "{}_result.csv".format(self.pcap_path.stem)

        path = filedialog.asksaveasfilename(
            title="Сохранить результат",
            defaultextension=".csv",
            initialfile=default_name,
            initialdir=self._last_dir or None,
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            self.handler.export_rows_to_csv(rows, path)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, "Не удалось сохранить файл:\n\n{}".format(exc))
            return

        if self._search_text:
            self._set_status(
                "Сохранено {} строк (поиск «{}»): {}".format(
                    format_count(len(rows)), self._search_text, path
                )
            )
        else:
            self._set_status(
                "Сохранено {} строк: {}".format(format_count(len(rows)), path)
            )

    # ------------------------------------------------------------------
    # Отрисовка и сортировка
    # ------------------------------------------------------------------
    def _render(self, result: PcapResult) -> None:
        self.current_result = result
        self._rows = list(result.rows)
        # Текст строки для поиска считаем один раз: иначе каждая буква
        # в поле поиска пересобирает все колонки всех строк.
        self._row_texts = [self._row_text(row).lower() for row in self._rows]
        self._reset_search()
        self._fill_table()

    # ------------------------------------------------------------------
    # Поиск по видимым строкам
    # ------------------------------------------------------------------
    ROW_TEXT_FIELDS = ("frame", "time", "protocol", "source", "src_port",
                       "destination", "dst_port", "length", "info")

    def _row_text(self, row) -> str:
        return " ".join(str(getattr(row, field, "")) for field in self.ROW_TEXT_FIELDS)

    def _reset_search(self) -> None:
        """Новый фильтр или новый файл — поиск начинается с чистого листа."""
        self._search_text = ""
        entry = getattr(self, "search_entry", None)
        if entry is not None:
            entry.delete(0, "end")
        label = getattr(self, "search_label", None)
        if label is not None:
            label.configure(text="")

    def _apply_search(self, event=None) -> None:
        if not getattr(self, "search_entry", None):
            return
        text = self.search_entry.get().strip()
        self._search_text = text
        self._fill_table()

        shown = len(self.tree.get_children())
        total = len(self._rows)
        if text:
            self.search_label.configure(
                text="{} из {}".format(shown, total),
                text_color=THEME["accent"] if shown else THEME["danger"],
            )
            self._set_status(
                "Поиск «{}»: {} совпадений из {} строк. Esc — снять поиск.".format(
                    text, shown, total
                )
            )
        else:
            self.search_label.configure(text="")
            self._fill_table()
            self._set_status("Поиск снят: показаны все строки текущего фильтра.")

    def _clear_search(self, event=None) -> None:
        if not getattr(self, "search_entry", None):
            return
        self._reset_search()
        self._fill_table()
        self._set_status("Поиск снят: показаны все строки текущего фильтра.")
        return "break"

    def _focus_search(self, event=None) -> None:
        entry = getattr(self, "search_entry", None)
        if entry is None:
            return
        entry.focus_set()
        entry.select_range(0, "end")
        return "break"

    def _fill_table(self) -> None:
        self.tree.delete(*self.tree.get_children())

        for index, row in enumerate(self._sorted_rows()):
            transport = (row.protocol or "").upper()
            tag = transport if transport in PROTOCOL_TINTS else "other"
            tags = ("{}_odd".format(tag) if index % 2 else "{}_even".format(tag),)
            self.tree.insert("", "end", values=(
                row.frame,
                row.time,
                row.protocol,
                row.source,
                row.src_port,
                row.destination,
                row.dst_port,
                row.length,
                row.info,
            ), tags=tags)

    def _sorted_rows(self) -> list:
        rows = self._rows
        texts = getattr(self, "_row_texts", None)
        needle = getattr(self, "_search_text", "").lower()
        if needle:
            if texts is None or len(texts) != len(rows):
                texts = [self._row_text(row).lower() for row in rows]
                self._row_texts = texts
            rows = [row for row, text in zip(rows, texts) if needle in text]

        if not self._sort_column:
            return rows

        attribute, kind = SORT_KEYS[self._sort_column]

        def sort_key(row):
            value = getattr(row, attribute, "")
            if kind == "int":
                text = str(value).strip()
                return int(text) if text.isdigit() else -1
            if kind == "float":
                try:
                    return float(value)
                except (TypeError, ValueError):
                    return 0.0
            return str(value).lower()

        return sorted(rows, key=sort_key, reverse=self._sort_reverse)

    def _on_heading_click(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False

        self._update_headings()
        self._fill_table()

    def _update_headings(self) -> None:
        for name in COLUMNS:
            anchor = COLUMN_ANCHORS.get(name, "w")
            text = name
            if name == self._sort_column:
                text = "{} {}".format(name, "▼" if self._sort_reverse else "▲")
            self.tree.heading(name, text=text, anchor=anchor)

    def _set_filter_text(self, text: str) -> None:
        self.filter_entry.configure(state="normal")
        self.filter_entry.delete(0, "end")
        if text:
            self.filter_entry.insert(0, text)
        self.filter_entry.configure(state="readonly")

    def _copy_filter(self) -> None:
        if not self.current_filter:
            self._set_status("Фильтр пока пуст: выполните команду.")
            return

        self.clipboard_clear()
        self.clipboard_append(self.current_filter)
        self._set_status("Фильтр скопирован в буфер обмена: {}".format(self.current_filter))

    def _copy_selected_row(self, event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        text = "\t".join(str(value) for value in values)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Строка скопирована в буфер обмена.")

    # ------------------------------------------------------------------
    # Детали пакета
    # ------------------------------------------------------------------
    def _selected_frame(self) -> int | None:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        if not values:
            return None
        try:
            return int(values[0])
        except (TypeError, ValueError):
            return None

    def _show_packet_details(self, event=None) -> None:
        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        if event is not None:
            row_id = self.tree.identify_row(event.y)
            if not row_id:
                return
            self.tree.selection_set(row_id)
            self.tree.focus(row_id)

        frame = self._selected_frame()
        if frame is None:
            self._set_status(
                "Выберите пакет в таблице, затем нажмите «Детали пакета»."
            )
            return

        packet = self.packet_index.get(frame)
        if packet is None:
            self._set_status("Пакет {} не найден в загруженном файле.".format(frame))
            return

        window = ctk.CTkToplevel(self)
        window.title("Пакет {} — детали".format(frame))
        window.geometry("820x680")
        window.minsize(640, 460)
        window.transient(self)
        window.configure(fg_color=THEME["bg"])

        header = ctk.CTkLabel(
            window,
            text="Кадр {} · {} · {} байт · {}".format(
                packet.number,
                packet.protocol or "?",
                packet.length,
                format_bytes(packet.length),
            ),
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=THEME["text"],
            anchor="w",
        )
        header.pack(fill="x", padx=14, pady=(12, 2))

        ctk.CTkLabel(
            window,
            text="{}  →  {}   ({})".format(
                self._endpoint_text(packet, source=True),
                self._endpoint_text(packet, source=False),
                packet.app or packet.protocol or "?",
            ),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=THEME["muted"],
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 8))

        fields = ttk.Treeview(
            window,
            columns=("value",),
            show="tree headings",
            style="Smart.Treeview",
            selectmode="browse",
        )
        fields.heading("#0", text="Слой / поле", anchor="w")
        fields.heading("value", text="Значение", anchor="w")
        fields.column("#0", width=260, anchor="w")
        fields.column("value", width=460, anchor="w", stretch=True)
        fields.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        def add_layer(name: str, pairs) -> None:
            parent = fields.insert("", "end", text=name, open=True)
            for field, value in pairs:
                if value is None or value == "":
                    continue
                fields.insert(parent, "end", text=field, values=(value,))

        add_layer("Frame", [
            ("Номер кадра", packet.number),
            ("Время, с", "{:.6f}".format(packet.timestamp)),
            ("Длина, байт", packet.length),
            ("Длина в сети, байт", packet.wire_length),
            ("Пакетов в файле", len(self.packets)),
        ])
        add_layer("Ethernet", [
            ("MAC отправителя", packet.src_mac),
            ("MAC получателя", packet.dst_mac),
        ])
        add_layer("IP", [
            ("Адрес отправителя", packet.src_ip),
            ("Адрес получателя", packet.dst_ip),
            ("TTL / Hop limit", packet.ttl or None),
            ("Длина IP-пакета", packet.ip_len or None),
        ])

        if packet.protocol == "TCP":
            add_layer("TCP", [
                ("Порт отправителя", packet.src_port),
                ("Порт получателя", packet.dst_port),
                ("Sequence number", packet.seq),
                ("Acknowledgment", packet.tcp_ack or None),
                ("Окно", packet.tcp_window or None),
                ("Флаги", decode_tcp_flags(packet.tcp_flags)),
                ("Флаги, hex", "0x{:03x}".format(packet.tcp_flags)),
                ("Данные, байт", len(packet.payload)),
                ("Приложение", packet.app),
            ])
        elif packet.protocol == "UDP":
            add_layer("UDP", [
                ("Порт отправителя", packet.src_port),
                ("Порт получателя", packet.dst_port),
                ("Длина UDP", packet.udp_len or None),
                ("Приложение", packet.app),
            ])

        add_layer("Имена", [
            ("Сайт (HTTP Host)", packet.host),
            ("Сервер (TLS SNI)", packet.sni),
            ("Домен (DNS)", packet.dns_name),
            ("Путь запроса", packet.http_uri),
        ])

        add_layer("Приложение", [("Info", packet.info)])

        payload_label = ctk.CTkLabel(
            window,
            text="Данные (hex-дамп)",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=THEME["muted"],
            anchor="w",
        )
        payload_label.pack(fill="x", padx=14)

        payload_box = ctk.CTkTextbox(
            window,
            height=170,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="none",
            fg_color=THEME["panel"],
            border_color=THEME["border"],
            border_width=1,
            text_color=THEME["mono"],
        )
        payload_box.pack(fill="x", padx=14, pady=(4, 12))

        if packet.payload:
            data = packet.payload[:HEX_LIMIT]
            payload_box.insert("1.0", hex_dump(data))
            if len(packet.payload) > HEX_LIMIT:
                payload_box.insert(
                    "end",
                    "\n\n… показаны первые {} КБ из {}".format(
                        HEX_LIMIT // 1024, format_bytes(len(packet.payload))
                    ),
                )
        else:
            payload_box.insert(
                "1.0",
                "Нет данных: у пакета нет полезной нагрузки или это не TCP.\n"
                "Тело TCP сохраняется при открытии файла, поэтому обычно\n"
                "здесь виден запрос или ответ.",
            )
        payload_box.configure(state="disabled")

        def close_window() -> None:
            window.withdraw()
            window.after(150, window.destroy)

        window.protocol("WM_DELETE_WINDOW", close_window)
        window.after(50, window.lift)
        window.after(100, window.focus_force)

        self._last_details_window = window
        window.field_tree = fields
        window.payload_box = payload_box

    @staticmethod
    def _endpoint_text(packet, source: bool = True) -> str:
        address = packet.src_ip if source else packet.dst_ip
        port = packet.src_port if source else packet.dst_port
        if not address:
            address = packet.src_mac if source else packet.dst_mac
        if port is None:
            return address or "?"
        return "{}:{}".format(address or "?", port)

    # ------------------------------------------------------------------
    # Поток TCP (Follow TCP stream)
    # ------------------------------------------------------------------
    def _show_context_menu(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        self.tree.focus(row)

        menu = self._context_menu
        menu.delete(0, "end")
        menu.add_command(
            label="Детали пакета (двойной клик)", command=self._show_packet_details
        )
        menu.add_command(
            label="Поток TCP (Ctrl+T)", command=self._follow_selected_stream
        )

        values = self.tree.item(row, "values")
        if values:
            source, src_port, destination, dst_port = (
                values[3], values[4], values[5], values[6]
            )
            protocol = values[2]

            menu.add_separator()
            if source and source != "?":
                menu.add_command(
                    label="Только от {}".format(source),
                    command=lambda value=source: self._filter_by("src", value),
                )
            if destination and destination != "?":
                menu.add_command(
                    label="Только к {}".format(destination),
                    command=lambda value=destination: self._filter_by("dst", value),
                )
            if source and source != "?" and source != destination:
                menu.add_command(
                    label="Фильтр по адресу {}".format(source),
                    command=lambda value=source: self._filter_by("addr", value),
                )
            ports = [port for port in (src_port, dst_port) if port]
            for port in dict.fromkeys(ports):
                menu.add_command(
                    label="Только порт {}".format(port),
                    command=lambda value=port: self._filter_by("port", value),
                )
            if protocol:
                menu.add_command(
                    label="Только {}".format(protocol),
                    command=lambda value=protocol: self._filter_by("proto", value),
                )

        menu.add_separator()
        menu.add_command(
            label="Копировать строку (Ctrl+C)", command=self._copy_selected_row
        )

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _filter_by(self, kind: str, value: str) -> None:
        """Готовит команду из значения ячейки — без набора текста руками."""
        value = str(value).strip()
        if not value:
            return

        mac_like = bool(
            re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", value)
            or re.fullmatch(r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}", value)
        )

        if kind == "src":
            command = (
                "покажи пакеты с мак адресом {}".format(value) if mac_like
                else "покажи пакеты от {}".format(value)
            )
        elif kind == "dst":
            command = (
                "покажи пакеты с мак адресом {}".format(value) if mac_like
                else "покажи пакеты к {}".format(value)
            )
        elif kind == "addr":
            command = (
                "покажи пакеты с мак адресом {}".format(value) if mac_like
                else "покажи пакеты с айпи {}".format(value)
            )
        elif kind == "port":
            command = "покажи пакеты на порт {}".format(value)
        elif kind == "proto":
            command = "покажи {} трафик".format(value.lower())
        else:
            return

        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, command)
        self._update_command_hint()
        self._apply_command()

    def _load_stream_payloads(self, frame: int, kind: str = "tcp") -> None:
        """Дочитывает тела только для выбранного соединения."""
        if self.pcap_path is None:
            return

        frames = conversation_frames(self.packets, frame, kind=kind)
        if not frames:
            return

        # Если данные уже есть (файл небольшой) — ничего не делаем.
        for number in frames:
            packet = self.packet_index.get(number)
            if packet is not None and packet.payload:
                return

        self._set_status(
            "Подгружаю данные потока из файла ({} кадров)...".format(len(frames))
        )
        self.update_idletasks()

        payloads = read_payloads(
            self.pcap_path, frames, max_bytes=STREAM_PAYLOAD_LIMIT
        )
        for number, data in payloads.items():
            packet = self.packet_index.get(number)
            if packet is not None:
                packet.payload = data

        loaded = sum(len(data) for data in payloads.values())
        if loaded >= STREAM_PAYLOAD_LIMIT:
            self._set_status(
                "Поток большой: показаны первые {} данных.".format(
                    format_bytes(STREAM_PAYLOAD_LIMIT)
                )
            )

    def _follow_selected_stream(self) -> None:
        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        frame = self._selected_frame()
        if frame is None:
            self._set_status(
                "Выберите TCP- или UDP-пакет в таблице, затем нажмите "
                "«Поток TCP» или Ctrl+T."
            )
            return

        target = self.packet_index.get(frame)

        stream = follow_stream(self.packets, frame)
        if stream is None:
            if target is not None and target.transport == "UDP":
                # «Поток» для UDP: датаграммы в порядке захвата.
                self._load_stream_payloads(frame, kind="udp")
                stream = follow_datagram_flow(self.packets, frame)
                if stream is None:
                    self._set_status(
                        "Пакет {} — UDP, но обмен для него не собрался.".format(frame)
                    )
                    return
            else:
                self._set_status(
                    "Пакет {} — не TCP и не UDP, поток для него не "
                    "собирается.".format(frame)
                )
                return

        if stream.total_bytes == 0:
            # Заголовки уже в памяти, а тела не хранились (большой файл):
            # дочитываем только кадры этого соединения.
            self._load_stream_payloads(
                frame, kind="udp" if getattr(stream, "kind", "TCP") == "UDP" else "tcp"
            )
            if getattr(stream, "kind", "TCP") == "UDP":
                stream = follow_datagram_flow(self.packets, frame) or stream
            else:
                stream = follow_stream(self.packets, frame) or stream

        if stream.total_bytes == 0:
            self._set_status(
                "В потоке {} <-> {} нет данных: только служебные пакеты "
                "(SYN/FIN/RST) или данные не попали в захват.".format(
                    format_endpoint(stream.client),
                    format_endpoint(stream.server),
                )
            )
            return

        self._set_status(summarize(stream))
        self._open_stream_window(stream)

    def _open_stream_window(self, stream) -> None:
        kind = getattr(stream, "kind", "TCP")
        window = ctk.CTkToplevel(self)
        window.title(
            "Поток {}: {} <-> {}".format(
                kind,
                format_endpoint(stream.client),
                format_endpoint(stream.server),
            )
        )
        window.geometry("1020x700")
        window.minsize(720, 480)
        window.transient(self)
        window.configure(fg_color=THEME["bg"])

        header = ctk.CTkLabel(
            window,
            text=(
                "Пакетов {} · длительность {:.3f} с · клиент -> сервер {} байт · "
                "сервер -> клиент {} байт"
            ).format(
                len(stream.packets),
                stream.duration,
                stream.client_to_server.stream.length,
                stream.server_to_client.stream.length,
            ),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=THEME["muted"],
            anchor="w",
        )
        header.pack(fill="x", padx=14, pady=(12, 4))

        controls = ctk.CTkFrame(
            window,
            fg_color=THEME["panel"],
            corner_radius=10,
            border_width=1,
            border_color=THEME["border"],
        )
        controls.pack(fill="x", padx=14, pady=6)

        view_switch = ctk.CTkSegmentedButton(
            controls,
            values=["Оба", "Клиент → сервер", "Сервер → клиент"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=THEME["accent"],
            selected_hover_color=THEME["accent_hover"],
            text_color=THEME["text"],
            fg_color=THEME["button"],
        )
        view_switch.set("Оба")
        view_switch.grid(row=0, column=0, padx=(12, 8), pady=8, sticky="w")

        mode_switch = ctk.CTkSegmentedButton(
            controls,
            values=["Текст", "HEX"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=THEME["accent"],
            selected_hover_color=THEME["accent_hover"],
            text_color=THEME["text"],
            fg_color=THEME["button"],
        )
        mode_switch.set("Текст")
        mode_switch.grid(row=0, column=1, padx=(8, 12), pady=8, sticky="w")

        textbox = ctk.CTkTextbox(
            window,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
            fg_color=THEME["panel"],
            border_color=THEME["border"],
            border_width=1,
            text_color=THEME["text"],
        )
        textbox.pack(fill="both", expand=True, padx=14, pady=6)

        buttons = ctk.CTkFrame(window, fg_color="transparent")
        buttons.pack(fill="x", padx=14, pady=(0, 12))

        def current_view() -> str:
            value = view_switch.get()
            if value.startswith("Клиент"):
                return VIEW_CLIENT
            if value.startswith("Сервер"):
                return VIEW_SERVER
            return VIEW_BOTH

        def current_mode() -> str:
            return MODE_HEX if mode_switch.get() == "HEX" else MODE_TEXT

        def render(*_args) -> None:
            text = render_stream(stream, view=current_view(), mode=current_mode())
            textbox.configure(state="normal")
            textbox.delete("1.0", "end")
            textbox.insert("1.0", text)
            textbox.configure(state="disabled")

        def copy_text() -> None:
            window.clipboard_clear()
            window.clipboard_append(textbox.get("1.0", "end-1c"))
            copy_button.configure(text="Скопировано")
            window.after(1500, lambda: copy_button.configure(text="Копировать"))

        def save_text() -> None:
            stem = "stream_{}_{}".format(
                _safe_stem(format_endpoint(stream.client)),
                _safe_stem(format_endpoint(stream.server)),
            )
            path = filedialog.asksaveasfilename(
                parent=window,
                title="Сохранить поток",
                defaultextension=".txt",
                initialfile="{}.txt".format(stem),
                filetypes=[("Текст", "*.txt"), ("Все файлы", "*.*")],
            )
            if not path:
                return
            try:
                Path(path).write_text(
                    textbox.get("1.0", "end-1c"), encoding="utf-8"
                )
            except OSError as exc:
                messagebox.showerror(
                    APP_TITLE,
                    "Не удалось сохранить файл:\n\n{}".format(exc),
                    parent=window,
                )
                return
            self._set_status("Поток сохранён: {}".format(path))

        copy_button = ctk.CTkButton(
            buttons,
            text="Копировать",
            width=130,
            height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            text_color=THEME["accent_text"],
            command=copy_text,
        )
        copy_button.pack(side="left")

        self._secondary_button(
            buttons, "Сохранить в файл", save_text, width=150
        ).pack(side="left", padx=8)

        view_switch.configure(command=render)
        mode_switch.configure(command=render)
        render()

        # Ссылки для тестов и для отладки из консоли.
        window.stream_textbox = textbox
        window.stream_view_switch = view_switch
        window.stream_mode_switch = mode_switch
        window.stream_render = render

        def close_window() -> None:
            # Отложенное закрытие: отложенные callbacks customtkinter успевают
            # отработать на живом окне, иначе Tk ругается в stderr.
            window.withdraw()
            window.after(150, window.destroy)

        window.protocol("WM_DELETE_WINDOW", close_window)

        window.after(50, window.lift)
        window.after(100, window.focus_force)

    # ------------------------------------------------------------------
    # Настройки: сохранение и восстановление
    # ------------------------------------------------------------------
    def _collect_columns(self) -> dict:
        """Текущая ширина колонок таблицы — чтобы не настраивать заново."""
        try:
            widths = {"#0": int(self.tree.column("#0", "width"))}
            for column in self.tree["columns"]:
                widths[str(column)] = int(self.tree.column(column, "width"))
            return widths
        except Exception:                             # noqa: BLE001
            return {}

    def _apply_columns(self, widths: dict) -> None:
        for name, width in (widths or {}).items():
            try:
                self.tree.column(name, width=int(width))
            except Exception:                         # noqa: BLE001
                continue

    def _current_settings(self) -> dict:
        return {
            "theme": self.theme_name,
            "geometry": self.geometry(),
            "history": list(self._history),
            "last_dir": self._last_dir,
            "columns": self._collect_columns(),
            "stats_scope": self.stats_scope.get(),
        }

    def _on_close(self) -> None:
        """Сохраняет настройки и закрывает окно."""
        try:
            save_settings(self._current_settings())
        finally:
            self.destroy()

    # ------------------------------------------------------------------
    # Тема
    # ------------------------------------------------------------------
    def _toggle_theme(self) -> None:
        target = "light" if self.theme_name == "dark" else "dark"
        self._set_theme(target)

    def _set_theme(self, name: str) -> None:
        global THEME, PROTOCOL_TINTS

        self.theme_name = name
        THEME = dict(LIGHT_THEME if name == "light" else DARK_THEME)
        PROTOCOL_TINTS = TINTS[name]
        ctk.set_appearance_mode("light" if name == "light" else "dark")

        # Полная перестройка: проще и надёжнее, чем красить каждый виджет.
        self.after(10, self._rebuild_ui)

    def _capture_state(self) -> dict:
        return {
            "file_text": self.file_label.cget("text"),
            "packets_text": self.packet_label.cget("text"),
            "empty_visible": bool(self.empty_state.winfo_ismapped()),
            "command_text": self.command_entry.get(),
            "filter_text": self.current_filter,
            "status_text": self.status_label.cget("text"),
            "rows": list(self._rows),
            "history": list(self._history),
            "sort_column": self._sort_column,
            "sort_reverse": self._sort_reverse,
            "view": self._current_view,
            "verdict_visible": bool(self.verdict_panel.winfo_ismapped()),
            "scope": self.stats_scope.get(),
            "chart_metric": self.chart_metric.get(),
            "columns": self._collect_columns(),
        }

    def _rebuild_ui(self) -> None:
        state = self._capture_state()

        for child in self.winfo_children():
            child.destroy()

        self.configure(fg_color=THEME["bg"])
        self._build_ui()
        self._restore_state(state)

    def _restore_state(self, state: dict) -> None:
        self.file_label.configure(text=state["file_text"])
        self.packet_label.configure(text=state["packets_text"])
        self.command_entry.delete(0, "end")
        if state["command_text"]:
            self.command_entry.insert(0, state["command_text"])
        self._set_filter_text(state["filter_text"])
        self.command_entry.bind("<Return>", self._apply_command)
        self.command_entry.bind("<KeyRelease>", self._on_command_key)
        self.command_entry.bind("<Escape>", self._clear_command)
        self._update_command_hint()

        self._history = state["history"]
        self._rebuild_history()

        self._sort_column = state["sort_column"]
        self._sort_reverse = state["sort_reverse"]
        self._search_text = ""
        self._apply_columns(state.get("columns") or {})
        self._update_headings()

        self._fill_table()

        self.stats_scope.set(state["scope"])
        self.chart_metric.set(state.get("chart_metric", "Байты"))
        self._refresh_stats()
        self._refresh_verdict()

        if state["empty_visible"]:
            self.empty_state.grid()
        else:
            self.empty_state.grid_remove()

        if state["view"] == "stats":
            self.view_switch.set("Статистика")
            self._show_view("stats")
        else:
            self.view_switch.set("Пакеты")
            self._show_view("packets")

        self._set_status(state["status_text"])
        self.bind("<Control-o>", lambda event: self._open_file())
        self.bind("<Control-t>", lambda event: self._follow_selected_stream())
        self.bind("<Control-l>", lambda event: self._toggle_theme())
        self.bind("<F1>", lambda event: self._show_help())

    # ------------------------------------------------------------------
    # Прочее
    # ------------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.configure(cursor="watch" if busy else "")
        self.status_dot.configure(
            text_color=THEME["muted"] if busy else THEME["accent"]
        )

    def _show_help(self) -> None:
        window = ctk.CTkToplevel(self)
        window.title("Как пользоваться — Smart PCAP Parser")
        window.geometry("860x740")
        window.transient(self)
        window.configure(fg_color=THEME["bg"])

        header = ctk.CTkFrame(window, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            header,
            text="Справка",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=THEME["text"],
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            header,
            text="Три шага, команды, колонки, статистика, детали и клавиши.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=THEME["muted"],
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))

        textbox = ctk.CTkTextbox(
            window,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
            fg_color=THEME["panel"],
            border_color=THEME["border"],
            border_width=1,
            text_color=THEME["text"],
        )
        textbox.pack(fill="both", expand=True, padx=16, pady=12)
        textbox.insert("1.0", HELP_TEXT)
        textbox.configure(state="disabled")

        window.after(50, window.lift)
        window.after(100, window.focus_force)


def main() -> None:
    app = SmartPcapApp()
    app.mainloop()


if __name__ == "__main__":
    main()
