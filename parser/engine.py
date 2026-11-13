"""
Natural Language Filter Engine (RegEx-based).

Этап 1 проекта SmartPCAPParser.

Задачи:
1. Извлечение сетевых индикаторов (IP, порты, MAC-адреса, протоколы)
   из текстовой команды пользователя на русском/английском языке.
2. Определение намерения (intent) через словари синонимов.
3. Сборка объекта parsed_query для дальнейшего использования.

Архитектура:
- NATURAL_LANGUAGE_KEYWORDS — словари синонимов для действий, сущностей, протоколов.
- REGEX_PATTERNS — регулярные выражения для извлечения сырых значений.
- NaturalLanguageFilterEngine — основной класс-движок.
"""

import re
from dataclasses import dataclass, field

from .validators import (
    ValidationError,
    is_valid_mac_address,
    validate_ipv4,
    validate_ipv6,
    validate_mac_address,
    validate_port,
)

# ---------------------------------------------------------------------------
# Словари синонимов (Natural Language Keywords)
# ---------------------------------------------------------------------------
# Ключ — нормализованное намерение/сущность, значение — список слов-триггеров.
# Реализованы как списки, чтобы можно было легко расширять и добавлять новые
# синонимы, сленг, опечатки и транслитерацию.

# Глаголы-действия (определяют, ЧТО нужно сделать)
ACTIONS = {
    "show": ["покажи", "покажи мне", "покажи все", "покажите", "выведи", "выведи все",
             "выведите", "показать", "отображать", "вывести", "найди", "найдите",
             "найти", "посмотри", "посмотри на", "продемонстрируй",
             "показать все пакеты", "список пакетов", "отображение",
             "покажи мне все", "глянь", "глянуть", "дай", "что там", "что тут",
             "покажи список", "выведи список", "show", "find", "display", "list",
             # Разговорные варианты: «хочу увидеть», «интересует», «grep».
             "хочу увидеть", "хочу посмотреть", "хочу", "интересует", "интересуют",
             "ищу", "ищем", "нужен", "нужны", "нужна", "дай глянуть", "дай посмотреть",
             "показывай", "выводи", "отфильтруй", "покажи-ка", "глянь-ка", "что за",
             "есть ли", "видно ли", "покажи всё", "покажи все пакеты", "пакеты",
             "трафик", "grep", "search", "find all", "show all", "покажите мне"],
    "filter": ["фильтр", "отфильтровать", "отфильтруй", "фильтровать",
               "показать только", "только", "ограничь", "select", "filter",
               "оставь", "оставить только", "убери лишнее"],
    "help": ["помощь", "помоги", "подскажи", "что можно", "какие команды",
             "список команд", "примеры", "как работает", "справка", "help",
             "как пользоваться", "инструкция", "что ты умеешь", "команды",
             "что умеешь", "как искать", "подсказка", "хелп"],
}

# Типы сущностей (определяют, ЧТО ищем)
ENTITY_TYPES = {
    "ip": ["айпи", "ип", "ip", "адрес", "ip адрес", "ip-адрес", "ip адресс",
           "хост", "host", "src_ip", "dst_ip", "source ip", "dest ip",
           "айпишник", "ипишник", "айпи-адрес", "ип-адрес", "ipv4", "айпиви",
           "ip address", "адресок", "хост адрес", "айпи адрес", "адрес ip",
           "network address", "сетевой адрес", "узел", "машина", "устройство",
           "ipv6", "айпиви6", "ipv6 адрес"],
    "port": ["порт", "порты", "портов", "порта", "порту", "tcp порт", "udp порт",
             "номер порта", "портец", "service", "service port",
             "tcp port", "udp port", "tcp ports", "udp ports", "port number",
             "портик", "порты tcp", "порты udp", "по порту", "портом"],
    "mac": ["мак", "mac", "mac адрес", "mac-адрес", "hardware address",
            "hardware", "eth addr", "ethaddr", "physical address",
            "физический адрес", "mac address", "eth address",
            "мак-адрес", "мак адрес устройства", "аппаратный адрес",
            "физический мак", "mac-адрес устройства"],
    "protocol": ["протокол", "протоколы", "protocol", "type", "eth type",
                 "ethertype", "frame type", "тип трафика", "вид трафика",
                 "тип пакета", "протокол трафика", "по протоколу"],
}

# Контекстные предлоги/связки — слова, которые помогают определить направление
# (src vs dst) для IP-адресов и портов.
# Важно: "с" и "на" сюда не входят — в командах вида "пакеты с айпи 1.2.3.4"
# или "пакеты на порт 80" они не означают направление, а просто связку.
SRC_WORDS = {"от", "из", "со", "откуда", "исходит", "source", "src",
             "отправитель", "отправителя", "исходящий"}
DST_WORDS = {"к", "ко", "кому", "куда", "назначению", "серверу",
             "destination", "dst", "получатель", "получателя", "входящий"}

# Отрицание: «не http», «кроме 203.0.113.53», «без dns».
NEGATION_WORDS = {"не", "нет", "кроме", "исключая", "исключи", "исключить",
                  "убери", "убрать", "минус", "без", "not", "except",
                  "игнорируй", "игнорировать", "пропусти", "не считая",
                  "без учёта", "без учета", "исключением", "кромеш",
                  "не показывать", "скрыть", "скрой"}

# Слова-связки, которые могут стоять между отрицанием и значением:
# «не на порт 80», «кроме трафика к 203.0.113.53».
CONNECTOR_WORDS = {
    "на", "в", "во", "по", "про", "для", "через", "и", "или", "а", "но",
    "все", "всё", "пакеты", "пакет", "пакета", "трафик", "трафика", "данные",
    "только", "лишь", "мне", "нам", "там", "тут", "что", "это", "них",
    "пожалуйста", "плиз", "прошу", "будь", "добр", "будьте", "у", "кого",
    "чего", "который", "которая", "которые", "этот", "этого", "такой",
    "определённый", "определенный", "конкретный", "указанный", "весь", "вся",
    "сессия", "сеанс", "соединение", "запрос", "запросы", "ответ", "ответы",
}

# Слова, которые вводят имя сайта: «покажи сайт example.com».
HOST_WORDS = {"сайт", "сайта", "сайты", "сайтов", "сайте", "сайтом",
              "хост", "хоста", "хосты", "хостов", "домен", "домена",
              "домены", "доменов", "домене", "sni", "host", "hostname",
              "имя сайта", "имени сайта", "адрес сайта"}

# Доменное имя: минимум одна точка, латиница/цифры/дефис, кириллица тоже.
DOMAIN_RE = re.compile(
    r"(?<![\w.@-])([a-zа-я0-9][a-zа-я0-9\-]{0,62}"
    r"(?:\.[a-zа-я0-9][a-zа-я0-9\-]{0,62})+)(?![\w.@-])",
    re.IGNORECASE,
)

# Расширения файлов не считаем доменом: «сайт.pcap» — это файл.
FILE_EXTENSIONS = {"pcap", "pcapng", "cap", "csv", "txt", "py", "log",
                   "json", "xml", "html", "png", "jpg", "zip", "gz"}

# Начала имён полей Wireshark: «http.host» — поле, а не домен.
FIELD_PREFIXES = {"http", "tls", "dns", "tcp", "udp", "ip", "ipv6", "frame",
                  "eth", "icmp", "icmpv6", "arp", "tls.handshake"}

# Слова, которые стоят между предлогом и значением и не несут направления.
FILLER_WORDS = {
    "айпи", "ип", "ip", "адрес", "адреса", "адресс", "ip-адрес",
    "порт", "порта", "порту", "портов", "порты",
    "мак", "mac", "mac-адрес", "хост", "host", "tcp", "udp",
    "айпишник", "ипишник", "ipv4", "айпиви", "адресок", "номер",
    "ipv6", "icmp", "айпи адрес", "айпи-адрес", "портик", "портом",
    "устройство", "устройства", "машина", "машины", "узел", "узла",
    "сетевой", "сетевого", "сеть", "сети",
}

# Протоколы, которые можно использовать как фильтр по имени.
# Порядок важен: проверка идёт сверху вниз, поэтому "https" должен попадать
# в tls, а не в http.
PROTOCOL_FILTERS = {
    # Порядок важен: проверка идёт сверху вниз, побеждает первое совпадение.
    # Поэтому «https» стоит до «http», а «http/3» — до «http».
    "tls": ["tls", "ssl", "https", "зашифрованный", "шифрованный", "шифрование",
            "сертификат", "сертификаты", "хттпс", "тлс", "ссл", "secure sockets",
            "защищённое соединение", "защищенное соединение", "шифр",
            "https трафик", "защищённый трафик"],
    "quic": ["quic", "http/3", "http3", "куик", "квид", "быстрый http"],
    "http2": ["http2", "http/2", "h2", "http 2", "хттп2", "хттп 2"],
    "http": ["http", "веб", "веб-трафик", "web", "world wide web", "http/1.1",
             "хттп", "вебсайт", "сайт", "сайты", "страница",
             "веб-страница", "веб страница", "браузер", "веб-сервер", "веб сервер",
             "апач", "apache", "nginx", "интернет-трафик", "гипертекст"],
    "dns": ["dns", "днс", "domain name system", "доменное имя", "домен", "домены",
            "резолв", "resolve", "разрешение имён", "разрешение имен",
            "разрешение доменов", "имя сайта", "неймсервер", "nameserver",
            "dns-сервер", "днс сервер"],
    "icmp": ["icmp", "пинг", "ping", "echo", "эхо", "трассировка", "traceroute",
             "эхо-запрос", "недоступен", "unreachable"],
    "tcp": ["tcp", "тсп", "transmission control protocol", "tcp-соединение",
            "tcp соединение", "соединение", "сессия tcp"],
    "udp": ["udp", "юдп", "user datagram protocol", "датаграмма", "udp-пакет",
            "udp пакет"],
    "ipv6": ["ipv6", "ip6", "ip v6"],
    "ipv4": ["ipv4", "ip4", "ip v4"],
    "arp": ["arp", "address resolution protocol", "разрешение адресов",
            "кто имеет", "who has", "мак по ip", "arp-запрос"],
    "ssh": ["ssh", "сш", "secure shell", "удаленная консоль", "удалённая консоль",
            "ssh-сессия", "ssh сессия", "секьюр шелл", "ssh доступ"],
    "ftp": ["ftp", "фтп", "file transfer protocol", "передача файлов", "файлообмен",
            "файловый сервер", "ftp-сервер", "фтп сервер"],
    "smtp": ["smtp", "смпт", "email", "e-mail", "почта", "mail", "письма",
             "отправка почты", "исходящая почта", "почтовый сервер", "смтп"],
    "ntp": ["ntp", "network time protocol", "синхронизация времени", "время",
            "точное время", "часы", "синхронизация часов", "нтп"],
    "dhcp": ["dhcp", "динамический адрес", "выдача адресов", "автонастройка сети",
             "получение адреса", "аренда адреса", "dhcp-сервер", "дхцп"],
    "telnet": ["telnet", "телнет", "телнет-сессия"],
    "pop3": ["pop3", "поп3", "получение почты", "почтовый ящик pop3"],
    "imap": ["imap", "имап", "синхронизация почты", "почтовый ящик imap"],
    "ldap": ["ldap", "лдап", "каталог пользователей", "active directory",
             "служба каталогов", "домен каталога"],
    "smb": ["smb", "cifs", "сетевая папка", "общая папка", "шара", "samba",
            "самба", "общий ресурс", "файловая шара", "windows share",
            "сетевой диск smb"],
    "rdp": ["rdp", "удаленный рабочий стол", "удалённый рабочий стол",
            "терминальный доступ", "рдп", "удалённый стол", "mstsc",
            "терминальный сервер"],
    "mysql": ["mysql", "мускул", "майскул", "mariadb", "мариадб", "mysql сервер"],
    "mdns": ["mdns", "bonjour", "zeroconf", "бонжур", "принтер", "airplay",
             "chromecast", "локальные имена", "обнаружение устройств",
             "устройства в сети", "устройство в сети", "кто в сети",
             "список устройств", "соседи по сети"],
    # --- базы данных и службы, которые часто ищут на работе ---------------
    "mssql": ["mssql", "ms sql", "sql server", "микрософт sql", "microsoft sql"],
    "postgresql": ["postgresql", "postgres", "постгрес", "постгре", "пг"],
    "redis": ["redis", "редис", "кеш", "кэш"],
    "mongodb": ["mongodb", "монго", "mongo", "монгодб"],
    "memcached": ["memcached", "мемкеш", "мемкэш"],
    "nfs": ["nfs", "нфс", "сетевой диск", "nfs-сервер"],
    # --- голос, видео, устройства -----------------------------------------
    "sip": ["sip", "сип", "телефония", "ip-телефония", "ip телефония", "звонки",
            "voip", "воип", "sip-телефон"],
    "stun": ["stun", "стун", "webrtc", "видеозвонки", "видеосвязь"],
    "mqtt": ["mqtt", "мктт", "iot", "интернет вещей", "умный дом", "датчики"],
    "snmp": ["snmp", "снмп", "опрос устройств", "мониторинг оборудования",
             "мониторинг сети"],
    "tftp": ["tftp", "тфтп", "прошивка", "загрузка по сети"],
    "vnc": ["vnc", "внс", "удалённый экран", "удаленный экран", "удалённый доступ"],
    "kerberos": ["kerberos", "керберос", "билеты", "аутентификация домена",
                 "вход в домен"],
    "syslog": ["syslog", "сислог", "журнал событий", "логи", "логирование"],
    "openvpn": ["openvpn", "впн", "vpn", "туннель", "випиэн"],
    "socks": ["socks", "сокс", "прокси", "proxy", "socks5"],
    # --- служебные и локальные протоколы ----------------------------------
    "icmpv6": ["icmpv6", "icmp6", "icmp v6", "icmpv6 трафик", "ицмпв6"],
    "igmp": ["igmp", "игмп", "групповой трафик", "multicast"],
    "gre": ["gre", "gre туннель", "грэ туннель"],
    "esp": ["esp", "esp трафик", "инкапсуляция ipsec"],
    "ospf": ["ospf", "оспф", "маршрутизация ospf"],
    "ipsec": ["ipsec", "ипсек", "ike", "isakmp", "ikev2"],
    "l2tp": ["l2tp", "л2тп", "туннель l2tp"],
    "llmnr": ["llmnr", "ллмнр", "локальное разрешение имён"],
    "ssdp": ["ssdp", "ссдп", "обнаружение устройств", "upnp"],
    "dhcpv6": ["dhcpv6", "dhcp v6", "дхцпв6"],
    "radius": ["radius", "радиус", "авторизация radius", "802.1x"],
    "netbios": ["netbios", "нетбиос", "nbns", "имена windows"],
    "bgp": ["bgp", "бгп", "border gateway"],
    "xmpp": ["xmpp", "jabber", "джаббер"],
    "irc": ["irc", "ирц", "чат irc"],
}

# Собирательные фразы: одно слово — сразу несколько протоколов.
# «покажи базы данных» честнее, чем угадывать один mysql.
PROTOCOL_GROUPS = {
    "базы данных": ("mysql", "mssql", "postgresql", "mongodb", "redis", "memcached"),
    "база данных": ("mysql", "mssql", "postgresql", "mongodb", "redis", "memcached"),
    "субд": ("mysql", "mssql", "postgresql", "mongodb", "redis", "memcached"),
    "бд": ("mysql", "mssql", "postgresql", "mongodb", "redis", "memcached"),
    "database": ("mysql", "mssql", "postgresql", "mongodb", "redis", "memcached"),
    "почтовые протоколы": ("smtp", "pop3", "imap"),
    "почта": ("smtp", "pop3", "imap"),
    "почту": ("smtp", "pop3", "imap"),
    "почты": ("smtp", "pop3", "imap"),
    "удалённый доступ": ("rdp", "ssh", "vnc", "telnet"),
    "удаленный доступ": ("rdp", "ssh", "vnc", "telnet"),
    "удалённое администрирование": ("rdp", "ssh", "vnc", "telnet"),
    "удаленное администрирование": ("rdp", "ssh", "vnc", "telnet"),
    "remote access": ("rdp", "ssh", "vnc", "telnet"),
    "видеосвязь": ("sip", "stun"),
    "звонки": ("sip", "stun"),
    "телефония": ("sip", "stun"),
    "мониторинг": ("snmp", "syslog"),
    "файловые серверы": ("ftp", "smb", "nfs"),
    "файловый сервер": ("ftp", "smb", "nfs"),
    "сетевые папки": ("smb", "nfs"),
    "локальная сеть": ("arp", "llmnr", "netbios", "ssdp", "mdns"),
    "локальной сети": ("arp", "llmnr", "netbios", "ssdp", "mdns"),
    "локальную сеть": ("arp", "llmnr", "netbios", "ssdp", "mdns"),
    "локальные протоколы": ("arp", "llmnr", "netbios", "ssdp", "mdns", "dhcpv6"),
    "локальных протоколов": ("arp", "llmnr", "netbios", "ssdp", "mdns", "dhcpv6"),
    "туннели": ("openvpn", "l2tp", "ipsec", "gre"),
    "туннелей": ("openvpn", "l2tp", "ipsec", "gre"),
    "туннель": ("openvpn", "l2tp", "ipsec", "gre"),
    "маршрутизация": ("bgp", "ospf", "icmp", "igmp"),
    "маршрутизацию": ("bgp", "ospf", "icmp", "igmp"),
    "сайты": ("http", "tls", "dns"),
    "веб": ("http", "tls"),
    "web": ("http", "tls"),
}

# Слова протоколов — на них поиск отрицания останавливается, чтобы «не http
# и tcp» не превращалось в «не tcp».
PROTOCOL_WORDS: set[str] = set()
for _keywords in PROTOCOL_FILTERS.values():
    PROTOCOL_WORDS.update(keyword.lower() for keyword in _keywords)
PROTOCOL_WORDS.update(PROTOCOL_GROUPS)


# ---------------------------------------------------------------------------
# Сопоставление слов с учётом русских окончаний
# ---------------------------------------------------------------------------
# Пользователь пишет «телефонию», «почту», «шару», а в словаре слова стоят
# в именительном падеже. Точное сравнение такие формы пропускает, поэтому
# слова сравниваются по общему началу: «телефони» + «я/ю/ей» — одно и то же.
WORD_RE = re.compile(r"[a-zа-яё0-9]+", re.IGNORECASE)


def _tokenize_words(text: str) -> list[tuple[str, int]]:
    """Слова в нижнем регистре вместе с позицией в тексте."""
    return [(match.group(0).lower(), match.start()) for match in WORD_RE.finditer(text)]


CYRILLIC_RE = re.compile(r"[а-яё]")

# «Покажи всё», «покажи весь трафик»: не фильтр, а просьба показать файл
# целиком. Слова только эти — иначе любая непонятная фраза снимала бы фильтр.
SHOW_ALL_WORDS = {
    "покажи", "покажите", "показать", "показывай", "показывать",
    "все", "всё", "весь", "вся",
    "пакет", "пакета", "пакеты", "пакетов", "пакетами",
    "трафик", "трафика", "трафику", "трафиком",
    "данные", "данных", "файл", "файла", "файл", "целиком", "полностью",
}


def is_show_all(command: str) -> bool:
    """Команда просит показать весь файл, а не применить фильтр."""
    words = WORD_RE.findall((command or "").lower())
    return bool(words) and all(word in SHOW_ALL_WORDS for word in words)

# Фильтр Wireshark, набранный как есть: «tcp.port==443», «frame.len > 1000»,
# «ip.addr==10.88.0.1 and http». Пользователь, знающий Wireshark, вправе
# вставить такой фильтр в строку команды — его не нужно переводить словами.
DISPLAY_FIELD_RE = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+\b")
DISPLAY_OP_RE = re.compile(r"==|!=|>=|<=|>|<|\bcontains\b|\bmatches\b|\bin\b")


def looks_like_display_filter(text: str) -> str:
    """
    Возвращает фильтр Wireshark как есть, если текст — именно фильтр.

    Пустая строка означает «это обычная команда словами». Проверка нарочно
    строгая: нужен вид «поле.подполе» и оператор сравнения, иначе «example.com»
    или «покажи http» считались бы фильтром.
    """
    stripped = text.strip()
    if not stripped or CYRILLIC_RE.search(stripped):
        return ""

    if DISPLAY_FIELD_RE.search(stripped) and DISPLAY_OP_RE.search(stripped):
        return stripped

    # Одиночное поле без сравнения: «tcp.analysis.retransmission».
    if " " not in stripped and stripped.count(".") >= 2 and DISPLAY_FIELD_RE.fullmatch(stripped):
        return stripped

    return ""

# Окончания, на которые можно «нарастить» слово: «сайт» -> «сайта», «почта» -> «почты».
RU_ENDINGS = {
    "а", "я", "у", "ю", "ы", "и", "е", "о", "ь",
    "ом", "ем", "ой", "ей", "ов", "ев", "ам", "ям", "ах", "ях",
    "ами", "ями", "ью", "ия", "ии", "ию", "ий", "ая", "ее", "ые",
    "ых", "ым", "ого", "ему", "ыми", "ся", "сь", "ение", "ения",
    "ению", "ении", "ений", "ать", "ить", "ал", "ала", "ало", "али",
}
RU_VOWELS = set("аеёиоуыэюя")


def _word_matches(keyword_word: str, text_word: str) -> bool:
    """Совпадают ли слова с точностью до русского окончания.

    Правило узкое, чтобы не ловить «видел» как «видео»:
    - одно слово — начало другого, а «хвост» — известное окончание;
    - слова одной длины и различаются только последней гласной
      («почта»/«почту», «телефония»/«телефонию»).
    Латинские слова сравниваются только точно: «http» — не «https».
    """
    if keyword_word == text_word:
        return True
    if not keyword_word or not text_word:
        return False
    if not (CYRILLIC_RE.search(keyword_word) and CYRILLIC_RE.search(text_word)):
        return False

    shorter, longer = sorted((keyword_word, text_word), key=len)
    if len(shorter) < 4:
        return False

    if longer.startswith(shorter):
        return longer[len(shorter):] in RU_ENDINGS

    if len(keyword_word) == len(text_word) and keyword_word[:-1] == text_word[:-1]:
        return keyword_word[-1] in RU_VOWELS and text_word[-1] in RU_VOWELS

    return False


def _keyword_tokens(keyword: str) -> list[str]:
    return [word for word, _ in _tokenize_words(keyword)]


def _find_phrase(tokens: list[tuple[str, int]], phrase: list[str]) -> int | None:
    """Индекс первого слова фразы в тексте или None.

    Сравнение идёт по словам, поэтому «веб-трафик» находится и в «веб трафик»,
    а «телефония» — в «телефонию».
    """
    if not phrase or len(phrase) > len(tokens):
        return None
    for start in range(len(tokens) - len(phrase) + 1):
        if all(
            _word_matches(phrase[index], tokens[start + index][0])
            for index in range(len(phrase))
        ):
            return start
    return None


# Пары «протокол — фраза» и «группа — фразы» с заранее разобранными словами.
PROTOCOL_PHRASES: list[tuple[str, str, list[str]]] = [
    (proto, keyword, _keyword_tokens(keyword))
    for proto, keywords in PROTOCOL_FILTERS.items()
    for keyword in keywords
]
GROUP_PHRASES: list[tuple[str, tuple[str, ...], list[str]]] = [
    (phrase, names, _keyword_tokens(phrase))
    for phrase, names in PROTOCOL_GROUPS.items()
]


# ---------------------------------------------------------------------------
# Регулярные выражения для извлечения сырых значений
# ---------------------------------------------------------------------------
REGEX_PATTERNS = {
    "ipv4": re.compile(
        r"""(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9.])""",
        re.VERBOSE,
    ),
    # Порт или диапазон портов; список через запятую/«и».
    "port": re.compile(
        r"(?:ports?|порт(?:а|у|ы|ов|ам|ах|ом|е|ец)?)\s*"
        r"(?:номер\s*|№\s*|n\s*)?"
        r"(?P<items>(?:от\s*|с\s*)?\d{1,5}"
        r"(?:\s*(?:-|–|—|\.\.|до|по)\s*\d{1,5})?"
        r"(?:\s*(?:,|и)\s*\d{1,5}"
        r"(?:\s*(?:-|–|—|\.\.|до|по)\s*\d{1,5})?)*)",
        re.IGNORECASE,
    ),
    "mac": re.compile(
        r"""(?<![0-9a-fA-F:])(?:(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}
                 |(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}
                 |(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4})(?![0-9a-fA-F:])""",
        re.VERBOSE,
    ),
}


# ---------------------------------------------------------------------------
# Данные результата
# ---------------------------------------------------------------------------
@dataclass
class ExtractedEntity:
    """Единый извлечённый индикатор с типом и нормализованным значением."""

    entity_type: str              # 'ip', 'port', 'port_range', 'mac', 'protocol'
    raw_value: str                # исходная строка из команды
    normalized_value: str         # нормализованное значение
    direction: str | None = None  # 'src' / 'dst' (для ip и port)
    protocol_filter: str | None = None  # фильтр протокола (http, dns...)
    negated: bool = False         # «не http», «кроме 203.0.113.53»


@dataclass
class ParsedQuery:
    """Результат парсинга команд пользователя."""

    intent: str                       # намерение ('show', 'help', 'filter')
    entities: list[ExtractedEntity] = field(default_factory=list)
    unknown_text: str = ""            # текст, который не был распознан
    warnings: list[str] = field(default_factory=list)  # предупреждения валидации
    host_terms: list[str] = field(default_factory=list)  # слова «сайт», «хост» из команды
    raw_filter: str = ""              # фильтр Wireshark, набранный пользователем как есть

    def add_entity(self, entity: ExtractedEntity) -> None:
        self.entities.append(entity)

    def has_ip(self) -> bool:
        return any(e.entity_type == "ip" for e in self.entities)

    def has_port(self) -> bool:
        return any(e.entity_type == "port" for e in self.entities)

    def has_port_range(self) -> bool:
        return any(e.entity_type == "port_range" for e in self.entities)

    def has_negation(self) -> bool:
        return any(e.negated for e in self.entities)

    def has_mac(self) -> bool:
        return any(e.entity_type == "mac" for e in self.entities)

    def has_protocol(self) -> bool:
        return any(e.entity_type == "protocol" for e in self.entities)

    def has_host(self) -> bool:
        return any(e.entity_type == "host" for e in self.entities)

    def __str__(self) -> str:
        parts = [f"intent={self.intent}"]
        for e in self.entities:
            direction = f"[{e.direction}]" if e.direction else ""
            if e.entity_type == "protocol":
                parts.append(f"proto={e.normalized_value}{direction}")
            else:
                parts.append(f"{e.entity_type}={direction}{e.normalized_value}")
        return " | ".join(parts)


# ---------------------------------------------------------------------------
# Логика движения
# ---------------------------------------------------------------------------
class NaturalLanguageFilterEngine:
    """RegEx-движок для парсинга текстовых команд."""

    def __init__(self) -> None:
        # Кэшируем Compiled-паттерны для скорости
        self._patterns = REGEX_PATTERNS

    def parse(self, command: str) -> ParsedQuery:
        """
        Парсит текстовую команду и извлекает сетевые индикаторы.

        Args:
            command: Текстовая команда пользователя (RU/EN).

        Returns:
            ParsedQuery с извлечёнными сущностями и намерением.
        """
        if not command or not command.strip():
            return ParsedQuery(intent="help", unknown_text="Команда пуста.")

        raw_filter = looks_like_display_filter(command)
        if raw_filter:
            return ParsedQuery(intent="show", raw_filter=raw_filter)

        query = ParsedQuery(intent="show")
        text = command.strip().lower()

        # 1. Определяем намерение
        query.intent = self._detect_intent(text)

        # 2. Извлекаем индикаторы
        self._extract_entities(text, query)

        # 3. Формируем предупреждение, если текст не распознан
        self._check_unknown_text(command, query)

        return query

    # ------------------------------------------------------------------
    # Детекция намерения
    # ------------------------------------------------------------------
    def _detect_intent(self, text: str) -> str:
        """Определяет намерение по ключевым словам."""
        if self._match_keywords(text, ACTIONS["help"]):
            return "help"

        if self._match_keywords(text, ACTIONS["show"]):
            return "show"

        if self._match_keywords(text, ACTIONS["filter"]):
            return "filter"

        # Дефолт — показ сущностей
        return "show"

    @staticmethod
    def _match_keywords(text: str, keywords: list[str]) -> bool:
        for kw in keywords:
            if kw in text:
                return True
        return False

    # ------------------------------------------------------------------
    # Извлечение индикаторов
    # ------------------------------------------------------------------
    def _extract_entities(self, text: str, query: ParsedQuery) -> None:
        # IP-адреса (IPv4 и IPv6)
        self._extract_ips(text, query)

        # Имена сайтов и доменов — до протоколов: слово «сайт» не должно
        # превращаться в отдельный протокол http рядом с именем.
        self._extract_hosts(text, query)

        # Протоколы
        self._extract_protocols(text, query)

        # Порты и диапазоны портов (в том числе списком: «порты 80 и 1000-2000»)
        self._extract_ports(text, query)

        # MAC-адреса
        self._extract_macs(text, query)

    @staticmethod
    def _direction_before(text: str, position: int) -> str | None:
        """
        Определяет направление по словам перед значением.

        Смотрим на 2-3 слова назад и пропускаем служебные слова вроде
        "айпи" или "порт": "пакеты от 10.88.0.5" -> src,
        "пакеты к 203.0.113.53" -> dst, "пакеты с айпи 10.88.0.5" -> None.
        """
        tokens = [match.group(0) for match in re.finditer(r"\S+", text[:position])]

        for raw_word in reversed(tokens[-3:]):
            word = raw_word.strip(".,;:!?()\"'«»").lower()
            if not word:
                continue
            if word in FILLER_WORDS:
                continue
            if word in SRC_WORDS:
                return "src"
            if word in DST_WORDS:
                return "dst"
            return None
        return None

    @staticmethod
    def _negated_before(text: str, position: int) -> bool:
        """Стоит ли перед значением отрицание: «не http», «кроме 203.0.113.53»."""
        tokens = [match.group(0) for match in re.finditer(r"\S+", text[:position])]

        for raw_word in reversed(tokens[-5:]):
            word = raw_word.strip(".,;:!?()\"'«»").lower()
            if not word:
                continue
            if word in NEGATION_WORDS:
                return True
            if word in SRC_WORDS or word in DST_WORDS:
                return False
            if word in PROTOCOL_WORDS:
                return False
            # Служебные слова и значения («кроме A и B») отрицание не снимают.
            continue
        return False

    def _extract_ips(self, text: str, query: ParsedQuery) -> None:
        """Извлекает IPv4- и IPv6-адреса."""
        found: list[tuple[int, int]] = []

        for match in self._patterns["ipv4"].finditer(text):
            ip = match.group(0)
            # Проверяем, что это не часть MAC-адреса или портового диапазона
            start, end = match.span()
            if self._is_part_of_mac(text, start, end):
                continue
            try:
                normalized = validate_ipv4(ip)
            except ValidationError:
                continue
            found.append((start, end))
            query.add_entity(ExtractedEntity(
                entity_type="ip",
                raw_value=ip,
                normalized_value=normalized,
                direction=self._direction_before(text, start),
                negated=self._negated_before(text, start),
            ))

        self._extract_ipv6(text, query, found)

    def _extract_ipv6(self, text: str, query: ParsedQuery,
                      already: list[tuple[int, int]]) -> None:
        """IPv6 ищем по словам: адрес с двумя и более двоеточиями."""
        for match in re.finditer(r"[^\s,;()«»\"'\[\]]+", text):
            token = match.group(0).strip(".,;!?«»\"'[]()")
            if token.count(":") < 2:
                continue
            if token.isdigit():
                continue
            start = match.start()
            if any(begin <= start < end for begin, end in already):
                continue
            if self._is_part_of_mac(text, start, match.end()):
                continue
            try:
                normalized = validate_ipv6(token)
            except ValidationError:
                continue
            # MAC-адрес тоже валиден как «IPv6» только при 8 группах — исключаем
            # точным совпадением с MAC-паттерном.
            if is_valid_mac_address(token):
                continue
            already.append((start, match.end()))
            query.add_entity(ExtractedEntity(
                entity_type="ip",
                raw_value=token,
                normalized_value=normalized,
                direction=self._direction_before(text, start),
                negated=self._negated_before(text, start),
            ))

    def _extract_hosts(self, text: str, query: ParsedQuery) -> None:
        """Команды вида «покажи сайт example.com» или «трафик к домену test.ru»."""
        if query.has_ip():
            # «сайт 10.77.0.1» — это адрес, а не имя.
            return

        triggers = [
            word for word in HOST_WORDS
            if re.search(rf"(?<![\w.-]){re.escape(word)}(?![\w.-])", text)
        ]
        if not triggers:
            return

        trigger_position = min(text.find(word) for word in triggers)
        for match in DOMAIN_RE.finditer(text):
            value = match.group(1).strip(".")
            if not re.search(r"[a-zа-я]", value):
                continue
            tail = value.rsplit(".", 1)[-1]
            if tail in FILE_EXTENSIONS:
                continue
            # Имя поля Wireshark — не сайт: http.host, tls.sni, dns.qry.name.
            if value.split(".", 1)[0] in FIELD_PREFIXES:
                continue
            query.add_entity(ExtractedEntity(
                entity_type="host",
                raw_value=value,
                normalized_value=value,
                negated=self._negated_before(text, trigger_position),
            ))
            for word in triggers:
                if word not in query.host_terms:
                    query.host_terms.append(word)

    def _extract_protocols(self, text: str, query: ParsedQuery) -> None:
        """Извлекает протоколы: отдельные слова и собирательные фразы.

        Фразы важнее отдельных слов: если в «имя сайта» нашли и dns, и http,
        побеждает более длинное совпадение — dns.
        """
        tokens = _tokenize_words(text)
        found: list[tuple[int, int, str, str, str]] = []  # start, длина, вид, имя, фраза

        for phrase, names, words in GROUP_PHRASES:
            start = _find_phrase(tokens, words)
            if start is None:
                continue
            # «покажи сайт example.com»: имена уже ограничивают трафик,
            # добавлять (http or tls or dns) вторым условием не нужно.
            if query.has_host() and set(names) <= {"http", "tls", "dns"}:
                continue
            for name in names:
                found.append((start, len(words), "group", name, phrase))

        for proto, keyword, words in PROTOCOL_PHRASES:
            start = _find_phrase(tokens, words)
            if start is None:
                continue
            # Слово «сайт»/«домен» в «покажи сайт example.com» — это имя,
            # а не отдельный протокол (в том числе в падежах: «сайты», «домену»).
            if proto in ("http", "dns") and any(
                _word_matches(keyword.lower(), term) for term in query.host_terms
            ):
                continue
            found.append((start, len(words), "protocol", proto, keyword))

        def covered(match) -> bool:
            """Совпадение целиком внутри более длинного — отбрасываем."""
            start, length = match[0], match[1]
            for other in found:
                if other is match or other[1] <= length:
                    continue
                if other[0] <= start and start + length <= other[0] + other[1]:
                    return True
            return False

        seen: set[str] = set()
        for start, length, kind, name, raw in found:
            if name in seen or covered((start, length, kind, name, raw)):
                continue
            seen.add(name)
            query.add_entity(ExtractedEntity(
                entity_type="protocol",
                raw_value=raw,
                normalized_value=name,
                negated=self._negated_before(text, tokens[start][1]),
            ))

    def _extract_ports(self, text: str, query: ParsedQuery) -> None:
        """Порты и диапазоны, в том числе списком: «порты 80 и 1000-2000»."""
        splitter = re.compile(r"\s*(?:,|и)\s*", re.IGNORECASE)
        range_separator = re.compile(r"\s*(?:-|–|—|\.\.|до|по)\s*", re.IGNORECASE)

        for match in self._patterns["port"].finditer(text):
            direction = self._direction_before(text, match.start())
            negated = self._negated_before(text, match.start())

            for item in splitter.split(match.group("items")):
                item = re.sub(r"^(?:от|с)\s+", "", item.strip())
                if not item:
                    continue
                bounds = range_separator.split(item)
                if len(bounds) == 2:
                    self._add_port_range(bounds[0], bounds[1], direction, query, negated)
                else:
                    self._add_port(item, direction, query, negated)

    @staticmethod
    def _add_port(port_str: str, direction: str | None, query: ParsedQuery,
                  negated: bool = False) -> None:
        try:
            normalized = validate_port(port_str)
        except ValidationError:
            return
        query.add_entity(ExtractedEntity(
            entity_type="port",
            raw_value=port_str,
            normalized_value=str(normalized),
            direction=direction,
            negated=negated,
        ))

    @staticmethod
    def _add_port_range(start_str: str, end_str: str, direction: str | None,
                        query: ParsedQuery, negated: bool = False) -> None:
        try:
            start_port = validate_port(start_str)
            end_port = validate_port(end_str)
        except ValidationError:
            return
        if start_port > end_port:
            start_port, end_port = end_port, start_port
        query.add_entity(ExtractedEntity(
            entity_type="port_range",
            raw_value=f"{start_str}-{end_str}",
            normalized_value=f"{start_port}-{end_port}",
            direction=direction,
            negated=negated,
        ))

    def _extract_macs(self, text: str, query: ParsedQuery) -> None:
        """Извлекает MAC-адреса."""
        for match in self._patterns["mac"].finditer(text):
            mac = match.group(0)
            try:
                normalized = validate_mac_address(mac)
                query.add_entity(ExtractedEntity(
                    entity_type="mac",
                    raw_value=mac,
                    normalized_value=normalized,
                    negated=self._negated_before(text, match.start()),
                ))
            except ValidationError:
                pass

    @staticmethod
    def _is_part_of_mac(text: str, start: int, end: int) -> bool:
        """Проверяет, находится ли совпадение внутри MAC-адреса."""
        # Проверяем символы вокруг совпадения (IP адрес может быть частью MAC)
        if start > 0 and text[start - 1] in (":", "-"):
            return True
        if end < len(text) and text[end] in (":", "-"):
            return True
        return False

    @staticmethod
    def _check_unknown_text(command: str, query: ParsedQuery) -> None:
        """Формирует предупреждение о нераспознанном тексте."""
        known_words = set(NEGATION_WORDS)
        for action in ACTIONS.values():
            known_words.update(action)
        for entity in ENTITY_TYPES.values():
            known_words.update(entity)
        for proto_keywords in PROTOCOL_FILTERS.values():
            known_words.update(proto_keywords)

        tokens = command.lower().split()
        unknown = [t for t in tokens if t not in known_words]
        if unknown:
            query.unknown_text = " ".join(set(unknown))
