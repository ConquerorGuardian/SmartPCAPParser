"""
Тесты для RegEx-движка и фильтров.
Запуск: python -m tests.test_engine
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.engine import NaturalLanguageFilterEngine
from parser.filters import generate_filter


def test_simple_ip():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("найди пакеты с айпи 192.168.1.1")
    assert query.intent == "show"
    assert query.has_ip()
    assert len(query.entities) == 1
    assert query.entities[0].normalized_value == "192.168.1.1"
    filter_str = generate_filter(query)
    assert filter_str == "ip.addr==192.168.1.1", filter_str
    print("PASS: test_simple_ip passed")


def test_ip_src():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("пакеты от 10.0.0.5")
    assert query.has_ip()
    assert query.entities[0].direction == "src"
    filter_str = generate_filter(query)
    assert filter_str == "ip.src==10.0.0.5", filter_str
    print("PASS: test_ip_src passed")


def test_port():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("выведи пакеты на порт 80")
    assert query.has_port()
    assert query.entities[0].normalized_value == "80"
    filter_str = generate_filter(query)
    assert filter_str == "tcp.port==80", filter_str
    print("PASS: test_port passed")


def test_tcp_port():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("найди tcp порт 443")
    assert query.has_port()
    filter_str = generate_filter(query)
    assert filter_str == "tcp.port==443", filter_str
    print("PASS: test_tcp_port passed")


def test_udp_port():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("покажи udp порт 53")
    assert query.has_port()
    filter_str = generate_filter(query)
    assert filter_str == "udp.port==53", filter_str
    print("PASS: test_udp_port passed")


def test_port_list():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("покажи пакеты на порт 80 и 443")
    assert len(query.entities) == 2, query.entities
    filter_str = generate_filter(query)
    assert filter_str == "tcp.port==80,443", filter_str
    print("PASS: test_port_list passed")


def test_ip_before_port_no_direction():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("покажи http трафик с айпи 192.168.1.10")
    assert query.entities[0].direction is None, query.entities[0]
    filter_str = generate_filter(query)
    assert filter_str == "ip.addr==192.168.1.10 and http", filter_str
    print("PASS: test_ip_before_port_no_direction passed")


def test_mac():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("покажи мак адрес aa:bb:cc:dd:ee:ff")
    assert query.has_mac()
    assert query.entities[0].normalized_value == "aa:bb:cc:dd:ee:ff"
    filter_str = generate_filter(query)
    assert filter_str == "eth.addr==aa:bb:cc:dd:ee:ff", filter_str
    print("PASS: test_mac passed")


def test_mac_cisco():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("мак адрес aabb.ccdd.eeff")
    assert query.has_mac()
    assert query.entities[0].normalized_value == "aabb.ccdd.eeff"
    print("PASS: test_mac_cisco passed")


def test_protocol():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("покажи http трафик")
    assert query.has_protocol()
    filter_str = generate_filter(query)
    assert filter_str == "http", filter_str
    print("PASS: test_protocol passed")


def test_combined():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("найди пакеты с айпи 192.168.1.100 на порт 8080")
    assert query.has_ip() and query.has_port()
    filter_str = generate_filter(query)
    assert "ip.addr==192.168.1.100" in filter_str
    assert "tcp.port==8080" in filter_str
    print("PASS: test_combined passed")


def test_directional_ip_both():
    """«от A к B» — оба направления попадают в фильтр, а не только первое."""
    engine = NaturalLanguageFilterEngine()
    filter_str = generate_filter(engine.parse("пакеты от 10.0.0.5 к 8.8.8.8"))
    assert filter_str == "ip.src==10.0.0.5 and ip.dst==8.8.8.8", filter_str
    print("PASS: test_directional_ip_both passed")


def test_empty_command():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("")
    assert query.intent == "help"
    assert query.unknown_text
    print("PASS: test_empty_command passed")


def test_no_entities():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("просто текст без индикаторов")
    assert query.intent == "show"
    assert not query.has_ip() and not query.has_port() and not query.has_mac()
    print("PASS: test_no_entities passed")


def test_negation():
    """Отрицание: «не http», «кроме 8.8.8.8», «не на порт 80»."""
    engine = NaturalLanguageFilterEngine()
    cases = {
        "не http": "not (http)",
        "покажи всё кроме 8.8.8.8": "not (ip.addr==8.8.8.8)",
        "покажи пакеты не на порт 80": "not (tcp.port==80)",
        "не dns и не http": "not (http or dns)",
        "покажи tcp трафик не на порт 22": "not (tcp.port==22) and tcp",
        "покажи http трафик с айпи 10.0.0.5": "ip.addr==10.0.0.5 and http",
    }
    for command, expected in cases.items():
        actual = generate_filter(engine.parse(command))
        assert actual == expected, f"{command}: ожидалось {expected!r}, получено {actual!r}"

    query = engine.parse("кроме http")
    assert query.has_negation()
    print("PASS: test_negation passed")


def test_port_ranges():
    """Диапазоны портов и списки с диапазонами."""
    engine = NaturalLanguageFilterEngine()
    cases = {
        "порты 1000-2000": "tcp.port in {1000..2000}",
        "порты от 1000 до 2000": "tcp.port in {1000..2000}",
        "порт от 22 до 23": "tcp.port in {22..23}",
        "порты 80 и 1000-2000": "(tcp.port==80 or tcp.port in {1000..2000})",
        "не на порты 80 и 1000-2000":
            "not (tcp.port==80 or tcp.port in {1000..2000})",
    }
    for command, expected in cases.items():
        actual = generate_filter(engine.parse(command))
        assert actual == expected, f"{command}: ожидалось {expected!r}, получено {actual!r}"

    query = engine.parse("порты 1000-2000")
    assert query.has_port_range()
    assert not query.has_port()
    print("PASS: test_port_ranges passed")


def test_ipv6():
    """IPv6-команды: адрес, направление, отсев MAC."""
    engine = NaturalLanguageFilterEngine()
    cases = {
        "покажи айпи 2001:db8::1": "ipv6.addr==2001:db8::1",
        "пакеты от 2001:db8::1": "ipv6.src==2001:db8::1",
        "пакеты к 2001:db8::2": "ipv6.dst==2001:db8::2",
        "пакеты с ipv6 адресом ::1": "ipv6.addr==::1",
        "пакеты с айпи 2001:DB8:0:0:0:0:0:1": "ipv6.addr==2001:db8::1",
    }
    for command, expected in cases.items():
        actual = generate_filter(engine.parse(command))
        assert actual == expected, f"{command}: ожидалось {expected!r}, получено {actual!r}"

    # MAC не должен притвориться IPv6.
    mac_filter = generate_filter(engine.parse("мак ff:ff:ff:ff:ff:ff"))
    assert mac_filter == "eth.addr==ff:ff:ff:ff:ff:ff", mac_filter
    print("PASS: test_ipv6 passed")


def test_protocol_groups():
    """Собирательные фразы: одно слово — несколько протоколов."""
    engine = NaturalLanguageFilterEngine()
    cases = {
        "покажи базы данных":
            "(mysql or tds or pgsql or mongo or redis or memcached)",
        "где база данных":
            "(mysql or tds or pgsql or mongo or redis or memcached)",
        "покажи почту": "(smtp or pop3 or imap)",
        "покажи удалённый доступ": "(rdp or ssh or vnc or telnet)",
        "покажи видеосвязь": "(sip or stun)",
        "покажи мониторинг": "(snmp or syslog)",
        "покажи сетевые папки": "(smb or nfs)",
        "покажи файловые серверы": "(ftp or smb or nfs)",
        "не базы данных":
            "not (mysql or tds or pgsql or mongo or redis or memcached)",
    }
    for command, expected in cases.items():
        actual = generate_filter(engine.parse(command))
        assert actual == expected, f"{command}: ожидалось {expected!r}, получено {actual!r}"
    print("PASS: test_protocol_groups passed")


def test_vocabulary():
    """Бытовые формулировки и новые протоколы из словаря."""
    engine = NaturalLanguageFilterEngine()
    cases = {
        # новые протоколы, имена — как в Wireshark
        "покажи sql server": "tds",
        "покажи постгрес": "pgsql",
        "покажи монго": "mongo",
        "трафик redis": "redis",
        "покажи мемкеш": "memcached",
        "покажи телефонию": "(sip or stun)",
        "покажи умный дом": "mqtt",
        "покажи http/2": "http2",
        "покажи h2 трафик": "http2",
        "покажи sip трафик": "sip",
        "покажи mqtt датчики": "mqtt",
        "покажи прошивку": "tftp",
        "покажи удалённый экран": "vnc",
        "покажи керберос": "kerberos",
        "покажи логи": "syslog",
        "покажи видеозвонки": "stun",
        "покажи впн": "openvpn",
        "покажи прокси": "socks",
        "покажи сетевой диск": "nfs",
        "покажи принтер": "mdns",
        # стек
        "покажи ipv6 трафик": "ipv6",
        "покажи ipv4 трафик": "ip",
        # бытовые синонимы старых протоколов
        "покажи сайт": "(http or tls or dns)",
        "покажи сертификаты": "tls",
        "покажи имя сайта": "dns",
        "покажи трассировку": "icmp",
        "покажи отправку почты": "smtp",
        "покажи точное время": "ntp",
        "покажи аренду адреса": "dhcp",
        "покажи кто имеет": "arp",
        "покажи шару": "smb",
        "покажи файловый сервер": "(ftp or smb or nfs)",
    }
    for command, expected in cases.items():
        actual = generate_filter(engine.parse(command))
        assert actual == expected, f"{command}: ожидалось {expected!r}, получено {actual!r}"
    print("PASS: test_vocabulary passed")


def test_chatty_commands():
    """Разговорные команды: «хочу увидеть», «грепни», «есть ли»."""
    engine = NaturalLanguageFilterEngine()
    cases = {
        "хочу увидеть где база данных":
            "(mysql or tds or pgsql or mongo or redis or memcached)",
        "грепни почтовый сервер": "smtp",
        "есть ли http трафик": "http",
        "что за устройства в сети": "mdns",
        "ищу зашифрованный трафик": "tls",
        "нужны запросы доменов": "dns",
        "дай глянуть консоль ssh": "ssh",
        "покажи-ка rdp": "rdp",
    }
    for command, expected in cases.items():
        actual = generate_filter(engine.parse(command))
        assert actual == expected, f"{command}: ожидалось {expected!r}, получено {actual!r}"

    # «покажи всё кроме http» — это не help, а обычная команда.
    assert engine.parse("покажи всё кроме http").intent == "show"
    print("PASS: test_chatty_commands passed")


def test_multiple_ips():
    engine = NaturalLanguageFilterEngine()
    query = engine.parse("найди 192.168.1.1 и 10.0.0.1")
    assert len(query.entities) == 2
    filter_str = generate_filter(query)
    assert "192.168.1.1" in filter_str and "10.0.0.1" in filter_str
    print("PASS: test_multiple_ips passed")


def test_extended_dictionary():
    """Новые слова и протоколы из расширенного словаря."""
    engine = NaturalLanguageFilterEngine()
    cases = {
        "покажи рдп трафик": "rdp",
        "https трафик": "tls",
        "днс запросы": "dns",
        "покажи smb трафик": "smb",
        "общая папка": "smb",
        "удалённый рабочий стол": "rdp",
        "каталог пользователей": "ldap",
        "покажи dhcp": "dhcp",
        "telnet трафик": "telnet",
        "айпишник 10.0.0.5": "ip.addr==10.0.0.5",
        "порт номер 22": "tcp.port==22",
        "порты 80 и 443": "tcp.port==80,443",
    }
    for command, expected in cases.items():
        query = engine.parse(command)
        actual = generate_filter(query)
        assert actual == expected, f"{command}: ожидалось {expected!r}, получено {actual!r}"
    print("PASS: test_extended_dictionary passed")


def test_help_intent():
    engine = NaturalLanguageFilterEngine()
    for command in ["справка", "что ты умеешь", "help", "как пользоваться"]:
        assert engine.parse(command).intent == "help", command
    print("PASS: test_help_intent passed")


def test_host_commands():
    """Имена сайтов: «покажи сайт example.com» и отрицание."""
    engine = NaturalLanguageFilterEngine()
    expected_group = ('(http.host contains "example.com" or '
                      'tls.handshake.extensions_server_name contains "example.com" or '
                      'dns.qry.name contains "example.com")')

    query = engine.parse("покажи сайт example.com")
    assert query.has_host(), query.entities
    assert generate_filter(query) == expected_group

    assert generate_filter(engine.parse("не сайт example.com")) == f"not ({expected_group[1:-1]})"
    assert generate_filter(engine.parse("покажи сайт example.com и порт 443")) == (
        "tcp.port==443 and " + expected_group
    )

    # Без имени «сайт» — это весь веб-трафик.
    assert generate_filter(engine.parse("покажи сайт")) == "(http or tls or dns)"
    # IP — это адрес, а не имя сайта.
    assert generate_filter(engine.parse("покажи сайт 192.168.1.1")) == (
        "ip.addr==192.168.1.1 and (http or tls or dns)"
    )
    # Имя файла доменом не считается.
    assert engine.parse("покажи сайт file.pcap").has_host() is False
    print("PASS: test_host_commands")


def test_new_protocol_words():
    """Новые протоколы и собирательные фразы дают рабочие фильтры."""
    engine = NaturalLanguageFilterEngine()

    assert generate_filter(engine.parse("покажи icmpv6")) == "icmpv6"
    assert generate_filter(engine.parse("покажи icmp6 трафик")) == "icmpv6"
    assert generate_filter(engine.parse("покажи llmnr")) == "llmnr"
    assert generate_filter(engine.parse("покажи ssdp")) == "ssdp"
    assert generate_filter(engine.parse("покажи dhcpv6")) == "dhcpv6"
    assert generate_filter(engine.parse("покажи radius")) == "radius"
    assert generate_filter(engine.parse("покажи netbios")) == "nbns"
    assert generate_filter(engine.parse("покажи bgp")) == "bgp"
    assert generate_filter(engine.parse("покажи ipsec")) == "isakmp"
    assert generate_filter(engine.parse("покажи туннели")) == (
        "(openvpn or l2tp or isakmp or gre)"
    )
    assert generate_filter(engine.parse("покажи маршрутизация")) == (
        "(bgp or ospf or icmp or igmp)"
    )
    assert "llmnr" in generate_filter(engine.parse("покажи локальные протоколы"))
    print("PASS: test_new_protocol_words")


if __name__ == "__main__":
    tests = [
        test_simple_ip,
        test_ip_src,
        test_port,
        test_tcp_port,
        test_udp_port,
        test_port_list,
        test_ip_before_port_no_direction,
        test_mac,
        test_mac_cisco,
        test_protocol,
        test_combined,
        test_directional_ip_both,
        test_empty_command,
        test_no_entities,
        test_multiple_ips,
        test_negation,
        test_port_ranges,
        test_ipv6,
        test_protocol_groups,
        test_vocabulary,
        test_chatty_commands,
        test_extended_dictionary,
        test_host_commands,
        test_new_protocol_words,
        test_help_intent,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"FAIL: {test.__name__} FAILED: {e}")
            failed += 1
        except Exception as e:  # noqa: BLE001
            print(f"ERROR: {test.__name__} ERROR: {e}")
            failed += 1

    print("")
    print("-"*40)
    print(f"Пройдено: {len(tests) - failed}/{len(tests)}")
    if failed:
        sys.exit(1)
    print("Все тесты прошли!")
