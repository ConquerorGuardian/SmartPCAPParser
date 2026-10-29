"""
Тесты вычислителя display-фильтров.
Запуск: python -m tests.test_matcher
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.matcher import FilterError, compile_filter, is_valid_filter, normalize_mac
from parser.pcap_reader import read_packets

SAMPLE = Path(__file__).parent / "sample_traffic.pcap"
PACKETS, _ = read_packets(SAMPLE)
ALL = list(range(1, len(PACKETS) + 1))


def matched(filter_string: str) -> list[int]:
    predicate = compile_filter(filter_string)
    return [packet.number for packet in PACKETS if predicate(packet)]


def test_ip_addr():
    assert matched("ip.addr==192.168.1.10") == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13]
    print("PASS: test_ip_addr")


def test_ip_src_dst():
    assert matched("ip.src==8.8.8.8") == [3]
    assert matched("ip.dst==8.8.8.8") == [2]
    print("PASS: test_ip_src_dst")


def test_port_fields():
    assert matched("tcp.port==80") == [4, 5, 6, 7]
    assert matched("tcp.dstport==22") == [11, 12]
    assert matched("tcp.srcport==40000") == [4, 6]
    print("PASS: test_port_fields")


def test_udp_port():
    assert matched("udp.port==53") == [2, 3]
    assert matched("tcp.port==53") == []
    assert matched("udp.port==443") == [13]
    print("PASS: test_udp_port")


def test_protocol_names():
    assert matched("http") == [6, 7]
    assert matched("dns") == [2, 3]
    assert matched("icmp") == [9, 10]
    assert matched("arp") == [1]
    assert matched("tls") == [8]
    assert matched("ssh") == [12]
    assert matched("quic") == [13]
    assert matched("tcp") == [4, 5, 6, 7, 8, 11, 12]
    assert matched("udp") == [2, 3, 13]
    print("PASS: test_protocol_names")


def test_mac_fields():
    assert matched("eth.addr==aa:bb:cc:dd:ee:01") == ALL
    assert matched("eth.src==aa:bb:cc:dd:ee:03") == [5, 7]
    print("PASS: test_mac_fields")


def test_logic_operators():
    assert matched("tcp.port==80 or tcp.port==443") == [4, 5, 6, 7, 8]
    assert matched("http and ip.addr==93.184.216.34") == [6, 7]
    assert matched("not tcp") == [1, 2, 3, 9, 10, 13]
    assert matched("(http or dns) and ip.addr==8.8.8.8") == [2, 3]
    print("PASS: test_logic_operators")


def test_value_lists():
    assert matched("tcp.port==80,443") == [4, 5, 6, 7, 8]
    assert matched("ip.addr==8.8.8.8,93.184.216.34") == [2, 3, 4, 5, 6, 7]
    print("PASS: test_value_lists")


def test_not_equal():
    result = matched("ip.addr!=8.8.8.8")
    assert 2 not in result and 3 not in result
    assert 1 in result
    print("PASS: test_not_equal")


def test_empty_filter():
    assert len(matched("")) == len(PACKETS)
    print("PASS: test_empty_filter")


def test_bad_filters():
    for bad in ["bad.field==1", "ip.addr==", "http and", "(tcp.port==80", "tcp.port==abc"]:
        try:
            compile_filter(bad)
        except FilterError:
            continue
        raise AssertionError("ожидалась ошибка для фильтра: " + bad)
    print("PASS: test_bad_filters")


def test_validity_helper():
    assert is_valid_filter("ip.addr==192.168.1.1")
    assert not is_valid_filter("bad.field==1")
    print("PASS: test_validity_helper")


def test_mac_normalization():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    print("PASS: test_mac_normalization")


def test_extended_protocols():
    """Новые имена протоколов компилируются и матчатся."""
    from parser.pcap_reader import Packet

    def packet(app: str, transport: str = "TCP") -> Packet:
        return Packet(number=1, timestamp=0.0, length=54, wire_length=54,
                      app=app, transport=transport, protocol=transport)

    names = ["rdp", "smb", "mysql", "telnet", "pop3", "imap", "ldap", "mdns", "dhcp"]
    for name in names:
        predicate = compile_filter(name)
        assert predicate(packet(name.upper())) is True, name
        assert predicate(packet("HTTP")) is False, name
        assert is_valid_filter(name) is True, name
    print("PASS: test_extended_protocols")


def test_port_range():
    """Диапазон портов через набор значений, как в Wireshark."""
    assert matched("tcp.port in {79..81}") == [4, 5, 6, 7]
    assert matched("tcp.port in {1024..65535}") == [4, 5, 6, 7, 8, 11, 12]
    assert matched("tcp.port in {22..22}") == [11, 12]
    assert matched("tcp.port in {53, 443}") == [8]
    assert matched("udp.port in {53, 443}") == [2, 3, 13]
    print("PASS: test_port_range")


def test_negation():
    """«не http» исключает HTTP, а не показывает его."""
    assert matched("not (http)") == [1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13]
    assert matched("tcp and not (tcp.port==80)") == [8, 11, 12]
    assert matched("not (ip.addr==192.168.1.10)") == [11, 12]
    print("PASS: test_negation")


def test_ipv6_fields():
    """IPv6-поля не путаются с IPv4 и MAC."""
    from parser.pcap_reader import Packet

    packet = Packet(number=1, timestamp=0.0, length=54, wire_length=54,
                    src_ip="2001:db8::1", dst_ip="2001:db8::2",
                    transport="TCP", protocol="TCP", src_port=50000, dst_port=443)

    assert compile_filter("ipv6.addr==2001:db8::1")(packet) is True
    assert compile_filter("ipv6.src==2001:db8::1")(packet) is True
    assert compile_filter("ipv6.dst==2001:db8::1")(packet) is False
    assert compile_filter("ip.addr==2001:db8::2")(packet) is False
    assert compile_filter("not (ipv6.addr==2001:db8::3)")(packet) is True
    print("PASS: test_ipv6_fields")


def test_new_protocols():
    """Новые протоколы: имена Wireshark и наши названия — одно и то же."""
    from parser.pcap_reader import Packet

    def packet(app: str, transport: str = "TCP") -> Packet:
        return Packet(number=1, timestamp=0.0, length=54, wire_length=54,
                      app=app, transport=transport, protocol=transport)

    cases = {
        "tds": "MSSQL",
        "mssql": "MSSQL",
        "pgsql": "PostgreSQL",
        "mongo": "MongoDB",
        "redis": "Redis",
        "memcached": "Memcached",
        "sip": "SIP",
        "snmp": "SNMP",
        "tftp": "TFTP",
        "vnc": "VNC",
        "mqtt": "MQTT",
        "kerberos": "Kerberos",
        "syslog": "Syslog",
        "stun": "STUN",
        "openvpn": "OpenVPN",
        "socks": "SOCKS",
        "nfs": "NFS",
        "http2": "HTTP2",
    }
    for name, app in cases.items():
        predicate = compile_filter(name)
        assert predicate(packet(app)) is True, name
        assert is_valid_filter(name) is True, name

    # ipv4/ipv6 — это семейство адреса, а не прикладной протокол.
    ipv4 = Packet(number=2, timestamp=0.0, length=54, wire_length=54,
                  src_ip="10.0.0.5", dst_ip="8.8.8.8", transport="TCP",
                  protocol="TCP")
    ipv6 = Packet(number=3, timestamp=0.0, length=54, wire_length=54,
                  src_ip="2001:db8::1", dst_ip="2001:db8::2", transport="TCP",
                  protocol="TCP")
    assert compile_filter("ipv4")(ipv4) is True
    assert compile_filter("ipv4")(ipv6) is False
    assert compile_filter("ipv6")(ipv6) is True
    assert compile_filter("ipv6")(ipv4) is False
    print("PASS: test_new_protocols")


def test_numeric_fields():
    """Числовые поля: длинные фильтры из интернета больше не падают."""
    from parser.pcap_reader import Packet

    packet = Packet(
        number=7, timestamp=0.0, length=120, wire_length=120,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", transport="TCP", protocol="TCP",
        src_port=40000, dst_port=80, ttl=61, ip_len=106, tcp_len=66,
        tcp_window=64240, seq=1000, tcp_ack=2000,
    )

    assert compile_filter("frame.len > 100")(packet) is True
    assert compile_filter("frame.len < 100")(packet) is False
    assert compile_filter("frame.len == 120")(packet) is True
    assert compile_filter("frame.len >= 120 and frame.len <= 120")(packet) is True
    assert compile_filter("frame.len in {54..128}")(packet) is True
    assert compile_filter("frame.number==7")(packet) is True
    assert compile_filter("ip.ttl < 64")(packet) is True
    assert compile_filter("ip.ttl > 64")(packet) is False
    assert compile_filter("ip.len > 100")(packet) is True
    assert compile_filter("tcp.len > 0")(packet) is True
    assert compile_filter("tcp.window_size==64240")(packet) is True
    assert compile_filter("tcp.ack==2000")(packet) is True

    empty = Packet(number=8, timestamp=0.0, length=64, wire_length=64,
                   transport="TCP", protocol="TCP")
    # Поле неприменимо (нет IP) — не совпадает, а не «0 < 64».
    assert compile_filter("ip.ttl < 64")(empty) is False
    assert compile_filter("udp.length > 0")(packet) is False
    print("PASS: test_numeric_fields")


def test_tcp_flags():
    """Флаги TCP: tcp.flags.syn==1 и tcp.flags.ack==0."""
    from parser.pcap_reader import Packet

    syn = Packet(number=1, timestamp=0.0, length=54, wire_length=54,
                 transport="TCP", protocol="TCP", src_port=50000, dst_port=80,
                 tcp_flags=0x002)
    syn_ack = Packet(number=2, timestamp=0.0, length=54, wire_length=54,
                     transport="TCP", protocol="TCP", src_port=80, dst_port=50000,
                     tcp_flags=0x012)

    assert compile_filter("tcp.flags.syn==1 and tcp.flags.ack==0")(syn) is True
    assert compile_filter("tcp.flags.syn==1 and tcp.flags.ack==0")(syn_ack) is False
    assert compile_filter("tcp.flags.ack==1")(syn_ack) is True
    assert compile_filter("tcp.flags.rst==1")(syn) is False

    udp = Packet(number=3, timestamp=0.0, length=60, wire_length=60,
                 transport="UDP", protocol="UDP")
    assert compile_filter("tcp.flags.syn==1")(udp) is False
    print("PASS: test_tcp_flags")


def test_names_filters():
    """Фильтры по именам: HTTP Host, TLS SNI, DNS-имя."""
    from parser.pcap_reader import Packet

    http = Packet(number=1, timestamp=0.0, length=90, wire_length=90,
                  transport="TCP", protocol="TCP", app="HTTP",
                  host="example.com", http_uri="/index.html")
    tls = Packet(number=2, timestamp=0.0, length=90, wire_length=90,
                 transport="TCP", protocol="TCP", app="TLS", sni="secure.example.com")
    dns = Packet(number=3, timestamp=0.0, length=90, wire_length=90,
                 transport="UDP", protocol="UDP", app="DNS", dns_name="test.org")
    empty = Packet(number=4, timestamp=0.0, length=40, wire_length=40,
                   transport="UDP", protocol="UDP")

    assert compile_filter('http.host contains "example"')(http) is True
    assert compile_filter('http.host contains "example"')(tls) is False
    assert compile_filter('tls.handshake.extensions_server_name contains "example"')(tls) is True
    assert compile_filter('tls.sni == secure.example.com')(tls) is True
    assert compile_filter('dns.qry.name == test.org')(dns) is True
    assert compile_filter('dns.qry.name contains "test"')(dns) is True
    assert compile_filter('http.request.uri contains "index"')(http) is True
    assert compile_filter('http.host contains "example"')(empty) is False
    # Объединённое условие, как его генерирует приложение.
    combined = ('(http.host contains "example.com" or '
                'tls.handshake.extensions_server_name contains "example.com" or '
                'dns.qry.name contains "example.com")')
    assert compile_filter(combined)(http) is True
    assert compile_filter(combined)(tls) is True
    assert compile_filter(combined)(dns) is False
    print("PASS: test_names_filters")


def test_payload_contains():
    """«tcp contains текст» — поиск по данным пакета."""
    from parser.pcap_reader import Packet

    packet = Packet(number=1, timestamp=0.0, length=120, wire_length=120,
                    transport="TCP", protocol="TCP", app="HTTP",
                    payload=b"GET /secret HTTP/1.1\r\nHost: a\r\n")
    udp = Packet(number=2, timestamp=0.0, length=60, wire_length=60,
                 transport="UDP", protocol="UDP", payload=b"hello dns")

    assert compile_filter("tcp contains secret")(packet) is True
    assert compile_filter("tcp contains missing")(packet) is False
    assert compile_filter("tcp contains secret")(udp) is False
    assert compile_filter("frame contains hello")(udp) is True
    assert compile_filter("udp contains hello")(udp) is True
    print("PASS: test_payload_contains")


def test_more_protocols():
    """Новые протоколы: ICMPv6, IGMP, LLMNR, SSDP, RADIUS, NetBIOS, IPsec."""
    from parser.pcap_reader import Packet

    def pkt(**kwargs):
        base = dict(number=1, timestamp=0.0, length=80, wire_length=80,
                    transport="UDP", protocol="UDP")
        base.update(kwargs)
        return Packet(**base)

    icmpv6 = pkt(transport="ICMPv6", protocol="ICMPv6")
    igmp = pkt(transport="IGMP", protocol="IGMP")
    llmnr = pkt(app="LLMNR")
    ssdp = pkt(app="SSDP")
    radius = pkt(app="RADIUS")
    dhcpv6 = pkt(app="DHCPv6")
    netbios = pkt(transport="TCP", protocol="TCP", app="NetBIOS", dst_port=139)
    ipsec = pkt(app="IPsec", dst_port=500)
    bgp = pkt(transport="TCP", protocol="TCP", app="BGP", dst_port=179)
    plain = pkt()

    for name, target in (
        ("icmpv6", icmpv6), ("icmp6", icmpv6), ("igmp", igmp),
        ("llmnr", llmnr), ("ssdp", ssdp), ("radius", radius),
        ("dhcpv6", dhcpv6), ("nbns", netbios), ("netbios", netbios),
        ("ipsec", ipsec), ("isakmp", ipsec), ("bgp", bgp),
    ):
        assert compile_filter(name)(target) is True, name
        assert compile_filter(name)(plain) is False, name

    assert compile_filter("icmpv6")(pkt(transport="ICMP", protocol="ICMP")) is False
    print("PASS: test_more_protocols")


if __name__ == "__main__":
    tests = [
        test_ip_addr,
        test_ip_src_dst,
        test_port_fields,
        test_udp_port,
        test_protocol_names,
        test_mac_fields,
        test_logic_operators,
        test_value_lists,
        test_not_equal,
        test_empty_filter,
        test_bad_filters,
        test_validity_helper,
        test_mac_normalization,
        test_extended_protocols,
        test_port_range,
        test_negation,
        test_ipv6_fields,
        test_new_protocols,
        test_numeric_fields,
        test_tcp_flags,
        test_names_filters,
        test_payload_contains,
        test_more_protocols,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            print("FAIL: {}: {}".format(test.__name__, exc))
            failed += 1
        except Exception as exc:  # noqa: BLE001
            print("ERROR: {}: {}".format(test.__name__, exc))
            failed += 1

    print("")
    print("-" * 40)
    print("Пройдено: {}/{}".format(len(tests) - failed, len(tests)))
    if failed:
        sys.exit(1)
    print("Все тесты прошли!")
