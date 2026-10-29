"""
Тесты чтения pcap/pcapng без tshark.
Запуск: python -m tests.test_reader
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.pcap_reader import PcapError, read_packets

SAMPLE_PCAP = Path(__file__).parent / "sample_traffic.pcap"
SAMPLE_PCAPNG = Path(__file__).parent / "sample_traffic.pcapng"


def test_pcap_packet_count():
    packets, linktype = read_packets(SAMPLE_PCAP)
    assert len(packets) == 13, len(packets)
    assert linktype == 1, linktype
    print("PASS: test_pcap_packet_count")


def test_pcapng_packet_count():
    packets, _linktype = read_packets(SAMPLE_PCAPNG)
    assert len(packets) == 13, len(packets)
    print("PASS: test_pcapng_packet_count")


def test_pcap_and_pcapng_are_equal():
    pcap_packets, _ = read_packets(SAMPLE_PCAP)
    pcapng_packets, _ = read_packets(SAMPLE_PCAPNG)
    assert len(pcap_packets) == len(pcapng_packets)
    for left, right in zip(pcap_packets, pcapng_packets):
        assert left.protocol == right.protocol, (left.protocol, right.protocol)
        assert left.app == right.app, (left.app, right.app)
        assert left.src_ip == right.src_ip
        assert left.dst_ip == right.dst_ip
        assert left.src_port == right.src_port
        assert left.dst_port == right.dst_port
    print("PASS: test_pcap_and_pcapng_are_equal")


def test_arp_packet():
    packets, _ = read_packets(SAMPLE_PCAP)
    arp = packets[0]
    assert arp.protocol == "ARP"
    assert arp.src_ip == "192.168.1.10"
    assert "Who has" in arp.info
    print("PASS: test_arp_packet")


def test_dns_packet():
    packets, _ = read_packets(SAMPLE_PCAP)
    dns = packets[1]
    assert dns.protocol == "UDP", dns.protocol
    assert dns.app == "DNS", dns.app
    assert dns.src_port == 10000
    assert dns.dst_port == 53
    print("PASS: test_dns_packet")


def test_http_packet():
    packets, _ = read_packets(SAMPLE_PCAP)
    http = packets[5]
    assert http.protocol == "TCP", http.protocol
    assert http.app == "HTTP", http.app
    assert http.dst_port == 80
    assert "40000 -> 80" in http.info
    print("PASS: test_http_packet")


def test_tcp_syn_has_no_app():
    packets, _ = read_packets(SAMPLE_PCAP)
    syn = packets[3]
    assert syn.protocol == "TCP"
    assert syn.app == "", syn.app
    print("PASS: test_tcp_syn_has_no_app")


def test_tls_packet():
    packets, _ = read_packets(SAMPLE_PCAP)
    tls = packets[7]
    assert tls.protocol == "TCP", tls.protocol
    assert tls.app == "TLS", tls.app
    assert tls.dst_port == 443
    print("PASS: test_tls_packet")


def test_quic_packet():
    packets, _ = read_packets(SAMPLE_PCAP)
    quic = packets[12]
    assert quic.protocol == "UDP", quic.protocol
    assert quic.app == "QUIC", quic.app
    assert quic.dst_port == 443
    print("PASS: test_quic_packet")


def test_ssh_packet():
    packets, _ = read_packets(SAMPLE_PCAP)
    banner = packets[11]
    assert banner.protocol == "TCP"
    assert banner.app == "SSH", banner.app
    print("PASS: test_ssh_packet")


def test_icmp_packet():
    packets, _ = read_packets(SAMPLE_PCAP)
    request, reply = packets[8], packets[9]
    assert request.protocol == "ICMP"
    assert "request" in request.info
    assert "reply" in reply.info
    print("PASS: test_icmp_packet")


def test_mac_addresses():
    packets, _ = read_packets(SAMPLE_PCAP)
    packet = packets[0]
    assert packet.src_mac == "aa:bb:cc:dd:ee:01"
    assert packet.dst_mac == "ff:ff:ff:ff:ff:ff"
    print("PASS: test_mac_addresses")


def test_relative_time():
    packets, _ = read_packets(SAMPLE_PCAP)
    first, second = packets[0], packets[1]
    delta = second.timestamp - first.timestamp
    assert abs(delta - 0.1) < 0.0001, delta
    print("PASS: test_relative_time")


def test_missing_file():
    try:
        read_packets(Path(__file__).parent / "no_such_file.pcap")
    except PcapError as exc:
        assert "не найден" in str(exc).lower()
        print("PASS: test_missing_file")
        return
    raise AssertionError("ожидалась ошибка PcapError")


def test_broken_file():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
        handle.write(b"not a pcap at all")
        broken = Path(handle.name)
    try:
        read_packets(broken)
    except PcapError:
        print("PASS: test_broken_file")
        return
    finally:
        broken.unlink(missing_ok=True)
    raise AssertionError("ожидалась ошибка PcapError")


def test_port_to_protocol_map():
    """Порты новых протоколов распознаются так же, как в Wireshark."""
    from parser.pcap_reader import _detect_tcp_app, _detect_udp_app

    tcp_cases = {
        1433: "MSSQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        5060: "SIP",
        5900: "VNC",
        1883: "MQTT",
        88: "Kerberos",
        1080: "SOCKS",
        2049: "NFS",
        11211: "Memcached",
    }
    for port, expected in tcp_cases.items():
        actual = _detect_tcp_app(port, 40000, b"\x00\x01")
        assert actual == expected, f"tcp {port}: {actual} != {expected}"

    udp_cases = {
        69: "TFTP",
        161: "SNMP",
        514: "Syslog",
        3478: "STUN",
        5060: "SIP",
        1194: "OpenVPN",
    }
    for port, expected in udp_cases.items():
        actual = _detect_udp_app(port, 40000)
        assert actual == expected, f"udp {port}: {actual} != {expected}"
    print("PASS: test_port_to_protocol_map")


def test_payload_protocols():
    """Протоколы, которые видны по данным, а не только по номеру порта."""
    from parser.pcap_reader import _detect_tcp_app

    cases = [
        (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "HTTP2"),
        (b"GET /index.html HTTP/1.1\r\nHost: a\r\n", "HTTP"),
        (b"HTTP/1.1 200 OK\r\n", "HTTP"),
        (b"INVITE sip:bob@example.com SIP/2.0\r\nVia: ...\r\n", "SIP"),
        (b"SIP/2.0 200 OK\r\n", "SIP"),
        (b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c", "MQTT"),
        (b"\x16\x03\x01\x00\x50", "TLS"),
        (b"SSH-2.0-OpenSSH_9.6\r\n", "SSH"),
        (b"random bytes", ""),
        # Похоже на SIP-метод, но это не SIP: без «SIP/2.0» не считаем.
        (b"ACK me later, please", ""),
        # Длина сообщения есть, а заголовок DNS битый — не DNS.
        (b"\x00\x0c" + b"\xff" * 12, ""),
        (b"\x00\x20" + b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6, ""),
    ]
    for payload, expected in cases:
        actual = _detect_tcp_app(40000, 12345, payload)
        assert actual == expected, f"{payload[:20]!r}: {actual} != {expected}"
    print("PASS: test_payload_protocols")


def build_dns_tcp_frame(port: int = 5353) -> bytes:
    """Ethernet + IPv4 + TCP с DNS-запросом поверх TCP (порт не 53)."""
    import struct

    question = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question += b"\x07example\x03com\x00\x00\x01\x00\x01"
    message = struct.pack("!H", len(question)) + question

    eth = bytes.fromhex("aabbccddeeff1122334455660800")
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    total = 20 + 20 + len(message)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", 40000, port, 1, 0, 0x50, 0x18, 8192, 0, 0)
    return eth + ipv4 + tcp + message


def test_dns_over_tcp_packet():
    """DNS поверх TCP определяется по данным, даже на нестандартном порту."""
    import struct

    from parser.pcap_reader import _detect_tcp_app, read_packets

    frame = build_dns_tcp_frame()
    payload = frame[14 + 20 + 20:]
    assert _detect_tcp_app(40000, 5353, payload) == "DNS"

    path = Path(__file__).parent / "_dns_tcp_test.pcap"
    with open(path, "wb") as handle:
        handle.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        handle.write(struct.pack("!IIII", 1_700_000_000, 0, len(frame), len(frame)))
        handle.write(frame)

    try:
        packets, _linktype = read_packets(path)
        assert len(packets) == 1, len(packets)
        packet = packets[0]
        assert packet.protocol == "TCP", packet.protocol
        assert packet.app == "DNS", packet.app
        assert packet.dst_port == 5353, packet.dst_port
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_dns_over_tcp_packet")


def build_tcp_frame(payload: bytes, dst_port: int = 80, src_port: int = 40000) -> bytes:
    """Ethernet + IPv4 + TCP с произвольными данными."""
    import struct

    eth = bytes.fromhex("aabbccddeeff1122334455660800")
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    total = 20 + 20 + len(payload)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, 0x50, 0x18, 8192, 0, 0)
    return eth + ipv4 + tcp + payload


def test_names_in_packet():
    """Имена попадают в пакет: HTTP Host, TLS SNI, DNS-запрос."""
    import struct

    from parser.pcap_reader import read_packets

    http_payload = b"GET /index.html HTTP/1.1\r\nHost: Example.COM\r\n\r\n"
    sni = b"secure.example.com"
    entry = b"\x00" + struct.pack("!H", len(sni)) + sni
    sni_list = struct.pack("!H", len(entry)) + entry
    ext = struct.pack("!HH", 0, len(sni_list)) + sni_list
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    tls_payload = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    question = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question += b"\x07example\x03com\x00\x00\x01\x00\x01"
    dns_payload = question

    frames = [
        build_tcp_frame(http_payload, dst_port=80),
        build_tcp_frame(tls_payload, dst_port=443, src_port=40001),
        build_tcp_frame(struct.pack("!H", len(dns_payload)) + dns_payload,
                        dst_port=5353, src_port=40002),
    ]

    path = Path(__file__).parent / "_names_test.pcap"
    with open(path, "wb") as handle:
        handle.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            handle.write(struct.pack("!IIII", 1_700_000_000 + index, 0,
                                     len(frame), len(frame)))
            handle.write(frame)

    try:
        packets, _linktype = read_packets(path)
        assert len(packets) == 3, len(packets)
        assert packets[0].host == "example.com", packets[0].host
        assert packets[0].http_uri == "/index.html", packets[0].http_uri
        assert "example.com" in packets[0].info
        assert packets[1].sni == "secure.example.com", packets[1].sni
        assert packets[1].app == "TLS", packets[1].app
        assert packets[2].dns_name == "example.com", packets[2].dns_name
        assert packets[2].app == "DNS", packets[2].app
        assert packets[0].ttl == 64, packets[0].ttl
        assert packets[0].tcp_len == len(http_payload), packets[0].tcp_len
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_names_in_packet")


def build_ipv4_fragment(chunk: bytes, offset: int, more: bool, ident: int,
                        proto: int = 17) -> bytes:
    """Ethernet + IPv4-фрагмент с заданным смещением (в байтах)."""
    import struct

    eth = bytes.fromhex("aabbccddeeff1122334455660800")
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    total = 20 + len(chunk)
    flags_frag = ((0x2000 if more else 0) | (offset // 8))
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, flags_frag,
                       64, proto, 0, src, dst)
    return eth + ipv4 + chunk


def build_ipv6_fragment(chunk: bytes, offset: int, more: bool, ident: int,
                        next_header: int = 17) -> bytes:
    """Ethernet + IPv6 с заголовком фрагментации."""
    import struct

    eth = bytes.fromhex("aabbccddeeff11223344556686dd")
    src = bytes.fromhex("20010db8000000000000000000000001")
    dst = bytes.fromhex("20010db8000000000000000000000002")
    frag_field = ((offset // 8) << 3) | (0x0001 if more else 0)
    fragment = struct.pack("!BBHI", next_header, 0, frag_field, ident)
    ipv6 = struct.pack("!IHBB", 0x60000000, len(fragment) + len(chunk), 44, 64)
    return eth + ipv6 + src + dst + fragment + chunk


def write_pcap(path: Path, frames: list[bytes]) -> None:
    import struct

    with open(path, "wb") as handle:
        handle.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            handle.write(struct.pack("!IIII", 1_700_000_000 + index, 0,
                                     len(frame), len(frame)))
            handle.write(frame)


def test_ipv4_reassembly():
    """Два фрагмента IPv4 собираются в один UDP-пакет."""
    import struct

    from parser.pcap_reader import read_packets

    udp = struct.pack("!HHHH", 5000, 53, 8 + 60, 0) + b"A" * 60
    first, second = udp[:48], udp[48:]
    frames = [
        build_ipv4_fragment(first, 0, True, ident=0x1234),
        build_ipv4_fragment(second, 48, False, ident=0x1234),
    ]

    path = Path(__file__).parent / "_frag_v4_test.pcap"
    write_pcap(path, frames)
    try:
        packets, _ = read_packets(path)
        assert len(packets) == 2
        assert packets[0].protocol == "IPv4", packets[0].protocol
        assert "Фрагмент IPv4" in packets[0].info, packets[0].info

        assembled = packets[1]
        assert assembled.reassembled is True, assembled.info
        assert assembled.fragments == 2, assembled.fragments
        assert assembled.transport == "UDP", assembled.transport
        assert assembled.src_port == 5000 and assembled.dst_port == 53
        assert assembled.app == "DNS", assembled.app
        assert assembled.info.endswith("собран из 2 фрагментов"), assembled.info
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_ipv4_reassembly")


def test_ipv6_reassembly():
    """Фрагменты IPv6 тоже собираются."""
    import struct

    from parser.pcap_reader import read_packets

    udp = struct.pack("!HHHH", 6000, 5353, 8 + 40, 0) + b"B" * 40
    first, second = udp[:40], udp[40:]
    frames = [
        build_ipv6_fragment(first, 0, True, ident=0xDEADBEEF),
        build_ipv6_fragment(second, 40, False, ident=0xDEADBEEF),
    ]

    path = Path(__file__).parent / "_frag_v6_test.pcap"
    write_pcap(path, frames)
    try:
        packets, _ = read_packets(path)
        assert len(packets) == 2
        assembled = packets[1]
        assert assembled.reassembled is True, assembled.info
        assert assembled.transport == "UDP", assembled.transport
        assert assembled.src_port == 6000 and assembled.dst_port == 5353
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_ipv6_reassembly")


def test_read_payloads_lazy():
    """Тела TCP читаются по требованию — только для нужных кадров."""
    from parser.pcap_reader import read_payloads

    sample = Path(__file__).parent / "sample_traffic.pcap"
    payloads = read_payloads(sample, {6, 7})
    assert set(payloads) == {6, 7}, sorted(payloads)
    assert b"HTTP" in payloads[6] or b"GET" in payloads[6], payloads[6]
    assert len(payloads[6]) == 80, len(payloads[6])

    # Несуществующие и пустые кадры не попадают в результат.
    assert read_payloads(sample, {1, 100500}) == {}
    assert read_payloads(sample, []) == {}
    assert read_payloads(Path(__file__).parent / "_no_such.pcap", {6}) == {}

    # UDP-датаграммы тоже отдают данные — для «Поток UDP».
    udp_payloads = read_payloads(sample, {2})
    assert set(udp_payloads) == {2}, udp_payloads

    # Ограничение объёма останавливает чтение.
    limited = read_payloads(sample, {6, 7}, max_bytes=1)
    assert len(limited) == 1, limited
    print("PASS: test_read_payloads_lazy")


def build_udp_frame(payload: bytes, dst_port: int, src_port: int = 40000) -> bytes:
    """Ethernet + IPv4 + UDP."""
    import struct

    eth = bytes.fromhex("aabbccddeeff1122334455660800")
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    total = 20 + 8 + len(payload)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 17, 0, src, dst)
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return eth + ipv4 + udp + payload


def build_ip_proto_frame(proto: int, payload: bytes) -> bytes:
    """Ethernet + IPv4 с произвольным номером протокола (IGMP, GRE, …)."""
    import struct

    eth = bytes.fromhex("aabbccddeeff1122334455660800")
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    total = 20 + len(payload)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, proto, 0, src, dst)
    return eth + ipv4 + payload


def build_icmpv6_frame(payload: bytes) -> bytes:
    """Ethernet + IPv6 + ICMPv6."""
    import struct

    eth = bytes.fromhex("aabbccddeeff11223344556686dd")
    src = bytes.fromhex("20010db8000000000000000000000001")
    dst = bytes.fromhex("fe800000000000000000000000000001")
    ipv6 = struct.pack("!IHBB", 0x60000000, len(payload), 58, 64)
    return eth + ipv6 + src + dst + payload


def test_service_port_map():
    """Новые сервисы узнаются по портам."""
    from parser.pcap_reader import read_packets

    cases = [
        ("LLMNR", build_udp_frame(b"name", 5355)),
        ("SSDP", build_udp_frame(b"M-SEARCH", 1900)),
        ("RADIUS", build_udp_frame(b"\x01\x00", 1812)),
        ("DHCPv6", build_udp_frame(b"\x01\x00", 547)),
        ("NetBIOS", build_udp_frame(b"\x00\x00", 137)),
        ("L2TP", build_udp_frame(b"\x00\x00", 1701)),
        ("IPsec", build_udp_frame(b"\x00" * 28, 500)),
        ("NetBIOS", build_tcp_frame(b"\x00" * 20, dst_port=139)),
        ("BGP", build_tcp_frame(b"\xff" * 19, dst_port=179)),
        ("XMPP", build_tcp_frame(b"<stream", dst_port=5222)),
        ("IRC", build_tcp_frame(b"NICK bot\r\n", dst_port=6667)),
    ]

    path = Path(__file__).parent / "_ports_test.pcap"
    write_pcap(path, [frame for _app, frame in cases])
    try:
        packets, _ = read_packets(path)
        assert len(packets) == len(cases)
        for expected, packet in zip(cases, packets):
            app = expected[0]
            assert packet.app == app, (packet.app, app, packet.info)
            assert app in packet.info or packet.info, packet.info
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_service_port_map")


def test_ip_protocols_and_icmpv6():
    """IGMP/GRE/OSPF по номеру протокола, ICMPv6 — отдельным именем."""
    from parser.pcap_reader import read_packets

    frames = [
        build_ip_proto_frame(2, b"\x16\x00\xfa\xf9\x00\x00\x00\x01"),
        build_ip_proto_frame(47, b"\x00\x00\x08\x00"),
        build_ip_proto_frame(89, b"\x02\x01" + b"\x00" * 20),
        build_icmpv6_frame(b"\x80\x00" + b"\x00" * 6),
    ]

    path = Path(__file__).parent / "_ipproto_test.pcap"
    write_pcap(path, frames)
    try:
        packets, _ = read_packets(path)
        assert packets[0].protocol == "IGMP", packets[0].protocol
        assert packets[1].protocol == "GRE", packets[1].protocol
        assert packets[2].protocol == "OSPF", packets[2].protocol

        icmp = packets[3]
        assert icmp.protocol == "ICMPv6", icmp.protocol
        assert icmp.transport == "ICMPv6", icmp.transport
        assert icmp.icmp_type == 128, icmp.icmp_type
        assert "Echo request" in icmp.info, icmp.info
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_ip_protocols_and_icmpv6")


def write_many_packets(path: Path, count: int) -> None:
    """Простой pcap с count TCP-пакетами: нужен, чтобы прогресс успел сработать."""
    import struct

    frame = (
        bytes.fromhex("aabbccddeeff1122334455660800")
        + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0x4000, 64, 6, 0,
                      bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
        + struct.pack("!HHIIBBHHH", 40000, 80, 1, 1, 0x50, 0x18, 65535, 0, 0)
    )
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index in range(count):
            handle.write(struct.pack("<IIII", 1700000000 + index, 0,
                                     len(frame), len(frame)))
            handle.write(frame)


def test_progress_reports_and_cancel_stops():
    """Прогресс доходит до 100 %, а отмена прекращает чтение с понятной ошибкой."""
    path = Path(__file__).parent / "_many_packets.pcap"
    write_many_packets(path, 600)
    try:
        seen: list = []
        packets, _ = read_packets(path, progress=seen.append)
        assert len(packets) == 600, len(packets)
        assert seen, "прогресс не вызывался"
        assert seen[-1] == 1.0, seen[-1]
        numbers = [value for value in seen if value is not None]
        assert numbers == sorted(numbers), numbers[:5]

        try:
            read_packets(path, should_stop=lambda: True)
        except PcapError as exc:
            assert "отменено" in str(exc), str(exc)
        else:
            raise AssertionError("отмена не сработала: чтение не прервалось")
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_progress_reports_and_cancel_stops")


if __name__ == "__main__":
    tests = [
        test_pcap_packet_count,
        test_pcapng_packet_count,
        test_pcap_and_pcapng_are_equal,
        test_arp_packet,
        test_dns_packet,
        test_http_packet,
        test_tcp_syn_has_no_app,
        test_tls_packet,
        test_quic_packet,
        test_ssh_packet,
        test_icmp_packet,
        test_mac_addresses,
        test_relative_time,
        test_missing_file,
        test_broken_file,
        test_port_to_protocol_map,
        test_payload_protocols,
        test_dns_over_tcp_packet,
        test_names_in_packet,
        test_ipv4_reassembly,
        test_ipv6_reassembly,
        test_read_payloads_lazy,
        test_service_port_map,
        test_ip_protocols_and_icmpv6,
        test_progress_reports_and_cancel_stops,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            print(f"FAIL: {test.__name__}: {exc}")
            failed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: {test.__name__}: {exc}")
            failed += 1

    print("")
    print("-" * 40)
    print(f"Пройдено: {len(tests) - failed}/{len(tests)}")
    if failed:
        sys.exit(1)
    print("Все тесты прошли!")
