"""Тесты статистики: иерархия протоколов, разговоры, узлы, сводка."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.pcap_reader import Packet
from parser.stats import (
    Conversation,
    conversations,
    endpoint_label,
    endpoints,
    format_bytes,
    format_duration,
    protocol_hierarchy,
    summary,
)


def _tcp(number, src_ip, src_port, dst_ip, dst_port, length=100, app="HTTP",
         timestamp=0.0):
    return Packet(
        number=number,
        timestamp=timestamp,
        length=length,
        wire_length=length,
        protocol="TCP",
        transport="TCP",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        app=app,
    )


def _udp(number, src_ip, src_port, dst_ip, dst_port, length=60, app="DNS",
         timestamp=0.0):
    return Packet(
        number=number,
        timestamp=timestamp,
        length=length,
        wire_length=length,
        protocol="UDP",
        transport="UDP",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        app=app,
    )


def _icmp(number, src_ip, dst_ip, length=40, timestamp=0.0):
    return Packet(
        number=number,
        timestamp=timestamp,
        length=length,
        wire_length=length,
        protocol="ICMP",
        transport="ICMP",
        src_ip=src_ip,
        dst_ip=dst_ip,
    )


def sample_packets():
    return [
        _tcp(1, "10.88.0.1", 1234, "10.88.0.2", 80, length=100, timestamp=0.0),
        _tcp(2, "10.88.0.2", 80, "10.88.0.1", 1234, length=400, timestamp=0.5),
        _udp(3, "10.88.0.1", 5353, "203.0.113.53", 53, length=60, timestamp=1.0),
        _icmp(4, "10.88.0.1", "10.88.0.2", length=40, timestamp=2.5),
    ]


def test_hierarchy_counts():
    rows = protocol_hierarchy(sample_packets())
    by_name = {row.name: row for row in rows}

    assert by_name["TCP"].packets == 2, by_name["TCP"].packets
    assert by_name["TCP"].bytes == 500, by_name["TCP"].bytes
    assert by_name["UDP"].packets == 1
    assert by_name["ICMP"].packets == 1
    assert by_name["HTTP"].level == 1, "прикладной протокол должен быть вложенным"
    assert by_name["HTTP"].parent == "TCP", by_name["HTTP"].parent
    assert by_name["HTTP"].packets == 2
    assert by_name["DNS"].level == 1
    assert by_name["DNS"].parent == "UDP", by_name["DNS"].parent
    print("PASS: test_hierarchy_counts")


def test_hierarchy_shares():
    rows = protocol_hierarchy(sample_packets())
    total = [row for row in rows if row.name == "Всего"][0]
    assert total.packets == 4, total.packets
    assert total.bytes == 600, total.bytes
    assert total.share == 100.0

    tcp = [row for row in rows if row.name == "TCP"][0]
    assert abs(tcp.share - 50.0) < 1e-9, tcp.share
    print("PASS: test_hierarchy_shares")


def test_conversations():
    pairs = conversations(sample_packets())
    assert len(pairs) == 3, len(pairs)

    biggest = pairs[0]
    assert isinstance(biggest, Conversation)
    assert {biggest.endpoint_a, biggest.endpoint_b} == {
        "10.88.0.1:1234", "10.88.0.2:80"
    }
    assert biggest.total_packets == 2
    assert biggest.total_bytes == 500
    assert biggest.packets_a_to_b + biggest.packets_b_to_a == 2
    assert biggest.bytes_a_to_b + biggest.bytes_b_to_a == 500
    print("PASS: test_conversations")


def test_conversations_limit():
    pairs = conversations(sample_packets(), limit=2)
    assert len(pairs) == 2, len(pairs)
    assert pairs[0].total_bytes >= pairs[1].total_bytes
    print("PASS: test_conversations_limit")


def test_endpoints():
    nodes = endpoints(sample_packets())
    by_address = {node.address: node for node in nodes}

    client = by_address["10.88.0.1"]
    assert client.packets_sent == 3, client.packets_sent
    assert client.packets_received == 1, client.packets_received
    assert client.bytes_sent == 200, client.bytes_sent
    assert client.bytes_received == 400, client.bytes_received
    assert client.total_bytes == 600

    server = by_address["10.88.0.2"]
    assert server.packets_sent == 1, server.packets_sent
    assert server.packets_received == 2
    print("PASS: test_endpoints")


def test_endpoint_label():
    packet = sample_packets()[0]
    assert endpoint_label(packet, source=True) == "10.88.0.1:1234"
    assert endpoint_label(packet, source=False) == "10.88.0.2:80"
    icmp = sample_packets()[3]
    assert endpoint_label(icmp, source=True) == "10.88.0.1"
    print("PASS: test_endpoint_label")


def test_summary():
    data = summary(sample_packets())
    assert data["packets"] == 4
    assert data["bytes"] == 600
    assert abs(data["duration"] - 2.5) < 1e-9, data["duration"]
    assert abs(data["average_length"] - 150.0) < 1e-9
    assert data["addresses"] == 3, data["addresses"]
    assert data["protocols"] == 3, data["protocols"]
    print("PASS: test_summary")


def test_empty_input():
    assert protocol_hierarchy([]) == []
    assert conversations([]) == []
    assert endpoints([]) == []
    data = summary([])
    assert data["packets"] == 0 and data["duration"] == 0.0
    print("PASS: test_empty_input")


def test_format_helpers():
    assert format_bytes(512) == "512 Б", format_bytes(512)
    assert format_bytes(1536) == "1.5 КБ", format_bytes(1536)
    assert format_bytes(1048576) == "1.0 МБ"
    assert format_duration(0.25).endswith("с")
    assert "мин" in format_duration(125)
    assert "ч" in format_duration(7300)
    print("PASS: test_format_helpers")


def test_real_file():
    """Иерархия по настоящему дампу покрывает все пакеты файла."""
    from parser.pcap_handler import PcapHandler

    sample = Path(__file__).parent / "sample_traffic.pcap"
    packets, error = PcapHandler().load(sample)
    assert error is None, error

    rows = protocol_hierarchy(packets)
    total = [row for row in rows if row.name == "Всего"][0]
    assert total.packets == len(packets), (total.packets, len(packets))

    top_level = [row for row in rows if row.level == 0 and row.name != "Всего"]
    assert sum(row.packets for row in top_level) == len(packets), (
        sum(row.packets for row in top_level),
        len(packets),
    )

    pairs = conversations(packets)
    assert pairs, "разговоры не найдены"
    assert pairs[0].total_bytes > 0
    print("PASS: test_real_file")


def test_hosts():
    """Топ сайтов и доменов: HTTP Host, TLS SNI и DNS в одном списке."""
    from parser.stats import hosts

    packets = [
        Packet(number=1, timestamp=0.0, length=100, wire_length=100,
               protocol="TCP", transport="TCP", app="HTTP", host="example.com"),
        Packet(number=2, timestamp=0.0, length=100, wire_length=100,
               protocol="TCP", transport="TCP", app="HTTP", host="example.com"),
        Packet(number=3, timestamp=0.0, length=120, wire_length=120,
               protocol="TCP", transport="TCP", app="TLS", sni="secure.example.com"),
        Packet(number=4, timestamp=0.0, length=80, wire_length=80,
               protocol="UDP", transport="UDP", app="DNS", dns_name="test.org"),
        Packet(number=5, timestamp=0.0, length=60, wire_length=60,
               protocol="UDP", transport="UDP", app="DNS"),
    ]

    rows = hosts(packets)
    assert len(rows) == 3, len(rows)
    assert rows[0].name == "example.com", rows[0]
    assert rows[0].packets == 2
    assert rows[0].source == "HTTP"
    assert {row.name for row in rows} == {"example.com", "secure.example.com", "test.org"}
    assert hosts(packets, limit=1)[0].name == "example.com"
    assert hosts([]) == []
    print("PASS: test_hosts")


def test_stats_page_filters():
    """Строка статистики превращается в рабочий фильтр, как и обещано в меню."""
    from gui.stats_view import conversation_filter, node_filter, site_filter
    from parser.matcher import compile_filter

    site = site_filter("example.com")
    assert 'http.host contains "example.com"' in site, site
    assert "tls.handshake.extensions_server_name" in site, site
    assert 'dns.qry.name contains "example.com"' in site, site

    assert node_filter("10.88.0.1") == "ip.addr==10.88.0.1", node_filter("10.88.0.1")
    assert node_filter("aa:bb:cc:dd:ee:ff") == "eth.addr==aa:bb:cc:dd:ee:ff"
    assert node_filter("?") == ""
    assert node_filter("не адрес") == ""

    pair = conversation_filter("10.88.0.1:5000  ↔  203.0.113.53:443")
    assert pair == "(ip.addr==10.88.0.1 and ip.addr==203.0.113.53)", pair
    assert conversation_filter("203.0.113.53  ↔  203.0.113.54") == (
        "(ip.addr==203.0.113.53 and ip.addr==203.0.113.54)"
    )
    assert conversation_filter("мусор") == ""

    for text in (site, node_filter("10.88.0.1"), pair):
        compile_filter(text)


def main() -> int:
    tests = [
        test_hierarchy_counts,
        test_hierarchy_shares,
        test_conversations,
        test_conversations_limit,
        test_endpoints,
        test_endpoint_label,
        test_summary,
        test_empty_input,
        test_format_helpers,
        test_real_file,
        test_hosts,
        test_stats_page_filters,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            print(f"FAIL: {test.__name__}: {exc}")
            failed += 1
        except Exception as exc:                       # noqa: BLE001
            print(f"FAIL: {test.__name__}: {type(exc).__name__}: {exc}")
            failed += 1

    print("")
    print("-" * 40)
    print(f"Пройдено: {len(tests) - failed}/{len(tests)}")
    if failed:
        print("Есть падения.")
        return 1
    print("Все тесты прошли!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
