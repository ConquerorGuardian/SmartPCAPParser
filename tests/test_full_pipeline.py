"""
Сквозной тест: команда -> сущности -> display-фильтр -> пакеты -> таблица.
Запуск: python -m tests.test_full_pipeline
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.engine import NaturalLanguageFilterEngine
from parser.filters import generate_filter
from parser.pcap_handler import PcapHandler

SAMPLE = Path(__file__).parent / "sample_traffic.pcap"
ENGINE = NaturalLanguageFilterEngine()
HANDLER = PcapHandler(preview_count=200)


def run(command: str):
    query = ENGINE.parse(command)
    filter_string = generate_filter(query)
    result = HANDLER.load_and_filter(SAMPLE, filter_string)
    return query, filter_string, result


def test_ip_direction():
    query, filter_string, result = run("пакеты от 192.168.1.10")
    assert filter_string == "ip.src==192.168.1.10", filter_string
    assert result.error is None
    assert result.matched_packets > 0
    assert result.rows[0].source.startswith("192.168.1.10")
    print("PASS: test_ip_direction")


def test_http_with_ip():
    query, filter_string, result = run("покажи http трафик с айпи 192.168.1.10")
    assert filter_string == "ip.addr==192.168.1.10 and http", filter_string
    assert result.matched_packets == 2, result.matched_packets
    assert all("HTTP" in row.info for row in result.rows)
    print("PASS: test_http_with_ip")


def test_port_list():
    query, filter_string, result = run("покажи пакеты на порт 80 и 443")
    assert filter_string == "tcp.port==80,443", filter_string
    assert result.matched_packets == 5, result.matched_packets
    print("PASS: test_port_list")


def test_mac():
    query, filter_string, result = run("покажи пакеты с мак адресом aa:bb:cc:dd:ee:01")
    assert filter_string == "eth.addr==aa:bb:cc:dd:ee:01"
    assert result.matched_packets == 13, result.matched_packets
    print("PASS: test_mac")


def test_dns():
    query, filter_string, result = run("найди dns запросы")
    assert filter_string == "dns"
    assert result.matched_packets == 2
    assert all(row.protocol == "UDP" and "DNS" in row.info for row in result.rows)
    print("PASS: test_dns")


def test_no_entities():
    query, filter_string, result = run("просто текст без индикаторов")
    assert filter_string == ""
    print("PASS: test_no_entities")


def test_negation():
    """«всё кроме http» действительно убирает HTTP, а не показывает его."""
    query, filter_string, result = run("покажи всё кроме http")
    assert filter_string == "not (http)", filter_string
    assert result.error is None
    assert result.matched_packets == 11, result.matched_packets
    assert all("HTTP" not in row.info for row in result.rows)
    assert all(row.protocol != "HTTP" for row in result.rows)
    print("PASS: test_negation")


def test_port_range():
    """Диапазон портов доходит до вычислителя и реально фильтрует."""
    query, filter_string, result = run("покажи порты 79-81")
    assert filter_string == "tcp.port in {79..81}", filter_string
    assert result.matched_packets == 4, result.matched_packets
    assert all(row.protocol == "TCP" for row in result.rows)
    print("PASS: test_port_range")


def test_ipv6_pipeline():
    """IPv6-фильтр компилируется и не роняет конвейер на IPv4-дампе."""
    query, filter_string, result = run("покажи пакеты с айпи 2001:db8::1")
    assert filter_string == "ipv6.addr==2001:db8::1", filter_string
    assert result.error is None
    assert result.matched_packets == 0, result.matched_packets
    print("PASS: test_ipv6_pipeline")


def test_host_pipeline():
    """«покажи сайт example.com» находит имя в DNS-пакетах."""
    query, filter_string, result = run("покажи сайт example.com")
    assert query.has_host(), query.entities
    assert "http.host contains" in filter_string, filter_string
    assert result.error is None
    assert result.matched_packets == 3, result.matched_packets
    assert all("example.com" in row.info for row in result.rows)
    print("PASS: test_host_pipeline")


if __name__ == "__main__":
    tests = [
        test_ip_direction,
        test_http_with_ip,
        test_port_list,
        test_mac,
        test_dns,
        test_no_entities,
        test_negation,
        test_port_range,
        test_ipv6_pipeline,
        test_host_pipeline,
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
