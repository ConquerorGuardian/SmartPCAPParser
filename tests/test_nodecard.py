"""Тесты карточки узла: счёт по адресу, порты, собеседники."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.node_card import (  # noqa: E402
    build_node_card,
    format_node_card,
    is_local_address,
    looks_like_ip,
)
from parser.pcap_reader import read_packets  # noqa: E402

SAMPLE = Path(__file__).parent / "sample_traffic.pcap"
PACKETS, _LINKTYPE = read_packets(SAMPLE)


def test_counts_and_bytes():
    """Направления и байты считаются по адресу, а не по всему файлу."""
    card = build_node_card(PACKETS, "192.168.1.10")
    assert card is not None
    assert card.total == 11, card.total
    assert card.sent == 7, card.sent
    assert card.received == 4, card.received
    assert card.bytes_sent == 516, card.bytes_sent
    assert card.bytes_received == 330, card.bytes_received
    assert card.total_bytes == 846, card.total_bytes
    print("PASS: test_counts_and_bytes")


def test_peers_and_ports():
    """Собеседники идут по убыванию пакетов, порты только свои."""
    card = build_node_card(PACKETS, "192.168.1.10")
    assert card is not None
    assert card.peers[0].address == "93.184.216.34", card.peers[0]
    assert card.peers[0].packets == 4, card.peers[0]
    ports = {(item.port, item.protocol): item.packets for item in card.ports}
    assert ports[(40000, "TCP")] == 4, ports
    assert ports[(10000, "UDP")] == 2, ports
    assert (80, "TCP") not in ports, ports
    print("PASS: test_peers_and_ports")


def test_local_address_rules():
    """Локальные адреса отличаются от внешних, multicast не локальный."""
    assert is_local_address("192.168.1.10")
    assert is_local_address("10.0.0.5")
    assert is_local_address("127.0.0.1")
    assert is_local_address("fe80::1")
    assert not is_local_address("8.8.8.8")
    assert not is_local_address("224.0.0.251")
    assert not is_local_address("не-адрес")
    assert looks_like_ip("93.184.216.34")
    assert not looks_like_ip("example.com")
    assert not looks_like_ip("e8:b0:c5:38:45:87")
    print("PASS: test_local_address_rules")


def test_missing_address_and_text():
    """Неизвестный адрес даёт None, а текст карточки читается человеком."""
    assert build_node_card(PACKETS, "10.9.9.9") is None
    assert build_node_card(PACKETS, "") is None
    card = build_node_card(PACKETS, "192.168.1.10")
    assert card is not None
    text = format_node_card(card)
    assert "Узел 192.168.1.10" in text
    assert "локальная сеть" in text
    assert "Собеседники:" in text
    print("PASS: test_missing_address_and_text")


if __name__ == "__main__":
    tests = [
        test_counts_and_bytes,
        test_peers_and_ports,
        test_local_address_rules,
        test_missing_address_and_text,
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
