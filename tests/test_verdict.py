"""Тесты вердикта по файлу: находки, тексты, команды."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.pcap_reader import Packet
from parser.verdict import (
    Finding,
    Verdict,
    build_verdict,
    detect_arp_noise,
    detect_dns_gap,
    detect_resets,
    detect_undecodable,
    detect_unanswered_syn,
    detect_watch_ports,
    format_verdict,
)

SYN, ACK, PSH, RST = 0x02, 0x10, 0x08, 0x04


def packet(number, protocol="TCP", src_ip="192.168.1.10", dst_ip="10.0.0.5",
           src_port=None, dst_port=None, flags=0, length=60, app="",
           timestamp=0.0, payload=b"", info=""):
    return Packet(
        number=number,
        timestamp=timestamp,
        length=length,
        wire_length=length,
        protocol=protocol,
        transport=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        app=app,
        payload=payload,
        info=info,
    )


def scan_traffic():
    """Четыре попытки подключения, ответа нет."""
    return [
        packet(1, src_ip="192.168.1.10", dst_ip="10.0.0.5", src_port=50001,
               dst_port=22, flags=SYN),
        packet(2, src_ip="192.168.1.10", dst_ip="10.0.0.5", src_port=50002,
               dst_port=23, flags=SYN),
        packet(3, src_ip="192.168.1.10", dst_ip="10.0.0.5", src_port=50003,
               dst_port=80, flags=SYN),
        packet(4, src_ip="192.168.1.10", dst_ip="10.0.0.5", src_port=50004,
               dst_port=443, flags=SYN),
    ]


def clean_traffic():
    """Обычный HTTP-обмен без сюрпризов."""
    return [
        packet(1, src_port=50000, dst_port=80, flags=SYN),
        packet(2, src_ip="10.0.0.5", dst_ip="192.168.1.10", src_port=80,
               dst_port=50000, flags=SYN | ACK),
        packet(3, src_port=50000, dst_port=80, flags=PSH | ACK, app="HTTP"),
        packet(4, src_ip="10.0.0.5", dst_ip="192.168.1.10", src_port=80,
               dst_port=50000, flags=PSH | ACK, app="HTTP"),
    ]


def test_scan_detected():
    findings = detect_unanswered_syn(scan_traffic())
    assert len(findings) == 1, findings
    finding = findings[0]
    assert "без ответа" in finding.title.lower(), finding.title
    assert "сканирование" in finding.detail, finding.detail
    assert finding.severity == "warning", finding.severity
    assert finding.command == "покажи пакеты к 10.0.0.5", finding.command
    print("PASS: test_scan_detected")


def test_answered_syn_is_quiet():
    assert detect_unanswered_syn(clean_traffic()) == []
    print("PASS: test_answered_syn_is_quiet")


def test_resets():
    traffic = [
        packet(1, src_port=50000, dst_port=80, flags=RST),
        packet(2, src_port=50001, dst_port=80, flags=RST),
        packet(3, src_port=50002, dst_port=80, flags=RST),
    ]
    findings = detect_resets(traffic)
    assert len(findings) == 1
    assert "3 соединений сброшено" in findings[0].detail, findings[0].detail
    assert findings[0].severity == "warning"
    print("PASS: test_resets")


def test_dns_gap():
    traffic = [
        packet(1, protocol="UDP", dst_ip="8.8.8.8", src_port=53000,
               dst_port=53, app="DNS"),
        packet(2, protocol="UDP", dst_ip="8.8.8.8", src_port=53001,
               dst_port=53, app="DNS"),
    ]
    findings = detect_dns_gap(traffic)
    assert len(findings) == 1, findings
    assert "2 запросов и только 0 ответов" in findings[0].detail, findings[0].detail
    assert findings[0].severity == "warning"
    print("PASS: test_dns_gap")


def test_arp_noise():
    traffic = [
        packet(number, protocol="ARP", src_ip="192.168.1.10", dst_ip="192.168.1.1")
        for number in range(1, 7)
    ] + [
        packet(number, src_port=50000, dst_port=80, flags=PSH | ACK)
        for number in range(7, 11)
    ]
    findings = detect_arp_noise(traffic)
    assert len(findings) == 1, findings
    assert "ARP" in findings[0].title
    assert "60%" in findings[0].detail, findings[0].detail
    print("PASS: test_arp_noise")


def test_watch_ports_outbound():
    traffic = [
        packet(1, src_ip="192.168.1.10", dst_ip="203.0.113.5", src_port=51000,
               dst_port=445, flags=PSH | ACK),
        packet(2, src_ip="192.168.1.10", dst_ip="203.0.113.5", src_port=51001,
               dst_port=445, flags=PSH | ACK),
    ]
    findings = detect_watch_ports(traffic)
    assert len(findings) == 1, findings
    assert findings[0].title == "Обращения к SMB", findings[0].title
    assert findings[0].severity == "warning"
    assert findings[0].command == "покажи пакеты на порт 445"
    print("PASS: test_watch_ports_outbound")


def test_watch_ports_internal_is_quiet():
    """Внутри локальной сети SMB — норма, не пугаем."""
    traffic = [
        packet(1, src_ip="192.168.1.10", dst_ip="192.168.1.20", src_port=51000,
               dst_port=445, flags=PSH | ACK),
    ]
    assert detect_watch_ports(traffic) == []
    print("PASS: test_watch_ports_internal_is_quiet")


def test_undecodable_frames():
    """Экзотический linktype не должен выглядеть как «всё хорошо»."""
    traffic = [
        packet(number, protocol="?",
               info="Кадр этого типа не разбирается (linktype 18)")
        for number in range(1, 5)
    ]
    findings = detect_undecodable(traffic)
    assert len(findings) == 1, findings
    assert "не разобраны" in findings[0].detail
    assert "linktype 18" in findings[0].detail
    assert findings[0].severity == "warning"

    # Один случайный «?» на фоне нормального трафика — не повод паниковать.
    mixed = clean_traffic() + [packet(5, protocol="?")]
    assert detect_undecodable(mixed) == []
    print("PASS: test_undecodable_frames")


def test_build_verdict_scan():
    verdict = build_verdict(scan_traffic())
    assert verdict.packets == 4
    assert verdict.headline.startswith("4 пакетов"), verdict.headline
    assert "Больше всего: TCP 4" in verdict.overview, verdict.overview
    assert verdict.findings
    assert verdict.worst_severity == "warning", verdict.worst_severity
    assert verdict.has_commands()
    print("PASS: test_build_verdict_scan")


def test_build_verdict_clean():
    verdict = build_verdict(clean_traffic())
    assert len(verdict.findings) == 1, verdict.findings
    assert "Явных проблем нет" in verdict.findings[0].title
    assert verdict.findings[0].command == ""
    assert verdict.worst_severity == "info"
    print("PASS: test_build_verdict_clean")


def test_build_verdict_empty():
    verdict = build_verdict([])
    assert "нет пакетов" in verdict.headline.lower(), verdict.headline
    assert verdict.findings == []
    print("PASS: test_build_verdict_empty")


def test_format_verdict():
    text = format_verdict(build_verdict(scan_traffic()))
    assert "4 пакетов" in text
    assert "•" in text
    assert "команда: покажи пакеты к 10.0.0.5" in text, text
    print("PASS: test_format_verdict")


def test_real_file_verdict():
    from parser.pcap_handler import PcapHandler

    sample = Path(__file__).parent / "sample_traffic.pcap"
    packets, error = PcapHandler().load(sample)
    assert error is None, error

    verdict = build_verdict(packets)
    assert verdict.packets == len(packets)
    assert verdict.headline
    assert verdict.overview
    assert verdict.findings, "вердикт всегда что-то говорит"
    assert isinstance(verdict.findings[0], Finding)
    assert isinstance(verdict, Verdict)
    print("PASS: test_real_file_verdict")


def test_port_scan_detector():
    """Много портов с одного адреса — скан; пара портов — нет."""
    from parser.verdict import detect_port_scan

    scanner = [
        packet(index, src_ip="192.168.1.10", dst_ip="10.0.0.5",
               src_port=40000 + index, dst_port=port, flags=SYN)
        for index, port in enumerate(range(20, 60), start=1)
    ]
    findings = detect_port_scan(scanner)
    assert len(findings) == 1, findings
    assert findings[0].severity == "critical", findings[0].severity
    assert "40" in findings[0].detail
    assert findings[0].command == "покажи пакеты к 10.0.0.5"

    # Пять портов — обычная работа, не скан.
    few = [packet(index, dst_port=port, flags=SYN)
           for index, port in enumerate(range(80, 85), start=1)]
    assert detect_port_scan(few) == []
    print("PASS: test_port_scan_detector")


def test_icmp_errors_detector():
    """ICMP «недоступно» повторяется — предупреждаем."""
    from parser.verdict import detect_icmp_errors

    errors = []
    for index, icmp_type in enumerate((3, 3, 11), start=1):
        item = packet(index, protocol="ICMP", src_ip="10.0.0.1",
                      dst_ip="192.168.1.10")
        item.icmp_type = icmp_type
        errors.append(item)
    findings = detect_icmp_errors(errors)
    assert len(findings) == 1, findings
    assert "3" in findings[0].detail
    assert findings[0].command == "покажи icmp трафик"

    assert detect_icmp_errors(errors[:2]) == []
    echo = [packet(1, protocol="ICMP")]
    echo[0].icmp_type = 8
    assert detect_icmp_errors(echo * 3) == []
    print("PASS: test_icmp_errors_detector")


def test_broadcast_detector():
    """Много broadcast/multicast — шум или петля."""
    from parser.verdict import detect_broadcast_storm

    noise = []
    for index in range(1, 26):
        item = packet(index, protocol="UDP", src_ip="192.168.1.10",
                      dst_ip="255.255.255.255", dst_port=5353)
        item.dst_mac = "ff:ff:ff:ff:ff:ff"
        noise.append(item)
    normal = [packet(index, dst_ip="10.0.0.5", dst_port=80,
                     src_ip="192.168.1.10") for index in range(1, 26)]
    packets = noise + normal
    findings = detect_broadcast_storm(packets)
    assert len(findings) == 1, findings
    assert "50%" in findings[0].detail, findings[0].detail

    assert detect_broadcast_storm(normal) == []
    print("PASS: test_broadcast_detector")


def test_top_talker_detector():
    """Один узел отправляет почти всё — называем его."""
    from parser.verdict import detect_top_talker

    packets = [
        packet(index, src_ip="192.168.1.50", dst_ip="10.0.0.5",
               src_port=40000 + index, dst_port=443, length=1400, flags=PSH | ACK)
        for index in range(1, 150)
    ]
    packets.append(packet(150, src_ip="192.168.1.10", dst_ip="10.0.0.5",
                          src_port=50000, dst_port=80, length=60, flags=PSH | ACK))
    findings = detect_top_talker(packets)
    assert len(findings) == 1, findings
    assert "192.168.1.50" in findings[0].detail
    assert findings[0].command == "покажи пакеты от 192.168.1.50"
    assert detect_top_talker(packets[:10]) == []
    print("PASS: test_top_talker_detector")


def test_verdict_mentions_hosts():
    """В обзоре вердикта видны сайты и домены из трафика."""
    from parser.stats import hosts

    items = clean_traffic()
    items[0].host = "example.com"
    verdict = build_verdict(items)
    assert "example.com" in verdict.overview, verdict.overview
    assert hosts(items)[0].name == "example.com"
    print("PASS: test_verdict_mentions_hosts")


def main() -> int:
    tests = [
        test_scan_detected,
        test_answered_syn_is_quiet,
        test_resets,
        test_dns_gap,
        test_arp_noise,
        test_watch_ports_outbound,
        test_watch_ports_internal_is_quiet,
        test_undecodable_frames,
        test_port_scan_detector,
        test_icmp_errors_detector,
        test_broadcast_detector,
        test_top_talker_detector,
        test_verdict_mentions_hosts,
        test_build_verdict_scan,
        test_build_verdict_clean,
        test_build_verdict_empty,
        test_format_verdict,
        test_real_file_verdict,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            print("FAIL: {}: {}".format(test.__name__, exc))
            failed += 1
        except Exception as exc:                       # noqa: BLE001
            print("FAIL: {}: {}: {}".format(test.__name__, type(exc).__name__, exc))
            failed += 1

    print("")
    print("-" * 40)
    print("Пройдено: {}/{}".format(len(tests) - failed, len(tests)))
    if failed:
        print("Есть падения.")
        return 1
    print("Все тесты прошли!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
