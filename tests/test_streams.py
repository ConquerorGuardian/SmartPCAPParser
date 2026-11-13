"""
Тесты сборки TCP-потоков ("Follow TCP stream").
Запуск: python -m tests.test_streams
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.pcap_reader import read_packets
from parser.streams import (
    MODE_TEXT,
    VIEW_BOTH,
    VIEW_CLIENT,
    VIEW_SERVER,
    assemble_segments,
    find_streams,
    flow_key,
    follow_stream,
    format_endpoint,
    render_hex,
    render_stream,
    summarize,
)

SAMPLE = Path(__file__).parent / "sample_traffic.pcap"
PACKETS, _ = read_packets(SAMPLE, keep_payload=True)


# ---------------------------------------------------------------------------
# Склейка сегментов
# ---------------------------------------------------------------------------
def test_assembly_in_order():
    result = assemble_segments([(100, b"abc"), (103, b"def")])
    assert result.data == b"abcdef"
    assert result.gaps == []
    assert result.segments == 2
    print("PASS: test_assembly_in_order")


def test_assembly_out_of_order():
    result = assemble_segments([(106, b"ghi"), (100, b"abc"), (103, b"def")])
    assert result.data == b"abcdefghi"
    assert result.gaps == []
    print("PASS: test_assembly_out_of_order")


def test_assembly_duplicates():
    result = assemble_segments([(100, b"abc"), (100, b"abc"), (103, b"def")])
    assert result.data == b"abcdef"
    assert result.retransmissions == 1
    print("PASS: test_assembly_duplicates")


def test_assembly_partial_overlap():
    result = assemble_segments([(100, b"abcdef"), (103, b"defghi")])
    assert result.data == b"abcdefghi"
    assert result.retransmissions == 0
    print("PASS: test_assembly_partial_overlap")


def test_assembly_gap():
    result = assemble_segments([(100, b"abc"), (110, b"xyz")])
    assert result.data == b"abcxyz"
    assert len(result.gaps) == 1
    assert result.gaps[0].offset == 3
    assert result.gaps[0].length == 7
    assert result.missing == 7
    print("PASS: test_assembly_gap")


def test_assembly_sequence_wrap():
    result = assemble_segments([(0xFFFFFFF8, b"abcdefgh"), (0x00000000, b"ijkl")])
    assert result.data == b"abcdefghijkl"
    assert result.gaps == []
    print("PASS: test_assembly_sequence_wrap")


def test_assembly_empty():
    assert assemble_segments([]).data == b""
    assert not assemble_segments([(1, b"")])
    print("PASS: test_assembly_empty")


# ---------------------------------------------------------------------------
# Ключ потока и поиск
# ---------------------------------------------------------------------------
def test_flow_key_same_for_both_directions():
    request = next(p for p in PACKETS if p.number == 6)
    response = next(p for p in PACKETS if p.number == 7)
    assert flow_key(request) == flow_key(response)
    assert flow_key(request) == flow_key(request)
    print("PASS: test_flow_key_same_for_both_directions")


def test_flow_key_ignores_non_tcp():
    icmp = next(p for p in PACKETS if p.number == 9)
    dns = next(p for p in PACKETS if p.number == 2)
    assert flow_key(icmp) is None
    assert flow_key(dns) is None
    print("PASS: test_flow_key_ignores_non_tcp")


def test_follow_stream_http():
    stream = follow_stream(PACKETS, 6)
    assert stream is not None
    assert format_endpoint(stream.client) == "10.77.0.10:40000"
    assert format_endpoint(stream.server) == "198.51.100.34:80"
    assert stream.packet_numbers == [4, 5, 6, 7]
    print("PASS: test_follow_stream_http")


def test_follow_stream_content():
    stream = follow_stream(PACKETS, 6)
    request = stream.client_to_server.data
    response = stream.server_to_client.data
    assert request.startswith(b"GET /index.html HTTP/1.1")
    assert b"Host: example.com" in request
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b"<html><body>ok</body>" in response
    print("PASS: test_follow_stream_content")


def test_follow_stream_non_tcp():
    assert follow_stream(PACKETS, 9) is None       # ICMP
    assert follow_stream(PACKETS, 2) is None       # DNS (UDP)
    assert follow_stream(PACKETS, 1) is None       # ARP
    print("PASS: test_follow_stream_non_tcp")


def test_follow_stream_missing_frame():
    assert follow_stream(PACKETS, 99999) is None
    print("PASS: test_follow_stream_missing_frame")


def test_find_streams():
    streams = find_streams(PACKETS)
    pairs = {
        (format_endpoint(s.client), format_endpoint(s.server)) for s in streams
    }
    assert len(streams) == 3
    assert ("10.77.0.10:40000", "198.51.100.34:80") in pairs
    assert ("10.77.0.10:40001", "203.0.113.44:443") in pairs
    print("PASS: test_find_streams")


# ---------------------------------------------------------------------------
# Вывод
# ---------------------------------------------------------------------------
def test_render_text_views():
    stream = follow_stream(PACKETS, 6)

    both = render_stream(stream, view=VIEW_BOTH, mode=MODE_TEXT)
    assert "GET /index.html" in both
    assert "HTTP/1.1 200 OK" in both
    assert both.count("===") >= 4        # два заголовка направлений

    client_only = render_stream(stream, view=VIEW_CLIENT, mode=MODE_TEXT)
    assert "GET /index.html" in client_only
    assert "HTTP/1.1 200 OK" not in client_only

    server_only = render_stream(stream, view=VIEW_SERVER, mode=MODE_TEXT)
    assert "HTTP/1.1 200 OK" in server_only
    assert "GET /index.html" not in server_only
    print("PASS: test_render_text_views")


def test_render_hex():
    stream = follow_stream(PACKETS, 8)      # TLS Client Hello
    text = render_hex(stream.client_to_server.stream)
    assert "16 03 01" in text
    print("PASS: test_render_hex")


def test_render_handles_binary():
    stream = follow_stream(PACKETS, 8)
    text = render_stream(stream, view=VIEW_BOTH, mode=MODE_TEXT)
    assert isinstance(text, str)
    assert text.strip() != ""
    print("PASS: test_render_handles_binary")


def test_summarize():
    stream = follow_stream(PACKETS, 6)
    text = summarize(stream)
    assert "10.77.0.10:40000" in text
    assert "198.51.100.34:80" in text
    print("PASS: test_summarize")


def test_gap_marker_in_output():
    from parser.streams import render_text
    result = assemble_segments([(100, b"abc"), (110, b"xyz")])
    text = render_text(result)
    assert "[пропущено 7 байт]" in text
    assert "abc" in text and "xyz" in text
    print("PASS: test_gap_marker_in_output")


# ---------------------------------------------------------------------------
# Память
# ---------------------------------------------------------------------------
def test_payload_kept_only_on_demand():
    without, _ = read_packets(SAMPLE)
    assert all(packet.payload == b"" for packet in without)
    assert any(packet.payload for packet in PACKETS)
    print("PASS: test_payload_kept_only_on_demand")


def test_udp_flow():
    """«Поток UDP»: датаграммы одного обмена склеиваются по направлениям."""
    from parser.streams import datagram_key, follow_datagram_flow

    packets = PACKETS
    stream = follow_datagram_flow(packets, 2)
    assert stream is not None
    assert stream.kind == "UDP", stream.kind
    assert stream.client == ("10.77.0.10", 10000), stream.client
    assert stream.server == ("203.0.113.53", 53), stream.server
    assert len(stream.packets) == 2
    assert stream.total_bytes > 0
    assert stream.client_to_server.stream.gaps == []
    assert b"\x07example\x03com" in stream.client_to_server.stream.data

    text = render_stream(stream, VIEW_BOTH, MODE_TEXT)
    assert "10.77.0.10:10000" in text
    assert "203.0.113.53:53" in text
    assert summarize(stream).startswith("Поток 10.77.0.10:10000")

    # TCP-пакет не собирается как UDP-поток, и наоборот.
    assert follow_datagram_flow(packets, 6) is None
    assert follow_stream(packets, 2) is None
    assert datagram_key(packets[1]) is not None      # UDP DNS-запрос
    assert datagram_key(packets[5]) is None          # TCP
    print("PASS: test_udp_flow")


if __name__ == "__main__":
    tests = [
        test_assembly_in_order,
        test_assembly_out_of_order,
        test_assembly_duplicates,
        test_assembly_partial_overlap,
        test_assembly_gap,
        test_assembly_sequence_wrap,
        test_assembly_empty,
        test_flow_key_same_for_both_directions,
        test_flow_key_ignores_non_tcp,
        test_follow_stream_http,
        test_follow_stream_content,
        test_follow_stream_non_tcp,
        test_follow_stream_missing_frame,
        test_find_streams,
        test_render_text_views,
        test_render_hex,
        test_render_handles_binary,
        test_summarize,
        test_gap_marker_in_output,
        test_payload_kept_only_on_demand,
        test_udp_flow,
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
