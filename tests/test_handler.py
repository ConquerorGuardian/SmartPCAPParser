"""
Тесты обработчика pcap: превью, фильтрация, экспорт.
Запуск: python -m tests.test_handler
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.pcap_handler import COLUMNS, PcapHandler

SAMPLE = Path(__file__).parent / "sample_traffic.pcap"


def test_preview_limit():
    handler = PcapHandler(preview_count=3)
    result = handler.load_and_filter(SAMPLE, "tcp")
    assert result.error is None, result.error
    assert result.total_packets == 13
    assert result.matched_packets == 7, result.matched_packets
    assert len(result.rows) == 3, len(result.rows)
    print("PASS: test_preview_limit")


def test_show_all():
    handler = PcapHandler(preview_count=3)
    result = handler.load_and_filter(SAMPLE, "tcp", limit=-1)
    assert len(result.rows) == result.matched_packets == 7
    print("PASS: test_show_all")


def test_default_on_empty_filter():
    handler = PcapHandler(preview_count=5)
    result = handler.load_and_filter(SAMPLE, "")
    assert result.total_packets == 13
    assert result.matched_packets == 13
    assert len(result.rows) == 5
    print("PASS: test_default_on_empty_filter")


def test_filter_error():
    handler = PcapHandler()
    result = handler.load_and_filter(SAMPLE, "no.such.field==1")
    assert result.error is not None
    assert not result.rows
    print("PASS: test_filter_error")


def test_missing_file():
    handler = PcapHandler()
    result = handler.load_and_filter(
        Path(__file__).parent / "missing.pcap", "ip.addr==1.1.1.1")
    assert result.error is not None
    assert "не найден" in result.error.lower()
    print("PASS: test_missing_file")


def test_load_then_apply():
    handler = PcapHandler(preview_count=200)
    packets, error = handler.load(SAMPLE)
    assert error is None
    assert len(packets) == 13

    http = handler.apply(packets, "http")
    assert http.matched_packets == 2
    assert len(http.rows) == 2

    dns = handler.apply(packets, "dns")
    assert dns.matched_packets == 2
    print("PASS: test_load_then_apply")


def test_row_fields():
    handler = PcapHandler()
    result = handler.load_and_filter(SAMPLE, "http")
    row = result.rows[0]
    assert row.frame == 6
    assert row.protocol == "TCP", row.protocol
    assert "HTTP" in row.info, row.info
    assert row.source == "192.168.1.10", row.source
    assert row.src_port == "40000", row.src_port
    assert row.destination == "93.184.216.34", row.destination
    assert row.dst_port == "80", row.dst_port
    assert row.time == "0.260000", row.time
    assert row.to_dict()["Src Port"] == "40000"
    assert row.to_dict()["Dst Port"] == "80"
    print("PASS: test_row_fields")


def test_csv_export():
    handler = PcapHandler()
    result = handler.load_and_filter(SAMPLE, "http", limit=-1)

    output = Path(__file__).parent / "_export_test.csv"
    try:
        handler.export_rows_to_csv(result.rows, output)
        assert output.exists()

        with open(output, "r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle, delimiter=";")
            rows = list(reader)
            assert reader.fieldnames == COLUMNS, reader.fieldnames

        assert len(rows) == 2, len(rows)
        assert rows[0]["Protocol"] == "TCP"
        assert rows[0]["Frame"] == "6"
    finally:
        output.unlink(missing_ok=True)
    print("PASS: test_csv_export")


def test_export_to_csv_alias():
    handler = PcapHandler()
    result = handler.load_and_filter(SAMPLE, "dns", limit=-1)
    output = Path(__file__).parent / "_export_test2.csv"
    try:
        path = handler.export_to_csv(result, output)
        assert Path(path).exists()
    finally:
        output.unlink(missing_ok=True)
    print("PASS: test_export_to_csv_alias")


if __name__ == "__main__":
    tests = [
        test_preview_limit,
        test_show_all,
        test_default_on_empty_filter,
        test_filter_error,
        test_missing_file,
        test_load_then_apply,
        test_row_fields,
        test_csv_export,
        test_export_to_csv_alias,
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
