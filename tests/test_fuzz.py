"""Битые файлы не должны ронять чтение: только понятная ошибка.

Тест не ищет конкретные сообщения, он проверяет главное: наружу выходит
PcapError, а не IndexError, struct.error или зависание.
"""

import gzip
import random
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.pcap_reader import PcapError, read_packets  # noqa: E402

PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
PCAPNG_HEADER = b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a"


def read_quietly(data: bytes, suffix: str) -> None:
    """Пишет данные во временный файл и читает; любые исключения кроме
    PcapError считаются провалом теста."""
    handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    try:
        handle.write(data)
        handle.close()
        path = Path(handle.name)
        try:
            read_packets(path)
        except PcapError:
            pass
    finally:
        try:
            Path(handle.name).unlink(missing_ok=True)
        except OSError:
            pass


def test_random_bytes():
    """Случайный мусор с правильным расширением."""
    rng = random.Random(2026)
    for _ in range(30):
        size = rng.randrange(0, 400)
        blob = bytes(rng.randrange(256) for _ in range(size))
        read_quietly(blob, ".pcap")
        read_quietly(blob, ".pcapng")
    print("PASS: test_random_bytes")


def test_broken_structures():
    """Битые заголовки: длина 0xFFFFFFFF, обрывки блоков, плохой gzip."""
    cases = [
        (PCAP_HEADER + b"\x00" * 7, ".pcap"),
        (PCAP_HEADER + struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF), ".pcap"),
        (PCAP_HEADER + struct.pack("<IIII", 0, 0, 262145, 0), ".pcap"),
        (PCAPNG_HEADER, ".pcapng"),
        (PCAPNG_HEADER + b"\xff" * 40, ".pcapng"),
        (b"\x0a\x0d\x0d\x0a" + b"\x00" * 3, ".pcapng"),
        (b"\x1f\x8b" + b"not a gzip stream", ".pcap"),
        (b"\xd4\xc3\xb2\xa1" + b"\x00" * 10, ".pcap"),
    ]
    for data, suffix in cases:
        read_quietly(data, suffix)
    print("PASS: test_broken_structures")


def test_gzip_of_broken_pcap():
    """Сжатый битый дамп: распаковка не должна вываливать чужое исключение."""
    broken = PCAP_HEADER + struct.pack("<IIII", 0, 0, 0xFFFF, 0)
    read_quietly(gzip.compress(broken), ".pcap.gz")
    print("PASS: test_gzip_of_broken_pcap")


if __name__ == "__main__":
    tests = [
        test_random_bytes,
        test_broken_structures,
        test_gzip_of_broken_pcap,
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
