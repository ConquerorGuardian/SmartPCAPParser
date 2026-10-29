"""Замер скорости: чтение pcap, фильтрация, сборка потоков.

Создаёт синтетический дамп нужного размера и печатает честные цифры —
их можно вставить в README (и сравнить на своей машине).

    python tools/bench.py                 # 40 МБ
    python tools/bench.py --mb 100        # 100 МБ
    python tools/bench.py --keep          # не удалять файл после замера
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from parser.matcher import compile_filter  # noqa: E402
from parser.pcap_reader import read_packets  # noqa: E402
from parser.streams import follow_stream  # noqa: E402

WORK = ROOT / ".bench"


def build_frame(seq: int) -> bytes:
    """Ethernet + IPv4 + TCP с полезной нагрузкой 1000 байт."""
    payload = (b"GET /page HTTP/1.1\r\nHost: bench.example\r\n\r\n" + b"x" * 64)
    eth = bytes.fromhex("aabbccddeeff1122334455660800")
    src = bytes([10, 1, 0, 1])
    dst = bytes([10, 1, 0, 2])
    src_port = 40000 + (seq % 1000)
    total = 20 + 20 + len(payload)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, seq % 65535, 0x4000, 64,
                       6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", src_port, 80, seq, 1, 0x50, 0x18, 65535, 0, 0)
    return eth + ipv4 + tcp + payload


def write_dump(path: Path, megabytes: int) -> tuple[int, float]:
    frame = None
    written = 0
    target = megabytes * 1024 * 1024
    count = 0
    started = time.perf_counter()
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        while written < target:
            frame = build_frame(count)
            timestamp = 1700000000 + count // 1000
            micro = (count % 1000) * 1000
            handle.write(struct.pack("<IIII", timestamp, micro, len(frame), len(frame)))
            handle.write(frame)
            written += len(frame) + 16
            count += 1
    return count, time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser(description="Замер скорости парсера")
    parser.add_argument("--mb", type=int, default=40, help="размер дампа, МБ")
    parser.add_argument("--keep", action="store_true", help="оставить файл")
    args = parser.parse_args()

    WORK.mkdir(exist_ok=True)
    path = WORK / "bench_{}mb.pcap".format(args.mb)

    print("Готовлю дамп на {} МБ...".format(args.mb))
    packets_written, write_time = write_dump(path, args.mb)
    size_mb = path.stat().st_size / (1024 * 1024)
    print("  {} пакетов, {:.1f} МБ, запись {:.1f} с".format(
        packets_written, size_mb, write_time))

    started = time.perf_counter()
    packets, linktype = read_packets(path)
    read_time = time.perf_counter() - started
    print("  чтение заголовков: {:.2f} с ({:.0f} пакетов/с, {:.1f} МБ/с, linktype {})".format(
        read_time, len(packets) / read_time, size_mb / read_time, linktype))

    started = time.perf_counter()
    payload_packets, _linktype = read_packets(path, keep_payload=True)
    payload_time = time.perf_counter() - started
    print("  чтение с телами:   {:.2f} с ({:.0f} пакетов/с)".format(
        payload_time, len(payload_packets) / payload_time))

    predicate = compile_filter("tcp.port==80 and frame.len > 100")
    started = time.perf_counter()
    matched = sum(1 for packet in packets if predicate(packet))
    filter_time = time.perf_counter() - started
    print("  фильтр 'tcp.port==80 and frame.len > 100': {:.2f} с, совпало {}".format(
        filter_time, matched))

    stream = follow_stream(payload_packets, 10)
    started = time.perf_counter()
    follow_stream(payload_packets, 10)
    follow_time = time.perf_counter() - started
    print("  сборка потока TCP: {:.3f} с (байт в потоке: {})".format(
        follow_time, stream.total_bytes if stream else 0))

    print("")
    print("Итог для README: {:.0f} МБ / {} пакетов — разбор {:.1f} с "
          "({:.0f} тыс. пакетов/с)".format(
              size_mb, len(packets), read_time, len(packets) / read_time / 1000))

    if not args.keep:
        path.unlink(missing_ok=True)
        print("Файл удалён (--keep оставляет его в .bench/)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
