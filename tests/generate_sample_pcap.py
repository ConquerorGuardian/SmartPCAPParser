"""
Генератор тестовых файлов захвата.

Создаёт два файла в папке tests:
- sample_traffic.pcap   — классический libpcap;
- sample_traffic.pcapng — формат pcapng.

В трафике есть ARP, DNS, HTTP, TLS, SSH и ICMP, чтобы демонстрировать
работу фильтров. Все заголовки собираются вручную через struct, поэтому
файлы читаются и Wireshark, и нашим парсером без tshark.
"""

import struct
from pathlib import Path

OUT_DIR = Path(__file__).parent

TS_BASE = 1700000000  # 14.11.2023


# ---------------------------------------------------------------------------
# Сборка кадров
# ---------------------------------------------------------------------------
def mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", "").replace("-", ""))


def eth(dst: str, src: str, ethertype: int = 0x0800) -> bytes:
    return mac(dst) + mac(src) + struct.pack(">H", ethertype)


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH",
        0x45, 0, total_len, ident, 0x4000, 64, proto, 0,
    )
    return header + bytes(map(int, src.split("."))) + bytes(map(int, dst.split("."))) + payload


def tcp(src_port: int, dst_port: int, seq: int, ack: int,
        flags: int, payload: bytes = b"") -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack(
        ">HHIIHHHH",
        src_port, dst_port, seq, ack, offset_flags, 65535, 0, 0,
    )
    return header + payload


def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def icmp(icmp_type: int, code: int, payload: bytes) -> bytes:
    return struct.pack(">BBHHH", icmp_type, code, 0, 1, 1) + payload


def arp_request(sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    return (
        struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
        + mac(sender_mac)
        + bytes(map(int, sender_ip.split(".")))
        + b"\x00" * 6
        + bytes(map(int, target_ip.split(".")))
    )


# ---------------------------------------------------------------------------
# Набор пакетов
# ---------------------------------------------------------------------------
def build_frames() -> list[tuple[int, bytes]]:
    """Возвращает список (timestamp, Ethernet-кадр)."""
    frames: list[tuple[int, bytes]] = []

    def add(ts_ms: int, frame: bytes) -> None:
        frames.append((ts_ms, frame))

    # 1. ARP: кто такой 192.168.1.1
    add(0, eth("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:01", 0x0806)
        + arp_request("aa:bb:cc:dd:ee:01", "192.168.1.10", "192.168.1.1"))

    # 2. DNS-запрос
    dns_query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    dns_query += b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    add(100, eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.10", "8.8.8.8", 17, udp(10000, 53, dns_query)))

    # 3. DNS-ответ
    dns_answer = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    dns_answer += b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    dns_answer += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    add(120, eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
        + ipv4("8.8.8.8", "192.168.1.10", 17, udp(53, 10000, dns_answer)))

    # 4. TCP SYN к веб-серверу
    add(200, eth("aa:bb:cc:dd:ee:03", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.10", "93.184.216.34", 6, tcp(40000, 80, 1000, 0, 0x02)))

    # 5. TCP SYN-ACK от сервера
    add(230, eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:03")
        + ipv4("93.184.216.34", "192.168.1.10", 6, tcp(80, 40000, 5000, 1001, 0x12)))

    # 6. HTTP GET
    http_get = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: SmartPCAPParser/1.0\r\n\r\n"
    )
    add(260, eth("aa:bb:cc:dd:ee:03", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.10", "93.184.216.34", 6, tcp(40000, 80, 1001, 5001, 0x18, http_get)))

    # 7. HTTP 200 OK
    http_ok = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 21\r\n\r\n"
        b"<html><body>ok</body>"
    )
    add(300, eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:03")
        + ipv4("93.184.216.34", "192.168.1.10", 6, tcp(80, 40000, 5001, 1001 + len(http_get), 0x18, http_ok)))

    # 8. TLS Client Hello (упрощённый)
    tls_hello = bytes.fromhex("16 03 01 00 2f 01 00 00 2b 03 03") + b"\x00" * 32
    add(400, eth("aa:bb:cc:dd:ee:04", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.10", "104.16.0.1", 6, tcp(40001, 443, 2000, 0, 0x18, tls_hello)))

    # 9. ICMP echo request
    add(500, eth("aa:bb:cc:dd:ee:05", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.10", "192.168.1.1", 1, icmp(8, 0, b"abcdefgh")))

    # 10. ICMP echo reply
    add(505, eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:05")
        + ipv4("192.168.1.1", "192.168.1.10", 1, icmp(0, 0, b"abcdefgh")))

    # 11. SSH-подключение (порт 22)
    add(600, eth("aa:bb:cc:dd:ee:06", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.20", "10.0.0.5", 6, tcp(50000, 22, 3000, 0, 0x02)))

    # 12. SSH-баннер: данные, по которым видно прикладной протокол
    add(620, eth("aa:bb:cc:dd:ee:06", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.20", "10.0.0.5", 6,
               tcp(50000, 22, 3001, 1, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n")))

    # 13. QUIC: UDP на порт 443 (это не TLS, как и в Wireshark)
    quic_payload = bytes.fromhex("c30000000108") + b"\x00" * 20
    add(700, eth("aa:bb:cc:dd:ee:07", "aa:bb:cc:dd:ee:01")
        + ipv4("192.168.1.10", "142.250.1.1", 17, udp(63255, 443, quic_payload)))

    return frames


# ---------------------------------------------------------------------------
# Запись pcap
# ---------------------------------------------------------------------------
def write_pcap(path: Path, frames: list[tuple[int, bytes]]) -> None:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for ts_ms, frame in frames:
        seconds = TS_BASE + ts_ms // 1000
        micros = (ts_ms % 1000) * 1000
        records.append(struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame)

    path.write_bytes(global_header + b"".join(records))


# ---------------------------------------------------------------------------
# Запись pcapng
# ---------------------------------------------------------------------------
def _block(block_type: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    padding = (-len(body)) % 4
    body = body + b"\x00" * padding
    total_len = 12 + len(body)
    return struct.pack("<II", block_type, total_len) + body + struct.pack("<I", total_len)


def write_pcapng(path: Path, frames: list[tuple[int, bytes]]) -> None:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    chunks = [_block(0x0A0D0D0A, shb_body), _block(0x00000001, idb_body)]

    for ts_ms, frame in frames:
        timestamp_us = (TS_BASE * 1_000_000) + ts_ms * 1000
        ts_high = (timestamp_us >> 32) & 0xFFFFFFFF
        ts_low = timestamp_us & 0xFFFFFFFF
        body = struct.pack("<IIIII", 0, ts_high, ts_low, len(frame), len(frame)) + frame
        chunks.append(_block(0x00000006, body))

    path.write_bytes(b"".join(chunks))


def main() -> None:
    frames = build_frames()
    write_pcap(OUT_DIR / "sample_traffic.pcap", frames)
    write_pcapng(OUT_DIR / "sample_traffic.pcapng", frames)
    print(f"Создано {len(frames)} пакетов")
    print("  {}".format(OUT_DIR / "sample_traffic.pcap"))
    print("  {}".format(OUT_DIR / "sample_traffic.pcapng"))


if __name__ == "__main__":
    main()
