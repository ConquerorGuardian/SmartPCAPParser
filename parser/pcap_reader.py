"""
Чтение файлов захвата .pcap / .pcapng.

Модуль не зависит от Wireshark/tshark/pyshark: формат разбирается
напрямую через стандартный модуль struct.

Поддерживается:
- классический libpcap (.pcap), в том числе с наносекундными метками;
- pcapng (.pcapng): блоки SHB / IDB / EPB / SPB;
- канальный уровень: Ethernet (в т.ч. VLAN), "raw IP", loopback, Linux SLL;
- сетевой уровень: IPv4, IPv6 (базовый), ARP;
- транспорт: TCP, UDP, ICMP;
- простое определение прикладного протокола по портам и данным (HTTP, DNS, TLS...).

Результат разбора — объекты Packet, из которых дальше строится таблица.
"""

import gzip
import re
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

PCAP_MAGIC_LE = 0xA1B2C3D4        # микросекунды, little-endian
PCAP_MAGIC_BE = 0xA1B2C3D4        # те же байты, читаются как big-endian
PCAP_MAGIC_NS_LE = 0xA1B23C4D     # наносекунды
PCAP_MAGIC_NS_BE = 0xA1B23C4D

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

# Прикладные протоколы, которые узнаём по номерам портов.
# Как и в Wireshark, протокол зависит от транспорта: 443/tcp — это TLS,
# а 443/udp — это QUIC (HTTP/3), поэтому таблицы разные.
TCP_APP_PORTS = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "TLS",
    445: "SMB",
    636: "TLS",
    993: "TLS",
    995: "TLS",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    179: "BGP",
    1883: "MQTT",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5222: "XMPP",
    5060: "SIP",
    5061: "SIP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6667: "IRC",
    8080: "HTTP",
    8443: "TLS",
    8883: "MQTT",
    11211: "Memcached",
    27017: "MongoDB",
}

UDP_APP_PORTS = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    161: "SNMP",
    162: "SNMP",
    443: "QUIC",
    500: "IPsec",
    514: "Syslog",
    546: "DHCPv6",
    547: "DHCPv6",
    1194: "OpenVPN",
    1701: "L2TP",
    1812: "RADIUS",
    1813: "RADIUS",
    1900: "SSDP",
    3478: "STUN",
    4500: "IPsec",
    5060: "SIP",
    5353: "mDNS",
    5355: "LLMNR",
}

TCP_FLAGS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
]

ICMP_TYPES = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo (ping) request",
    11: "Time-to-live exceeded",
}

# ICMPv6: другие коды, поэтому отдельная таблица.
ICMPV6_TYPES = {
    1: "Destination unreachable",
    2: "Packet too big",
    3: "Time exceeded",
    4: "Parameter problem",
    128: "Echo request",
    129: "Echo reply",
    133: "Router solicitation",
    134: "Router advertisement",
    135: "Neighbor solicitation",
    136: "Neighbor advertisement",
    137: "Redirect",
}

# IP-протоколы без портов: по номеру из заголовка.
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

HTTP_PREFIXES = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"HTTP/",
)

# HTTP/2 всегда начинается с этого предисловия (RFC 7540, раздел 3.5).
HTTP2_PREFACE = b"PRI * HTTP/2.0"

SIP_METHODS = (
    b"INVITE ",
    b"REGISTER ",
    b"OPTIONS ",
    b"BYE ",
    b"ACK ",
    b"CANCEL ",
    b"SUBSCRIBE ",
    b"NOTIFY ",
    b"PUBLISH ",
    b"MESSAGE ",
)


class PcapError(Exception):
    """Ошибка чтения файла захвата."""


# ---------------------------------------------------------------------------
# Модель пакета
# ---------------------------------------------------------------------------
@dataclass
class Packet:
    """Один разобранный пакет."""

    number: int                 # номер кадра в файле (с 1)
    timestamp: float            # абсолютное время, секунды
    length: int                 # длина кадра в файле (захвачено)
    wire_length: int            # исходная длина кадра в сети
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    transport: str = ""         # TCP / UDP / ICMP / ARP
    protocol: str = ""          # то же, что transport (как колонка Protocol в Wireshark)
    app: str = ""               # прикладной протокол: HTTP / DNS / TLS / QUIC / SSH
    info: str = ""
    seq: int = 0                # TCP sequence number (0 у не-TCP)
    tcp_flags: int = 0          # битовая маска флагов TCP
    payload: bytes = b""        # данные TCP; заполняется только при keep_payload=True
    ttl: int = 0                # TTL / Hop limit
    ip_len: int = 0             # длина IP-пакета целиком
    ip_id: int = 0              # identification для сборки фрагментов
    frag_offset: int = 0        # смещение фрагмента в байтах
    frag_more: bool = False     # есть ли ещё фрагменты
    tcp_len: int = 0            # длина данных TCP
    tcp_window: int = 0         # размер окна TCP
    tcp_ack: int = 0            # TCP acknowledgement number
    udp_len: int = 0            # длина UDP-датаграммы (заголовок + данные)
    icmp_type: int = 0
    icmp_code: int = 0
    host: str = ""              # HTTP Host или :authority
    sni: str = ""               # имя сервера из TLS ClientHello
    dns_name: str = ""          # первый запрошенный домен в DNS
    http_uri: str = ""          # путь запроса HTTP
    fragments: int = 0          # из скольких фрагментов собран пакет
    reassembled: bool = False   # True, если это результат сборки

    def has_ports(self) -> bool:
        return self.src_port is not None and self.dst_port is not None

    def to_row(self, relative_time: float | None = None) -> dict:
        """Строка для таблицы GUI. IP и порты — в отдельных колонках."""
        time_value = self.timestamp if relative_time is None else relative_time
        return {
            "Frame": self.number,
            "Time": f"{time_value:.6f}",
            "Protocol": self.protocol or "?",
            "Source": self.src_ip or self.src_mac or "?",
            "Src Port": "" if self.src_port is None else str(self.src_port),
            "Destination": self.dst_ip or self.dst_mac or "?",
            "Dst Port": "" if self.dst_port is None else str(self.dst_port),
            "Length": self.length,
            "Info": self.info,
        }


# ---------------------------------------------------------------------------
# Вспомогательные функции форматирования
# ---------------------------------------------------------------------------
class _Reassembler:
    """
    Сборка IP-фрагментов.

    Ключ — (откуда, куда, identification, протокол). Фрагменты кладём по
    смещениям; как только собраны все байты от 0 до конца — отдаём склейку.
    Незавершённые датаграммы не держим бесконечно: при переполнении словарь
    очищается, счётчик `dropped` помогает это заметить в тестах.
    """

    MAX_PENDING = 256
    MAX_DATAGRAM = 65535

    def __init__(self, max_pending: int = MAX_PENDING) -> None:
        self.max_pending = max_pending
        self._pending: dict[tuple, dict] = {}
        self.dropped = 0

    def add(self, key, offset: int, more: bool, data: bytes):
        """Возвращает (склеенные данные, число фрагментов) или None."""
        if offset < 0 or offset > self.MAX_DATAGRAM or not data:
            return None

        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self.max_pending:
                self._pending.clear()
                self.dropped += 1
            entry = {"parts": {}, "total": None, "count": 0}
            self._pending[key] = entry

        entry["parts"][offset] = bytes(data)
        entry["count"] += 1
        if not more:
            entry["total"] = min(offset + len(data), self.MAX_DATAGRAM)

        total = entry["total"]
        if total is None:
            return None

        chunks: list[bytes] = []
        position = 0
        for start in sorted(entry["parts"]):
            if start > position:
                return None                      # ещё есть дырка
            chunk = entry["parts"][start]
            end = start + len(chunk)
            if end <= position:
                continue
            chunks.append(chunk[position - start:])
            position = end

        if position < total:
            return None

        merged = b"".join(chunks)[:total]
        count = entry["count"]
        del self._pending[key]
        return merged, count


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _format_ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _format_ipv6(raw: bytes) -> str:
    groups = [f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2)]
    # Простое сжатие подряд идущих нулевых групп (как в RFC 5952).
    best_start, best_len = -1, 0
    start = -1
    for idx, group in enumerate(groups):
        if group == "0000":
            if start < 0:
                start = idx
        else:
            if start >= 0 and idx - start > best_len:
                best_start, best_len = start, idx - start
            start = -1
    if start >= 0 and len(groups) - start > best_len:
        best_start, best_len = start, len(groups) - start

    if best_len > 1:
        head = ":".join(groups[:best_start])
        tail = ":".join(groups[best_start + best_len:])
        return f"{head}::{tail}"
    return ":".join(groups)


def _tcp_flags(flags: int) -> str:
    names = [name for bit, name in TCP_FLAGS if flags & bit]
    return ",".join(names) if names else "None"


def _detect_tcp_app(src_port: int | None, dst_port: int | None,
                    payload: bytes) -> str:
    """
    Прикладной протокол TCP по данным и портам.

    Пустая строка означает «приложение не определено» — так же ведёт себя
    Wireshark: у SYN/FIN/RST без данных прикладного протокола нет.
    """
    if not payload:
        return ""

    if payload.startswith(HTTP2_PREFACE):
        return "HTTP2"
    if payload.startswith(HTTP_PREFIXES):
        return "HTTP"
    if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
        return "TLS"
    if payload.startswith(b"SSH-"):
        return "SSH"
    # SIP виден по началу сообщения: «INVITE sip:… SIP/2.0».
    if _looks_like_sip(payload):
        return "SIP"
    # MQTT CONNECT: тип пакета 0x10, дальше в переменном заголовке «MQTT».
    if payload[:1] == b"\x10" and b"MQTT" in payload[:16]:
        return "MQTT"
    # DNS поверх TCP: двухбайтовая длина сообщения + заголовок DNS.
    if _looks_like_dns_tcp(payload):
        return "DNS"

    for port in (dst_port, src_port):
        if port in TCP_APP_PORTS:
            return TCP_APP_PORTS[port]
    return ""


def _looks_like_dns_tcp(payload: bytes) -> bool:
    """DNS поверх TCP: 2 байта длины, затем 12-байтовый заголовок DNS.

    Проверяем поля заголовка, а не только порт 53: DNS по TCP встречается
    и на нестандартных портах (туннели, резолверы в контейнерах).
    """
    if len(payload) < 14:
        return False

    message_len = int.from_bytes(payload[:2], "big")
    if not 12 <= message_len <= len(payload) - 2:
        return False
    if message_len > 4096:  # ограничение TCP-сообщения DNS по RFC 1035
        return False

    header = payload[2:14]
    qdcount = int.from_bytes(header[4:6], "big")
    ancount = int.from_bytes(header[6:8], "big")
    opcode = (header[2] >> 3) & 0x0F
    rcode = header[3] & 0x0F
    return opcode <= 5 and rcode <= 5 and 1 <= qdcount <= 4 and ancount <= 16


def _looks_like_sip(payload: bytes) -> bool:
    """Похоже ли начало TCP-потока на сообщение SIP."""
    if not payload.startswith(SIP_METHODS) and not payload.startswith(b"SIP/2.0 "):
        return False
    head = payload[:160]
    return b"SIP/2.0" in head


# ---------------------------------------------------------------------------
# Имена из данных: HTTP Host, TLS SNI, DNS-запрос
# ---------------------------------------------------------------------------
HTTP_HOST_RE = re.compile(rb"\r\nhost[ \t]*:[ \t]*([^\r\n]{1,255})", re.IGNORECASE)
HTTP_REQUEST_LINE_RE = re.compile(rb"^([A-Z]{3,10}) (\S{1,512}) HTTP/\d\.\d")
DNS_NAME_MAX = 253


def _decode_http_host(payload: bytes) -> tuple[str, str]:
    """Возвращает (Host, путь запроса) или пустые строки."""
    head = payload[:4096]
    uri = ""
    match = HTTP_REQUEST_LINE_RE.match(head)
    if match:
        uri = match.group(2).decode("latin-1", "replace")

    # «\r\n» спереди — чтобы Host в первой строке заголовков тоже попался.
    found = HTTP_HOST_RE.search(b"\r\n" + head)
    host = ""
    if found:
        host = found.group(1).decode("latin-1", "replace").strip().lower()
        host = host.split(":")[0].strip() if ":" in host else host
    return host, uri


def _decode_tls_sni(payload: bytes) -> str:
    """Имя сервера из TLS ClientHello (extension server_name, тип 0)."""
    data = payload
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03:
        return ""
    pos = 5                                   # заголовок записи TLS
    if pos >= len(data) or data[pos] != 0x01:  # только ClientHello
        return ""
    pos += 4 + 2 + 32                          # тип, длина, версия, random
    if pos >= len(data):
        return ""

    session_len = data[pos]
    pos += 1 + session_len
    if pos + 2 > len(data):
        return ""
    cipher_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2 + cipher_len
    if pos + 1 > len(data):
        return ""
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos + 2 > len(data):
        return ""

    ext_total = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    end = min(pos + ext_total, len(data))

    while pos + 4 <= end:
        ext_type = int.from_bytes(data[pos:pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        body = pos + 4
        body_end = body + ext_len
        if body_end > len(data):
            return ""
        if ext_type == 0 and body + 2 <= body_end:
            list_len = int.from_bytes(data[body:body + 2], "big")
            list_end = min(body + 2 + list_len, body_end)
            cursor = body + 2
            while cursor + 3 <= list_end:
                name_type = data[cursor]
                name_len = int.from_bytes(data[cursor + 1:cursor + 3], "big")
                cursor += 3
                if cursor + name_len > list_end:
                    break
                if name_type == 0:
                    raw = data[cursor:cursor + name_len]
                    return raw.decode("ascii", "ignore").lower()
                cursor += name_len
            return ""
        pos = body_end

    return ""


def _decode_dns_name(payload: bytes, tcp: bool = False) -> str:
    """Первый запрошенный домен из DNS-сообщения."""
    data = payload
    if tcp:
        if len(data) < 14:
            return ""
        data = data[2:]
    if len(data) < 13:
        return ""

    qdcount = int.from_bytes(data[4:6], "big")
    if not 1 <= qdcount <= 4:
        return ""

    pos = 12
    labels: list[str] = []
    for _ in range(16):
        if pos >= len(data):
            return ""
        length = data[pos]
        if length == 0:
            break
        if length & 0xC0 or length > 63:
            return ""
        pos += 1
        if pos + length > len(data):
            return ""
        labels.append(data[pos:pos + length].decode("ascii", "ignore"))
        pos += length

    name = ".".join(labels).lower()
    return name if len(name) <= DNS_NAME_MAX else ""


def _detect_udp_app(src_port: int | None, dst_port: int | None) -> str:
    """Прикладной протокол UDP по портам (443/udp — это QUIC, а не TLS)."""
    for port in (dst_port, src_port):
        if port in UDP_APP_PORTS:
            return UDP_APP_PORTS[port]
    return ""


# ---------------------------------------------------------------------------
# Разбор канального и сетевого уровней
# ---------------------------------------------------------------------------
def _decode_tcp(data: bytes, pkt: Packet, seg_len: int) -> None:
    if len(data) < 20:
        pkt.protocol = "TCP"
        pkt.info = "TCP (короткий заголовок)"
        return

    src_port, dst_port, seq, ack, offset_flags, window, _csum, _urg = struct.unpack(
        ">HHIIHHHH", data[:20]
    )
    header_len = (offset_flags >> 12) * 4
    if header_len < 20 or header_len > len(data):
        header_len = 20
    flags = offset_flags & 0x01FF
    payload = data[header_len:]
    payload_len = max(len(payload), seg_len - header_len)

    pkt.src_port = src_port
    pkt.dst_port = dst_port
    pkt.transport = "TCP"
    pkt.protocol = "TCP"
    pkt.seq = seq
    pkt.tcp_ack = ack
    pkt.tcp_window = window
    pkt.tcp_flags = flags
    # Данные нужны для сборки потока ("Follow TCP stream"). read_packets
    # обнуляет поле, если вызывающий код не просил хранить payload.
    pkt.payload = payload
    if payload_len > 0:
        pkt.tcp_len = payload_len
        pkt.app = _detect_tcp_app(src_port, dst_port, payload[:64])
    if pkt.app == "HTTP":
        pkt.host, pkt.http_uri = _decode_http_host(payload)
    elif pkt.app == "TLS":
        pkt.sni = _decode_tls_sni(payload)
    elif pkt.app == "DNS":
        pkt.dns_name = _decode_dns_name(payload, tcp=True)

    pkt.info = f"{src_port} -> {dst_port} [{_tcp_flags(flags)}] Seq={seq} Len={payload_len}"
    if pkt.app:
        pkt.info = f"{pkt.info} {pkt.app}"
    name = pkt.host or pkt.sni or pkt.dns_name
    if name:
        pkt.info = f"{pkt.info} · {name}"


def _decode_udp(data: bytes, pkt: Packet) -> None:
    if len(data) < 8:
        pkt.protocol = "UDP"
        pkt.info = "UDP (короткий заголовок)"
        return

    src_port, dst_port, udp_len, _csum = struct.unpack(">HHHH", data[:8])
    pkt.src_port = src_port
    pkt.dst_port = dst_port
    pkt.transport = "UDP"
    pkt.protocol = "UDP"
    pkt.udp_len = udp_len
    pkt.app = _detect_udp_app(src_port, dst_port)
    payload = data[8:]
    pkt.payload = payload          # тела UDP нужны для «Поток UDP»
    if pkt.app == "DNS":
        pkt.dns_name = _decode_dns_name(payload)
    pkt.info = f"{src_port} -> {dst_port} Len={udp_len - 8}"
    if pkt.app:
        pkt.info = f"{pkt.info} {pkt.app}"
    if pkt.dns_name:
        pkt.info = f"{pkt.info} · {pkt.dns_name}"


def _decode_icmp(data: bytes, pkt: Packet, version: int = 4) -> None:
    name = "ICMPv6" if version == 6 else "ICMP"
    pkt.transport = name
    pkt.protocol = name
    if not data:
        pkt.info = name
        return
    icmp_type = data[0]
    pkt.icmp_type = icmp_type
    pkt.icmp_code = data[1] if len(data) > 1 else 0
    types = ICMPV6_TYPES if version == 6 else ICMP_TYPES
    pkt.info = types.get(icmp_type, f"Type {icmp_type}")


def _decode_arp(data: bytes, pkt: Packet) -> None:
    pkt.protocol = "ARP"
    pkt.transport = "ARP"
    if len(data) < 28:
        pkt.info = "ARP"
        return

    hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack(">HHBBH", data[:8])
    if hw_type != 1 or proto_type != ETHERTYPE_IPV4 or hw_len != 6 or proto_len != 4:
        pkt.info = "ARP (не Ethernet/IPv4)"
        return

    sender_mac = data[8:14]
    sender_ip = data[14:18]
    target_mac = data[18:24]
    target_ip = data[24:28]

    pkt.src_mac = _format_mac(sender_mac)
    pkt.src_ip = _format_ipv4(sender_ip)
    pkt.dst_ip = _format_ipv4(target_ip)
    if opcode == 1:
        pkt.info = f"Who has {pkt.dst_ip}? Tell {pkt.src_ip}"
    elif opcode == 2:
        pkt.dst_mac = _format_mac(target_mac)
        pkt.info = f"{pkt.src_ip} is at {pkt.src_mac}"
    else:
        pkt.info = f"ARP opcode {opcode}"


def _decode_ipv4(data: bytes, pkt: Packet, reassembler=None) -> None:
    if len(data) < 20:
        pkt.protocol = "IPv4"
        return

    ver_ihl, _tos, total_len, ident, flags_frag, ttl, proto, _csum = struct.unpack(
        ">BBHHHBBH", data[:12]
    )
    header_len = (ver_ihl & 0x0F) * 4
    frag_offset = flags_frag & 0x1FFF
    frag_more = bool(flags_frag & 0x2000)

    pkt.ttl = ttl
    pkt.ip_len = total_len
    pkt.ip_id = ident
    pkt.frag_offset = frag_offset * 8
    pkt.frag_more = frag_more
    pkt.src_ip = _format_ipv4(data[12:16])
    pkt.dst_ip = _format_ipv4(data[16:20])

    payload = data[header_len:]
    seg_len = max(total_len - header_len, 0)

    if frag_offset or frag_more:
        _handle_ipv4_fragment(pkt, payload, proto, frag_offset * 8,
                              frag_more, seg_len, reassembler)
        return

    if proto == IPPROTO_TCP:
        _decode_tcp(payload, pkt, seg_len)
    elif proto == IPPROTO_UDP:
        _decode_udp(payload, pkt)
    elif proto == IPPROTO_ICMP:
        _decode_icmp(payload, pkt)
    else:
        name = IP_PROTOCOLS.get(proto)
        if name:
            pkt.protocol = name
            pkt.transport = name
            pkt.info = f"{name} протокол"
        else:
            pkt.protocol = "IPv4"
            pkt.info = f"IPv4 protocol {proto}"


def _handle_ipv4_fragment(pkt: Packet, payload: bytes, proto: int, offset: int,
                          more: bool, seg_len: int, reassembler) -> None:
    """Складывает фрагменты и разбирает транспорт, когда датаграмма собрана."""
    if reassembler is None:
        pkt.protocol = "IPv4"
        pkt.info = ("Фрагмент IPv4 (начало)" if not offset
                    else f"Фрагмент IPv4 (offset {offset})")
        return

    key = (pkt.src_ip, pkt.dst_ip, pkt.ip_id, proto)
    merged = reassembler.add(key, offset, more, payload)

    if merged is None:
        pkt.protocol = "IPv4"
        pkt.info = (f"Фрагмент IPv4 (начало, {len(payload)} байт)"
                    if not offset else f"Фрагмент IPv4 (offset {offset})")
        return

    data, count = merged
    pkt.reassembled = True
    pkt.fragments = count
    if proto == IPPROTO_TCP:
        _decode_tcp(data, pkt, len(data))
    elif proto == IPPROTO_UDP:
        _decode_udp(data, pkt)
    elif proto == IPPROTO_ICMP:
        _decode_icmp(data, pkt)
    else:
        name = IP_PROTOCOLS.get(proto)
        if name:
            pkt.protocol = name
            pkt.transport = name
            pkt.info = f"{name} протокол"
        else:
            pkt.protocol = "IPv4"
            pkt.info = f"IPv4 protocol {proto}"
    suffix = f" · собран из {count} фрагментов"
    pkt.info = (pkt.info + suffix) if pkt.info else suffix.strip(" ·")


def _decode_ipv6(data: bytes, pkt: Packet, reassembler=None) -> None:
    if len(data) < 40:
        pkt.protocol = "IPv6"
        return

    _ver_tc_fl, payload_len, next_header, hop, src, dst = struct.unpack(
        ">IHBB16s16s", data[:40]
    )
    pkt.ttl = hop
    pkt.ip_len = payload_len + 40
    pkt.src_ip = _format_ipv6(src)
    pkt.dst_ip = _format_ipv6(dst)

    # Пропускаем простые расширенные заголовки, чтобы добраться до TCP/UDP.
    offset = 40
    current = next_header
    for _ in range(4):
        if current in (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6):
            break
        if len(data) < offset + 8:
            break
        if current in (0, 43, 60):          # Hop-by-Hop, Routing, Destination
            ext_len = (data[offset + 1] + 1) * 8
            current = data[offset]
            offset += ext_len
        elif current == 44:                 # Fragment
            if len(data) < offset + 8:
                break
            next_header = data[offset]
            fragment = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            frag_offset = (fragment >> 3) * 8
            more = bool(fragment & 0x0001)
            ident = struct.unpack(">I", data[offset + 4:offset + 8])[0]
            pkt.frag_offset = frag_offset
            pkt.frag_more = more
            pkt.ip_id = ident
            _handle_ipv6_fragment(pkt, data[offset + 8:], next_header,
                                  frag_offset, more, reassembler)
            return
        else:
            break

    payload = data[offset:]
    if current == IPPROTO_TCP:
        _decode_tcp(payload, pkt, payload_len)
    elif current == IPPROTO_UDP:
        _decode_udp(payload, pkt)
    elif current == IPPROTO_ICMPV6:
        _decode_icmp(payload, pkt, version=6)
    else:
        name = IP_PROTOCOLS.get(current)
        if name:
            pkt.protocol = name
            pkt.transport = name
            pkt.info = f"{name} протокол"
        else:
            pkt.protocol = "IPv6"
            pkt.info = f"IPv6 next header {current}"


def _handle_ipv6_fragment(pkt: Packet, payload: bytes, next_header: int,
                          offset: int, more: bool, reassembler) -> None:
    """Сборка фрагментов IPv6 — по тем же правилам, что и в IPv4."""
    if reassembler is None:
        pkt.protocol = "IPv6"
        pkt.info = ("Фрагмент IPv6 (начало)" if not offset
                    else f"Фрагмент IPv6 (offset {offset})")
        return

    key = (pkt.src_ip, pkt.dst_ip, pkt.ip_id, next_header)
    merged = reassembler.add(key, offset, more, payload)

    if merged is None:
        pkt.protocol = "IPv6"
        pkt.info = (f"Фрагмент IPv6 (начало, {len(payload)} байт)"
                    if not offset else f"Фрагмент IPv6 (offset {offset})")
        return

    data, count = merged
    pkt.reassembled = True
    pkt.fragments = count
    if next_header == IPPROTO_TCP:
        _decode_tcp(data, pkt, len(data))
    elif next_header == IPPROTO_UDP:
        _decode_udp(data, pkt)
    elif next_header == IPPROTO_ICMPV6:
        _decode_icmp(data, pkt, version=6)
    else:
        pkt.protocol = "IPv6"
        pkt.info = f"IPv6 next header {next_header}"
    suffix = f" · собран из {count} фрагментов"
    pkt.info = (pkt.info + suffix) if pkt.info else suffix.strip(" ·")


def _decode_ethernet(data: bytes, pkt: Packet, reassembler=None) -> None:
    if len(data) < 14:
        pkt.protocol = "Ethernet"
        return

    pkt.dst_mac = _format_mac(data[0:6])
    pkt.src_mac = _format_mac(data[6:12])
    ethertype = struct.unpack(">H", data[12:14])[0]
    offset = 14

    # VLAN / QinQ: каждый тег добавляет 4 байта.
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(data) >= offset + 4:
        ethertype = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        offset += 4

    payload = data[offset:]
    if ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(payload, pkt, reassembler)
    elif ethertype == ETHERTYPE_IPV6:
        _decode_ipv6(payload, pkt, reassembler)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(payload, pkt)
    else:
        pkt.protocol = "Ethernet"
        pkt.info = f"EtherType 0x{ethertype:04x}"


def _decode_raw_ip(data: bytes, pkt: Packet, reassembler=None) -> None:
    if not data:
        pkt.protocol = "?"
        return
    version = data[0] >> 4
    if version == 4:
        _decode_ipv4(data, pkt, reassembler)
    elif version == 6:
        _decode_ipv6(data, pkt, reassembler)
    else:
        pkt.protocol = "?"
        pkt.info = "Неизвестная версия IP"


def _decode_loopback(data: bytes, pkt: Packet, reassembler=None) -> None:
    # Первые 4 байта — семейство протоколов в порядке хоста.
    if len(data) < 4:
        pkt.protocol = "?"
        return
    family_le = struct.unpack("<I", data[:4])[0]
    family_be = struct.unpack(">I", data[:4])[0]
    family = family_le if family_le in (2, 10, 24, 28, 30) else family_be
    payload = data[4:]
    if family in (2, 24, 28, 30):
        _decode_ipv4(payload, pkt, reassembler)
    elif family in (10,):
        _decode_ipv6(payload, pkt, reassembler)
    else:
        _decode_raw_ip(payload, pkt, reassembler)


def _decode_linux_sll(data: bytes, pkt: Packet, reassembler=None) -> None:
    if len(data) < 16:
        pkt.protocol = "SLL"
        return
    ethertype = struct.unpack(">H", data[14:16])[0]
    payload = data[16:]
    if ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(payload, pkt, reassembler)
    elif ethertype == ETHERTYPE_IPV6:
        _decode_ipv6(payload, pkt, reassembler)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(payload, pkt)
    else:
        pkt.protocol = "SLL"
        pkt.info = f"EtherType 0x{ethertype:04x}"


def _decode_linux_sll2(data: bytes, pkt: Packet, reassembler=None) -> None:
    """Linux cooked v2: 20 байт заголовка, протокол в первых двух."""
    if len(data) < 20:
        pkt.protocol = "SLL2"
        return
    ethertype = struct.unpack(">H", data[0:2])[0]
    payload = data[20:]
    if ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(payload, pkt, reassembler)
    elif ethertype == ETHERTYPE_IPV6:
        _decode_ipv6(payload, pkt, reassembler)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(payload, pkt)
    else:
        pkt.protocol = "SLL2"
        pkt.info = f"EtherType 0x{ethertype:04x}"


def _decode_loop_big_endian(data: bytes, pkt: Packet, reassembler=None) -> None:
    """LINKTYPE_LOOP (BSD): семейство записано big-endian."""
    if len(data) < 4:
        pkt.protocol = "?"
        return
    family = struct.unpack(">I", data[:4])[0]
    payload = data[4:]
    if family in (2, 24, 28, 30):
        _decode_ipv4(payload, pkt, reassembler)
    elif family == 10:
        _decode_ipv6(payload, pkt, reassembler)
    else:
        _decode_raw_ip(payload, pkt, reassembler)


def decode_frame(data: bytes, linktype: int, pkt: Packet,
                 reassembler=None) -> None:
    """Разбирает кадр в зависимости от типа канала (linktype)."""
    if linktype == LINKTYPE_ETHERNET:
        _decode_ethernet(data, pkt, reassembler)
    elif linktype == LINKTYPE_RAW:
        _decode_raw_ip(data, pkt, reassembler)
    elif linktype == LINKTYPE_NULL:
        _decode_loopback(data, pkt, reassembler)
    elif linktype == LINKTYPE_LOOP:
        _decode_loop_big_endian(data, pkt, reassembler)
    elif linktype == LINKTYPE_LINUX_SLL:
        _decode_linux_sll(data, pkt, reassembler)
    elif linktype == LINKTYPE_LINUX_SLL2:
        _decode_linux_sll2(data, pkt, reassembler)
    elif linktype == LINKTYPE_IPV4:
        _decode_ipv4(data, pkt, reassembler)
    elif linktype == LINKTYPE_IPV6:
        _decode_ipv6(data, pkt, reassembler)
    else:
        pkt.protocol = "?"
        pkt.info = f"Кадр этого типа не разбирается (linktype {linktype})"


# ---------------------------------------------------------------------------
# Чтение файла
# ---------------------------------------------------------------------------
class _PcapFileReader:
    """Классический .pcap."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        header = stream.read(24)
        if len(header) < 24:
            raise PcapError("Файл слишком короткий для формата pcap")

        magic = struct.unpack("<I", header[:4])[0]
        self.nanoseconds = False

        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self.endian = "<"
            self.nanoseconds = magic == PCAP_MAGIC_NS_LE
        else:
            magic_be = struct.unpack(">I", header[:4])[0]
            if magic_be in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
                self.endian = ">"
                self.nanoseconds = magic_be == PCAP_MAGIC_NS_BE
            else:
                raise PcapError("Не найдена сигнатура pcap")

        (_magic, _vmaj, _vmin, _tz, _sig, self.snaplen,
         self.linktype) = struct.unpack(self.endian + "IHHIIII", header)

    def packets(self) -> Iterator[tuple[float, int, int, bytes]]:
        """Отдаёт (timestamp, captured_len, wire_len, data)."""
        header_struct = struct.Struct(self.endian + "IIII")
        while True:
            header = self.stream.read(16)
            if not header:
                break
            if len(header) < 16:
                break

            ts_sec, ts_frac, incl_len, orig_len = header_struct.unpack(header)
            if incl_len > 262144:
                raise PcapError("Некорректная длина пакета в файле")

            data = self.stream.read(incl_len)
            if len(data) < incl_len:
                break

            fraction = ts_frac / (1_000_000_000 if self.nanoseconds else 1_000_000)
            yield ts_sec + fraction, incl_len, orig_len, data


class _PcapngFileReader:
    """Файл .pcapng (блоки SHB / IDB / EPB / SPB)."""

    SHB = 0x0A0D0D0A
    IDB = 0x00000001
    EPB = 0x00000006
    SPB = 0x00000003

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.interfaces: list[dict] = []
        self.endian = "<"

    @staticmethod
    def _options(data: bytes, endian: str) -> dict:
        options = {}
        offset = 0
        while offset + 4 <= len(data):
            code, length = struct.unpack(endian + "HH", data[offset:offset + 4])
            offset += 4
            if code == 0:
                break
            value = data[offset:offset + length]
            options[code] = value
            offset += (length + 3) & ~3
        return options

    def _read_shb(self, body: bytes) -> None:
        if len(body) < 4:
            raise PcapError("Повреждён блок SHB")
        bom = struct.unpack("<I", body[:4])[0]
        if bom == 0x1A2B3C4D:
            self.endian = "<"
        else:
            bom = struct.unpack(">I", body[:4])[0]
            if bom == 0x1A2B3C4D:
                self.endian = ">"
            else:
                raise PcapError("Не найдена сигнатура pcapng")

    def _read_idb(self, body: bytes) -> None:
        if len(body) < 8:
            return
        linktype, _reserved, _snaplen = struct.unpack(self.endian + "HHI", body[:8])
        options = self._options(body[8:], self.endian)
        resolution = 1e-6
        if 9 in options and options[9]:
            value = options[9][0]
            if value & 0x80:
                resolution = 2.0 ** -(value & 0x7F)
            else:
                resolution = 10.0 ** (-value)
        self.interfaces.append({"linktype": linktype, "tsresol": resolution})

    def _read_epb(self, body: bytes) -> tuple[int, float, int, int, bytes] | None:
        if len(body) < 20:
            return None
        iface_id, ts_high, ts_low, cap_len, pkt_len = struct.unpack(
            self.endian + "IIIII", body[:20]
        )
        data = body[20:20 + cap_len]
        iface = self.interfaces[iface_id] if iface_id < len(self.interfaces) else {"tsresol": 1e-6}
        timestamp = ((ts_high << 32) | ts_low) * iface["tsresol"]
        return iface_id, timestamp, cap_len, pkt_len, data

    def packets(self) -> Iterator[tuple[int, float, int, int, bytes]]:
        """Отдаёт (linktype, timestamp, captured_len, wire_len, data)."""
        while True:
            header = self.stream.read(8)
            if not header:
                break
            if len(header) < 8:
                break

            block_type_le = struct.unpack("<I", header[:4])[0]

            if block_type_le == self.SHB:
                total_len = struct.unpack("<I", header[4:8])[0]
                if not self._plausible(total_len):
                    total_len = struct.unpack(">I", header[4:8])[0]
                body = self.stream.read(total_len - 12)
                self.stream.read(4)   # завершающая длина блока
                self._read_shb(body)
                continue

            block_type = struct.unpack(self.endian + "I", header[:4])[0]
            total_len = struct.unpack(self.endian + "I", header[4:8])[0]
            if not self._plausible(total_len):
                raise PcapError("Некорректная длина блока pcapng")

            body = self.stream.read(total_len - 12)
            self.stream.read(4)

            if block_type == self.IDB:
                self._read_idb(body)
            elif block_type == self.EPB:
                parsed = self._read_epb(body)
                if parsed is None:
                    continue
                iface_id, timestamp, cap_len, pkt_len, data = parsed
                linktype = self.interfaces[iface_id]["linktype"] if iface_id < len(self.interfaces) else LINKTYPE_ETHERNET
                yield linktype, timestamp, cap_len, pkt_len, data
            elif block_type == self.SPB:
                if len(body) < 4:
                    continue
                orig_len = struct.unpack(self.endian + "I", body[:4])[0]
                data = body[4:]
                linktype = self.interfaces[0]["linktype"] if self.interfaces else LINKTYPE_ETHERNET
                yield linktype, 0.0, len(data), orig_len, data

    @staticmethod
    def _plausible(length: int) -> bool:
        return 12 <= length <= 64 * 1024 * 1024


def _detect_format(stream: BinaryIO) -> str:
    head = stream.read(4)
    stream.seek(0)
    if head == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if head == b"\xd4\xc3\xb2\xa1" or head == b"\xa1\xb2\xc3\xd4":
        return "pcap"
    if head == b"\x4d\x3c\xb2\xa1" or head == b"\xa1\xb2\x3c\x4d":
        return "pcap"
    raise PcapError("Не удалось определить формат файла (ожидается pcap или pcapng)")


def _open_capture(path: Path) -> tuple[BinaryIO, bool]:
    """Открывает дамп, распаковывая gzip на лету (многие образцы сжаты)."""
    raw = open(path, "rb")                     # noqa: SIM115 — закрывается вызывающим
    head = raw.read(2)
    raw.seek(0)
    if head == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=raw, mode="rb"), True
    return raw, False


def read_packets(
    path: str | Path,
    keep_payload: bool = False,
    progress: Callable[[float | None], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> tuple[list[Packet], int]:
    """
    Читает файл захвата и возвращает (список пакетов, linktype).

    Args:
        path: Путь к .pcap/.pcapng (можно .gz).
        keep_payload: Хранить данные TCP в Packet.payload. Нужно для сборки
            потока ("Follow TCP stream"); по умолчанию выключено, чтобы не
            держать в памяти копию содержимого дампа.
        progress: Необязательный обратный вызов: получает долю прочитанного
            от 0 до 1 или None, если файл сжат и процент посчитать нельзя.
        should_stop: Необязательная проверка «пользователь нажал Отмена».
            Вызывается каждые 256 пакетов; при True чтение прекращается
            с PcapError("Чтение отменено").

    Исключения формата заворачиваются в PcapError, файл закрывается.
    """
    path = Path(path)
    if not path.exists():
        raise PcapError(f"Файл не найден: {path}")
    if not path.is_file():
        raise PcapError(f"Это не файл: {path}")

    try:
        total_bytes = 0
        if progress is not None:
            try:
                total_bytes = path.stat().st_size
            except OSError:
                total_bytes = 0

        stream, compressed = _open_capture(path)
        reassembler = _Reassembler()

        def tick(number: int) -> None:
            """Раз в 256 пакетов: отмена и прогресс."""
            if number % 256:
                return
            if should_stop is not None and should_stop():
                raise PcapError("Чтение отменено")
            if progress is None:
                return
            if compressed or not total_bytes:
                progress(None)
                return
            try:
                position = stream.tell()
            except (OSError, ValueError):
                position = 0
            progress(min(1.0, position / total_bytes))

        try:
            fmt = _detect_format(stream)
            if fmt == "pcap":
                reader = _PcapFileReader(stream)
                linktype = reader.linktype
                packets = []
                for number, (ts, cap_len, wire_len, data) in enumerate(reader.packets(), start=1):
                    pkt = Packet(number=number, timestamp=ts, length=cap_len, wire_length=wire_len)
                    decode_frame(data, linktype, pkt, reassembler)
                    if not keep_payload:
                        pkt.payload = b""
                    packets.append(pkt)
                    tick(number)
                if progress is not None:
                    progress(1.0)
                return packets, linktype

            reader = _PcapngFileReader(stream)
            packets = []
            for number, (linktype, ts, cap_len, wire_len, data) in enumerate(reader.packets(), start=1):
                pkt = Packet(number=number, timestamp=ts, length=cap_len, wire_length=wire_len)
                decode_frame(data, linktype, pkt, reassembler)
                if not keep_payload:
                    pkt.payload = b""
                packets.append(pkt)
                tick(number)
            if progress is not None:
                progress(1.0)
            return packets, (reader.interfaces[0]["linktype"] if reader.interfaces else LINKTYPE_ETHERNET)
        finally:
            stream.close()
    except PcapError:
        raise
    except (OSError, struct.error) as exc:
        raise PcapError(f"Не удалось прочитать файл: {exc}") from exc


def read_payloads(path: str | Path, frames, max_bytes: int | None = None) -> dict[int, bytes]:
    """
    Повторно читает файл и возвращает данные TCP только для нужных кадров.

    Нужно для «Поток TCP» на больших файлах: заголовки пакетов уже в памяти,
    а тела читаем по требованию — только для выбранного соединения.

    Args:
        path: Файл .pcap/.pcapng.
        frames: Номера кадров, данные которых нужны.
        max_bytes: Ограничение суммарного объёма; при превышении чтение
            останавливается (лучше показать часть потока, чем съесть память).

    Returns:
        Словарь номер кадра -> данные TCP. Кадры без данных не попадают.
    """
    path = Path(path)
    wanted = {int(frame) for frame in frames or ()}
    if not wanted or not path.exists():
        return {}

    result: dict[int, bytes] = {}
    total = 0

    try:
        stream, _compressed = _open_capture(path)
        try:
            fmt = _detect_format(stream)
            if fmt == "pcap":
                reader = _PcapFileReader(stream)
                linktype = reader.linktype
                source = ((number, linktype, ts, cap_len, wire_len, data)
                          for number, (ts, cap_len, wire_len, data)
                          in enumerate(reader.packets(), start=1))
            else:
                reader = _PcapngFileReader(stream)
                source = (
                    (number, frame_linktype, ts, cap_len, wire_len, data)
                    for number, (frame_linktype, ts, cap_len, wire_len, data)
                    in enumerate(reader.packets(), start=1)
                )

            for number, frame_linktype, ts, cap_len, wire_len, data in source:
                if number not in wanted:
                    continue
                pkt = Packet(number=number, timestamp=ts, length=cap_len,
                             wire_length=wire_len)
                decode_frame(data, frame_linktype, pkt)
                if not pkt.payload:
                    continue
                result[number] = pkt.payload
                total += len(pkt.payload)
                if max_bytes is not None and total >= max_bytes:
                    break
        finally:
            stream.close()
    except (OSError, struct.error, PcapError):
        return result

    return result


def count_packets(path: str | Path) -> int:
    """Быстро считает число пакетов в файле."""
    packets, _ = read_packets(path)
    return len(packets)
