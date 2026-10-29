"""
Статистика по захвату: иерархия протоколов, разговоры, узлы.

Модуль не знает про интерфейс: на вход идут объекты Packet из pcap_reader,
на выход — простые dataclass-строки, которые GUI только рисует.
"""

from dataclasses import dataclass
from typing import Iterable, Sequence


# ---------------------------------------------------------------------------
# Строки результата
# ---------------------------------------------------------------------------
@dataclass
class ProtocolStat:
    """Строка дерева «Иерархия протоколов»."""

    name: str
    packets: int = 0
    bytes: int = 0
    share: float = 0.0      # доля пакетов, 0..100
    level: int = 0          # 0 — транспорт, 1 — прикладной протокол
    parent: str = ""        # для level=1: имя транспортного протокола


@dataclass
class Conversation:
    """Пара узлов и объём обмена между ними."""

    endpoint_a: str
    endpoint_b: str
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0

    @property
    def total_packets(self) -> int:
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def total_bytes(self) -> int:
        return self.bytes_a_to_b + self.bytes_b_to_a


@dataclass
class EndpointStat:
    """Узел сети: сколько отправил и сколько получил."""

    address: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


@dataclass
class HostStat:
    """Имя из трафика: сайт из HTTP Host / TLS SNI или домен из DNS."""

    name: str
    packets: int = 0
    bytes: int = 0
    source: str = ""        # HTTP / TLS / DNS


@dataclass
class TimelineBucket:
    """Один столбик графика: с какого момента и сколько трафика."""

    start: float        # секунды от первого пакета
    packets: int = 0
    bytes: int = 0


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
def timeline(packets: Sequence, buckets: int = 60) -> list[TimelineBucket]:
    """
    Раскладывает пакеты по равным интервалам времени.

    Сумма packets и bytes по всем бакетам равна числу пакетов и байт файла,
    поэтому график всегда согласован со сводкой.
    """
    if not packets:
        return []

    buckets = max(1, min(int(buckets), 240))
    stamps = [float(getattr(packet, "timestamp", 0.0) or 0.0) for packet in packets]
    first, last = min(stamps), max(stamps)
    span = last - first

    if span <= 0:
        # Все пакеты в одну секунду — один столбик на весь файл.
        return [TimelineBucket(
            start=0.0,
            packets=len(packets),
            bytes=sum(_safe_int(packet.length) for packet in packets),
        )]

    step = span / buckets
    rows = [
        TimelineBucket(start=index * step)
        for index in range(buckets)
    ]

    for packet, stamp in zip(packets, stamps):
        index = int((stamp - first) / step)
        index = min(max(index, 0), buckets - 1)
        rows[index].packets += 1
        rows[index].bytes += _safe_int(packet.length)

    return rows


def packet_host(packet) -> tuple[str, str]:
    """Возвращает (имя, источник): HTTP Host, TLS SNI или DNS-запрос."""
    if packet.host:
        return packet.host, "HTTP"
    if packet.sni:
        return packet.sni, "TLS"
    if packet.dns_name:
        return packet.dns_name, "DNS"
    return "", ""


def hosts(packets: Sequence, limit: int = 25) -> list[HostStat]:
    """Топ имён (сайтов и доменов) по числу пакетов, затем по байтам."""
    found: dict[str, HostStat] = {}
    for packet in packets:
        name, source = packet_host(packet)
        if not name:
            continue
        entry = found.get(name)
        if entry is None:
            entry = HostStat(name=name, source=source)
            found[name] = entry
        entry.packets += 1
        entry.bytes += _safe_int(packet.length)
        if not entry.source and source:
            entry.source = source

    ordered = sorted(
        found.values(),
        key=lambda item: (-item.packets, -item.bytes, item.name),
    )
    return ordered[:limit] if limit > 0 else ordered


def endpoint_address(packet, source: bool = True) -> str:
    """Адрес узла без порта: IP, иначе MAC, иначе заглушка."""
    if source:
        return packet.src_ip or packet.src_mac or "?"
    return packet.dst_ip or packet.dst_mac or "?"


def endpoint_label(packet, source: bool = True) -> str:
    """Адрес узла вместе с портом, если порт известен."""
    address = endpoint_address(packet, source=source)
    port = packet.src_port if source else packet.dst_port
    if port is None:
        return address
    return "{}:{}".format(address, port)


def _safe_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Иерархия протоколов
# ---------------------------------------------------------------------------
def protocol_hierarchy(packets: Sequence) -> list[ProtocolStat]:
    """
    Дерево протоколов: транспорт сверху, прикладные протоколы вложенно.

    Доля считается от всех пакетов файла, а не от показанных строк.
    """
    total_packets = len(packets)
    total_bytes = sum(_safe_int(packet.length) for packet in packets)

    transport: dict[str, list[int]] = {}
    apps: dict[str, dict[str, list[int]]] = {}

    for packet in packets:
        name = (packet.protocol or "?").upper()
        length = _safe_int(packet.length)
        entry = transport.setdefault(name, [0, 0])
        entry[0] += 1
        entry[1] += length

        app = (packet.app or "").upper()
        if app and app != name:
            bucket = apps.setdefault(name, {})
            app_entry = bucket.setdefault(app, [0, 0])
            app_entry[0] += 1
            app_entry[1] += length

    rows: list[ProtocolStat] = []
    for name, (count, size) in sorted(
        transport.items(), key=lambda item: (-item[1][0], item[0])
    ):
        rows.append(
            ProtocolStat(
                name=name,
                packets=count,
                bytes=size,
                share=_share(count, total_packets),
                level=0,
            )
        )
        for app_name, (app_count, app_size) in sorted(
            apps.get(name, {}).items(), key=lambda item: (-item[1][0], item[0])
        ):
            rows.append(
                ProtocolStat(
                    name=app_name,
                    packets=app_count,
                    bytes=app_size,
                    share=_share(app_count, total_packets),
                    level=1,
                    parent=name,
                )
            )

    if rows:
        rows.append(
            ProtocolStat(
                name="Всего",
                packets=total_packets,
                bytes=total_bytes,
                share=100.0 if total_packets else 0.0,
                level=0,
            )
        )
    return rows


def _share(part: int, total: int) -> float:
    if not total:
        return 0.0
    return 100.0 * part / total


# ---------------------------------------------------------------------------
# Разговоры
# ---------------------------------------------------------------------------
def conversations(packets: Sequence, limit: int = 25) -> list[Conversation]:
    """Топ пар «узел A — узел B» по числу пакетов."""
    pairs: dict[tuple[str, str], Conversation] = {}

    for packet in packets:
        left = endpoint_label(packet, source=True)
        right = endpoint_label(packet, source=False)
        first, second = sorted((left, right))

        conversation = pairs.get((first, second))
        if conversation is None:
            conversation = Conversation(endpoint_a=first, endpoint_b=second)
            pairs[(first, second)] = conversation

        length = _safe_int(packet.length)
        if left == first:
            conversation.packets_a_to_b += 1
            conversation.bytes_a_to_b += length
        else:
            conversation.packets_b_to_a += 1
            conversation.bytes_b_to_a += length

    ordered = sorted(
        pairs.values(),
        key=lambda item: (-item.total_bytes, -item.total_packets),
    )
    return ordered[:limit] if limit > 0 else ordered


# ---------------------------------------------------------------------------
# Узлы
# ---------------------------------------------------------------------------
def endpoints(packets: Sequence, limit: int = 25) -> list[EndpointStat]:
    """Топ узлов: сколько байт отправил и получил каждый адрес."""
    nodes: dict[str, EndpointStat] = {}

    for packet in packets:
        length = _safe_int(packet.length)
        sender = endpoint_address(packet, source=True)
        receiver = endpoint_address(packet, source=False)

        node = nodes.setdefault(sender, EndpointStat(address=sender))
        node.packets_sent += 1
        node.bytes_sent += length

        node = nodes.setdefault(receiver, EndpointStat(address=receiver))
        node.packets_received += 1
        node.bytes_received += length

    ordered = sorted(
        nodes.values(),
        key=lambda item: (-item.total_bytes, -item.total_packets),
    )
    return ordered[:limit] if limit > 0 else ordered


# ---------------------------------------------------------------------------
# Сводка
# ---------------------------------------------------------------------------
def summary(packets: Sequence) -> dict:
    """Короткая сводка: длительность, размеры, число узлов."""
    if not packets:
        return {
            "packets": 0,
            "bytes": 0,
            "duration": 0.0,
            "average_length": 0.0,
            "addresses": 0,
            "protocols": 0,
        }

    total_bytes = sum(_safe_int(packet.length) for packet in packets)
    timestamps = [packet.timestamp for packet in packets]
    duration = max(timestamps) - min(timestamps)
    addresses = set()
    protocols = set()

    for packet in packets:
        addresses.add(endpoint_address(packet, source=True))
        addresses.add(endpoint_address(packet, source=False))
        protocols.add((packet.protocol or "?").upper())

    return {
        "packets": len(packets),
        "bytes": total_bytes,
        "duration": duration,
        "average_length": total_bytes / len(packets),
        "addresses": len(addresses),
        "protocols": len(protocols),
    }


def format_bytes(value: int) -> str:
    """Человеческий размер: 512 Б, 4.2 КБ, 1.7 МБ."""
    size = float(value)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if size < 1024 or unit == "ГБ":
            if unit == "Б":
                return "{:.0f} {}".format(size, unit)
            return "{:.1f} {}".format(size, unit)
        size /= 1024.0
    return "{:.1f} ГБ".format(size)


def format_duration(seconds: float) -> str:
    """Длительность в удобном виде: 2.5 с, 3 мин 12 с."""
    if seconds < 60:
        return "{:.3f} с".format(seconds)
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return "{:.0f} мин {:.0f} с".format(minutes, rest)
    hours, minutes = divmod(minutes, 60)
    return "{:.0f} ч {:.0f} мин".format(hours, minutes)
