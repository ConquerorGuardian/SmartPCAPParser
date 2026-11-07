"""Карточка одного узла: сколько отправил, получил, с кем говорил.

Чистая функция над списком пакетов, без tkinter: её же использует и окно,
и тесты. Порты и собеседники сортируются по числу пакетов.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from parser.stats import format_bytes, format_duration

PEERS_LIMIT = 12
PORTS_LIMIT = 10


@dataclass(frozen=True)
class Peer:
    """Второй конец разговора и его вклад."""

    address: str
    packets: int
    bytes: int


@dataclass(frozen=True)
class PortStat:
    port: int
    protocol: str
    packets: int


@dataclass(frozen=True)
class NodeCard:
    """Сводка по адресу за весь файл."""

    address: str
    local: bool
    total: int
    sent: int
    received: int
    bytes_sent: int
    bytes_received: int
    first_seen: float
    last_seen: float
    protocols: list[tuple[str, int]]
    ports: list[PortStat]
    peers: list[Peer]

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


def is_local_address(address: str) -> bool:
    """Локальная сеть, loopback или link-local. Multicast сюда не входит."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.is_multicast:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def looks_like_ip(value: str) -> bool:
    """Похоже ли значение на IP-адрес, а не на имя или MAC."""
    try:
        ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return True


def build_node_card(packets: Sequence, address: str) -> NodeCard | None:
    """Считает карточку; None, если в файле нет пакетов с таким адресом."""
    address = (address or "").strip().strip("[]")
    if not address:
        return None

    total = sent = received = 0
    bytes_sent = bytes_received = 0
    protocols: Counter[str] = Counter()
    ports: Counter[tuple[int, str]] = Counter()
    peers: dict[str, list[int]] = {}
    first_seen: float | None = None
    last_seen: float | None = None

    for packet in packets:
        from_source = packet.src_ip == address
        to_target = packet.dst_ip == address
        if not (from_source or to_target):
            continue

        length = packet.wire_length or packet.length
        total += 1
        if from_source:
            sent += 1
            bytes_sent += length
        if to_target:
            received += 1
            bytes_received += length

        protocols[packet.protocol or "?"] += 1
        if from_source and packet.src_port is not None:
            ports[(packet.src_port, packet.protocol or "?")] += 1
        if to_target and packet.dst_port is not None:
            ports[(packet.dst_port, packet.protocol or "?")] += 1

        other = packet.dst_ip if from_source else packet.src_ip
        if other:
            entry = peers.setdefault(other, [0, 0])
            entry[0] += 1
            entry[1] += length

        if first_seen is None or packet.timestamp < first_seen:
            first_seen = packet.timestamp
        if last_seen is None or packet.timestamp > last_seen:
            last_seen = packet.timestamp

    if not total or first_seen is None or last_seen is None:
        return None

    port_stats = [
        PortStat(port=port, protocol=protocol, packets=count)
        for (port, protocol), count in sorted(
            ports.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
        )[:PORTS_LIMIT]
    ]
    peer_stats = [
        Peer(address=name, packets=count, bytes=size)
        for name, (count, size) in sorted(
            peers.items(), key=lambda item: (-item[1][0], item[0])
        )[:PEERS_LIMIT]
    ]

    return NodeCard(
        address=address,
        local=is_local_address(address),
        total=total,
        sent=sent,
        received=received,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        first_seen=first_seen,
        last_seen=last_seen,
        protocols=protocols.most_common(),
        ports=port_stats,
        peers=peer_stats,
    )


def format_node_card(card: NodeCard) -> str:
    """Текст для окна и копирования в буфер."""
    kind = "локальная сеть" if card.local else "внешний адрес"
    first = datetime.fromtimestamp(card.first_seen).strftime("%H:%M:%S")
    last = datetime.fromtimestamp(card.last_seen).strftime("%H:%M:%S")
    lines = [
        f"Узел {card.address} ({kind})",
        "",
        f"Пакетов: {card.total}, отправил {card.sent}, получил {card.received}",
        "Байт: {} (отдал {}, принял {})".format(
            format_bytes(card.total_bytes),
            format_bytes(card.bytes_sent),
            format_bytes(card.bytes_received),
        ),
        f"Первый пакет: {first}, последний: {last}",
        f"Длительность: {format_duration(card.duration)}",
        "",
        "Протоколы: " + ", ".join(
            f"{name} {count}" for name, count in card.protocols[:8]
        ),
    ]

    if card.ports:
        lines += ["", "Порты:"]
        for item in card.ports:
            lines.append(
                "  {}/{}  {} пакетов".format(item.port, item.protocol, item.packets)
            )

    if card.peers:
        lines += ["", "Собеседники:"]
        for peer in card.peers:
            lines.append(
                "  {}  {} пакетов, {}".format(
                    peer.address, peer.packets, format_bytes(peer.bytes)
                )
            )
    return "\n".join(lines)
