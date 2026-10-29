"""
Сборка TCP-потоков («Follow TCP stream»).

Модуль берёт пакеты, уже разобранные `pcap_reader`, и склеивает данные
одного TCP-соединения в два направления: клиент → сервер и сервер → клиент.

Что делается:
- сегменты раскладываются по sequence number, поэтому порядок в файле
  не важен: ретрансмиссии и перестановки не ломают результат;
- полные дубликаты отбрасываются, частичные перекрытия обрезаются;
- дыры (потерянные при захвате байты) запоминаются и показываются
  в выводе как «[пропущено N байт]»;
- 32-битное переполнение sequence number обрабатывается (RFC 1982).

Типовой сценарий:

    packets, _ = read_packets("capture.pcap", keep_payload=True)
    stream = follow_stream(packets, frame_number=6)
    print(render_stream(stream, view="both", mode="text"))
"""

from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

from .pcap_reader import Packet

SEQ_MODULO = 1 << 32
SEQ_HALF = 1 << 31

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

VIEW_CLIENT = "client"
VIEW_SERVER = "server"
VIEW_BOTH = "both"

MODE_TEXT = "text"
MODE_HEX = "hex"

#: Сколько байт максимум отдавать в окно предпросмотра (защита от гигантских
#: потоков вида «скачали 300 МБ файла»).
MAX_RENDER_BYTES = 2 * 1024 * 1024

Endpoint = tuple[str, int]


# ---------------------------------------------------------------------------
# Сборка одного направления
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Chunk:
    """Непрерывный кусок данных, начинающийся со смещения offset."""

    offset: int
    data: bytes


@dataclass(frozen=True)
class Gap:
    """Дыра в данных: offset байт не были захвачены."""

    offset: int
    length: int


@dataclass
class AssembledStream:
    """Склеенные данные одного направления TCP-потока."""

    chunks: list[Chunk] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    segments: int = 0            # сегментов, попавших в результат
    retransmissions: int = 0     # отброшенных дубликатов
    bytes_seen: int = 0          # всего байт пришло, с ретрансмиссиями

    @property
    def data(self) -> bytes:
        """Данные без учёта дыр (для сохранения в файл)."""
        return b"".join(chunk.data for chunk in self.chunks)

    @property
    def length(self) -> int:
        """Сколько байт реально собрано."""
        return sum(len(chunk.data) for chunk in self.chunks)

    @property
    def missing(self) -> int:
        """Сколько байт потеряно при захвате."""
        return sum(gap.length for gap in self.gaps)

    def __bool__(self) -> bool:
        return bool(self.chunks)


def assemble_segments(segments: Iterable[tuple[int, bytes]]) -> AssembledStream:
    """
    Склеивает (sequence_number, payload) в непрерывные куски.

    Порядок сегментов на входе произвольный. Дубликаты отбрасываются,
    перекрытия обрезаются, дыры попадают в `gaps`.
    """
    prepared = [(seq, payload) for seq, payload in segments if payload]
    if not prepared:
        return AssembledStream()

    base = prepared[0][0]

    # Переводим абсолютные sequence number в смещения относительно первого
    # сегмента. Модуль 2**32 и «половина» дают корректную работу при
    # переполнении счётчика.
    normalized = []
    for seq, payload in prepared:
        offset = (seq - base) % SEQ_MODULO
        if offset >= SEQ_HALF:
            offset -= SEQ_MODULO
        normalized.append((offset, payload))
    normalized.sort(key=lambda item: item[0])

    shift = normalized[0][0]
    if shift:
        normalized = [(offset - shift, payload) for offset, payload in normalized]

    chunks: list[Chunk] = []
    gaps: list[Gap] = []
    expected = 0
    retransmissions = 0
    bytes_seen = 0

    for offset, payload in normalized:
        bytes_seen += len(payload)
        end = offset + len(payload)

        if end <= expected:
            retransmissions += 1
            continue

        if offset >= expected:
            if offset > expected:
                gaps.append(Gap(offset=expected, length=offset - expected))
            chunks.append(Chunk(offset=offset, data=payload))
            expected = end
        else:
            # Частичное перекрытие: берём только новый хвост.
            chunks.append(Chunk(offset=expected, data=payload[expected - offset:]))
            expected = end

    return AssembledStream(
        chunks=chunks,
        gaps=gaps,
        segments=len(chunks),
        retransmissions=retransmissions,
        bytes_seen=bytes_seen,
    )


# ---------------------------------------------------------------------------
# Поток целиком
# ---------------------------------------------------------------------------
@dataclass
class StreamDirection:
    """Одно направление потока."""

    sender: Endpoint
    receiver: Endpoint
    label: str
    stream: AssembledStream
    packets: list[Packet] = field(default_factory=list)

    @property
    def data(self) -> bytes:
        return self.stream.data


@dataclass
class TcpStream:
    """TCP-соединение: два направления и список пакетов."""

    key: tuple
    client: Endpoint
    server: Endpoint
    packets: list[Packet]
    client_to_server: StreamDirection
    server_to_client: StreamDirection
    kind: str = "TCP"

    @property
    def packet_numbers(self) -> list[int]:
        return [packet.number for packet in self.packets]

    @property
    def first_timestamp(self) -> float:
        return self.packets[0].timestamp if self.packets else 0.0

    @property
    def duration(self) -> float:
        if not self.packets:
            return 0.0
        return self.packets[-1].timestamp - self.packets[0].timestamp

    @property
    def total_bytes(self) -> int:
        return self.client_to_server.stream.length + self.server_to_client.stream.length

    def directions(self, view: str = VIEW_BOTH) -> list[StreamDirection]:
        if view == VIEW_CLIENT:
            return [self.client_to_server]
        if view == VIEW_SERVER:
            return [self.server_to_client]
        return [self.client_to_server, self.server_to_client]

    def peer(self, packet: Packet) -> Endpoint:
        """Куда идёт пакет — в терминах клиент/сервер."""
        if (packet.src_ip, packet.src_port) == self.client:
            return self.server
        return self.client


# ---------------------------------------------------------------------------
# Поиск потока
# ---------------------------------------------------------------------------
def format_endpoint(endpoint: Endpoint) -> str:
    host, port = endpoint
    if ":" in host:          # IPv6
        return "[{}]:{}".format(host, port)
    return "{}:{}".format(host, port)


def flow_key(packet: Packet) -> Optional[tuple]:
    """
    Ключ соединения: пара концов в отсортированном виде.

    Благодаря сортировке пакеты обоих направлений попадают в один поток.
    Для не-TCP пакетов возвращается None.
    """
    if packet.transport != "TCP" or not packet.has_ports():
        return None

    first = (packet.src_ip, packet.src_port)
    second = (packet.dst_ip, packet.dst_port)
    return (first, second) if first <= second else (second, first)


def conversation_frames(packets: Sequence, frame_number: int,
                        kind: str = "tcp") -> list[int]:
    """Номера кадров того же соединения (TCP или UDP), что и выбранный пакет.

    Нужно для ленивой подгрузки данных из большого файла: читаем заново
    только эти кадры, а не весь дамп.
    """
    target = None
    for packet in packets:
        if packet.number == frame_number:
            target = packet
            break
    if target is None:
        return []

    key = datagram_key(target) if kind == "udp" else flow_key(target)
    if key is None:
        return []
    key_function = datagram_key if kind == "udp" else flow_key
    return [
        packet.number for packet in packets if key_function(packet) == key
    ]


def datagram_key(packet: Packet) -> Optional[tuple]:
    """Ключ UDP-обмена: та же пара концов, что и у TCP-потока."""
    if packet.transport != "UDP" or not packet.has_ports():
        return None
    first = (packet.src_ip, packet.src_port)
    second = (packet.dst_ip, packet.dst_port)
    return (first, second) if first <= second else (second, first)


def follow_datagram_flow(
    packets: Sequence[Packet],
    frame_number: int,
) -> Optional[TcpStream]:
    """
    Собирает UDP-обмен, к которому относится пакет.

    У UDP нет sequence number, поэтому датаграммы просто идут в порядке
    захвата: каждое направление — непрерывная лента данных. Результат
    совместим с отрисовкой TCP-потока, чтобы не дублировать окно.
    """
    target = None
    for packet in packets:
        if packet.number == frame_number:
            target = packet
            break
    if target is None:
        return None

    key = datagram_key(target)
    if key is None:
        return None

    members = [packet for packet in packets if datagram_key(packet) == key]
    if not members:
        return None

    first = members[0]
    client = (first.src_ip, first.src_port)
    server = (first.dst_ip, first.dst_port)

    client_data: list[bytes] = []
    server_data: list[bytes] = []
    client_packets: list[Packet] = []
    server_packets: list[Packet] = []

    for packet in members:
        if not packet.payload:
            continue
        if (packet.src_ip, packet.src_port) == client:
            client_data.append(packet.payload)
            client_packets.append(packet)
        else:
            server_data.append(packet.payload)
            server_packets.append(packet)

    def build(direction_data: list[bytes]) -> AssembledStream:
        offset = 0
        chunks = []
        for payload in direction_data:
            chunks.append(Chunk(offset=offset, data=payload))
            offset += len(payload)
        return AssembledStream(
            chunks=chunks,
            segments=len(chunks),
            bytes_seen=offset,
        )

    return TcpStream(
        key=key,
        client=client,
        server=server,
        packets=members,
        client_to_server=StreamDirection(
            sender=client,
            receiver=server,
            label="{} -> {}".format(format_endpoint(client), format_endpoint(server)),
            stream=build(client_data),
            packets=client_packets,
        ),
        server_to_client=StreamDirection(
            sender=server,
            receiver=client,
            label="{} -> {}".format(format_endpoint(server), format_endpoint(client)),
            stream=build(server_data),
            packets=server_packets,
        ),
        kind="UDP",
    )


def _client_endpoint(members: Sequence[Packet]) -> Endpoint:
    """Клиент — тот, кто отправил SYN без ACK; иначе отправитель первого пакета."""
    for packet in members:
        if packet.tcp_flags & TCP_SYN and not packet.tcp_flags & TCP_ACK:
            return (packet.src_ip, packet.src_port)
    first = members[0]
    return (first.src_ip, first.src_port)


def follow_stream(
    packets: Sequence[Packet],
    frame_number: int,
) -> Optional[TcpStream]:
    """
    Собирает поток, к которому относится пакет с номером `frame_number`.

    Returns:
        TcpStream или None, если пакет не найден либо не является TCP.
    """
    target = None
    for packet in packets:
        if packet.number == frame_number:
            target = packet
            break
    if target is None:
        return None

    key = flow_key(target)
    if key is None:
        return None

    members = [packet for packet in packets if flow_key(packet) == key]
    if not members:
        return None

    client = _client_endpoint(members)
    first = members[0]
    if client == (first.src_ip, first.src_port):
        server = (first.dst_ip, first.dst_port)
    else:
        server = (first.src_ip, first.src_port)

    client_segments = []
    server_segments = []
    client_packets = []
    server_packets = []

    for packet in members:
        if not packet.payload:
            continue
        source = (packet.src_ip, packet.src_port)
        if source == client:
            client_segments.append((packet.seq, packet.payload))
            client_packets.append(packet)
        else:
            server_segments.append((packet.seq, packet.payload))
            server_packets.append(packet)

    client_to_server = StreamDirection(
        sender=client,
        receiver=server,
        label="{} -> {}".format(format_endpoint(client), format_endpoint(server)),
        stream=assemble_segments(client_segments),
        packets=client_packets,
    )
    server_to_client = StreamDirection(
        sender=server,
        receiver=client,
        label="{} -> {}".format(format_endpoint(server), format_endpoint(client)),
        stream=assemble_segments(server_segments),
        packets=server_packets,
    )

    return TcpStream(
        key=key,
        client=client,
        server=server,
        packets=members,
        client_to_server=client_to_server,
        server_to_client=server_to_client,
    )


def find_streams(packets: Sequence[Packet]) -> list[TcpStream]:
    """Собирает все TCP-потоки файла (в порядке первого появления)."""
    seen: dict[tuple, TcpStream] = {}
    order: list[tuple] = []

    for packet in packets:
        key = flow_key(packet)
        if key is None or key in seen:
            continue
        stream = follow_stream(packets, packet.number)
        if stream is None:
            continue
        seen[key] = stream
        order.append(key)

    return [seen[key] for key in order]


# ---------------------------------------------------------------------------
# Вывод
# ---------------------------------------------------------------------------
_PRINTABLE_EXTRA = {"\n", "\r", "\t"}


def _sanitize(text: str) -> str:
    """Оставляет печатные символы, управляющие заменяет точкой."""
    return "".join(
        char if char in _PRINTABLE_EXTRA or char.isprintable() else "."
        for char in text
    )


def _gaps_before_chunks(stream: AssembledStream) -> dict[int, Gap]:
    """
    Дыры, привязанные к смещению следующего за ними куска.

    Сборщик создаёт дыру тогда, когда ожидаемый байт не пришёл, поэтому
    конец дыры всегда совпадает с началом следующего куска.
    """
    return {gap.offset + gap.length: gap for gap in stream.gaps}


def render_text(stream: AssembledStream, limit: int = MAX_RENDER_BYTES) -> str:
    """Данные направления как текст. Бинарные байты заменяются точками."""
    pieces: list[str] = []
    used = 0
    gap_map = _gaps_before_chunks(stream)

    for chunk in stream.chunks:
        gap = gap_map.get(chunk.offset)
        if gap is not None:
            pieces.append("\n[пропущено {} байт]\n".format(gap.length))

        data = chunk.data
        if used + len(data) > limit:
            data = data[: max(limit - used, 0)]
        used += len(data)
        pieces.append(_sanitize(data.decode("utf-8", errors="replace")))
        if used >= limit:
            pieces.append("\n[... вывод обрезан: показаны первые {} байт ...]\n".format(limit))
            break

    text = "".join(pieces)
    return text if text.endswith("\n") else text + "\n"


def render_hex(stream: AssembledStream, limit: int = MAX_RENDER_BYTES) -> str:
    """Данные направления как hex-дамп: смещение, 16 байт, ASCII."""
    lines: list[str] = []
    used = 0
    gap_map = _gaps_before_chunks(stream)

    for chunk in stream.chunks:
        gap = gap_map.get(chunk.offset)
        if gap is not None:
            lines.append("{:08x}  << пропущено {} байт >>".format(gap.offset, gap.length))

        data = chunk.data
        if used + len(data) > limit:
            data = data[: max(limit - used, 0)]
        used += len(data)

        for index in range(0, len(data), 16):
            block = data[index:index + 16]
            hex_part = " ".join("{:02x}".format(byte) for byte in block).ljust(47)
            text_part = "".join(
                chr(byte) if 32 <= byte < 127 else "." for byte in block
            )
            lines.append(
                "{:08x}  {}  {}".format(chunk.offset + index, hex_part, text_part)
            )

        if used >= limit:
            lines.append("... вывод обрезан: показаны первые {} байт ...".format(limit))
            break

    return "\n".join(lines) + "\n" if lines else ""


def direction_header(direction: StreamDirection) -> str:
    """Заголовок блока направления — как разделитель в Wireshark."""
    stream = direction.stream
    return "=== {} · {} байт · {} сегментов ===\n".format(
        direction.label, stream.length, stream.segments
    )


def render_direction(direction: StreamDirection, mode: str = MODE_TEXT,
                     limit: int = MAX_RENDER_BYTES) -> str:
    body = render_hex(direction.stream, limit) if mode == MODE_HEX else render_text(
        direction.stream, limit
    )
    if not body:
        body = "(данных нет)\n"
    return direction_header(direction) + body


def render_stream(stream: TcpStream, view: str = VIEW_BOTH,
                  mode: str = MODE_TEXT, limit: int = MAX_RENDER_BYTES) -> str:
    """Готовый текст для окна предпросмотра."""
    blocks = [
        render_direction(direction, mode=mode, limit=limit)
        for direction in stream.directions(view)
    ]
    return "\n".join(blocks)


def summarize(stream: TcpStream) -> str:
    """Одна строка для строки состояния."""
    return (
        "Поток {} <-> {}: пакетов {}, клиент -> сервер {} байт, "
        "сервер -> клиент {} байт".format(
            format_endpoint(stream.client),
            format_endpoint(stream.server),
            len(stream.packets),
            stream.client_to_server.stream.length,
            stream.server_to_client.stream.length,
        )
    )
