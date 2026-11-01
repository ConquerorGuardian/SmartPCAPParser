"""
Smart PCAP Parser — фильтры Wireshark из обычных слов.

Пакет `parser` содержит:
- engine     — разбор текстовой команды (IP, порты, MAC, протоколы, имена);
- filters    — сборка display-фильтра Wireshark;
- pcap_reader — чтение .pcap/.pcapng без tshark, фрагменты, имена;
- matcher    — применение display-фильтра к пакетам;
- pcap_handler — превью, подсчёт совпадений, экспорт в CSV;
- streams    — сборка TCP-потоков и UDP-обменов;
- stats      — иерархия, разговоры, узлы, имена, график по времени;
- verdict    — вердикт по файлу простыми словами;
- settings   — сохранение настроек между запусками.
"""

from .engine import NaturalLanguageFilterEngine, ParsedQuery
from .filters import generate_filter
from .matcher import FilterError, compile_filter
from .pcap_handler import PcapHandler, PcapResult
from .pcap_reader import Packet, PcapError, read_packets, read_payloads
from .settings import load_settings, save_settings
from .stats import hosts, timeline
from .streams import (
    TcpStream,
    assemble_segments,
    find_streams,
    follow_datagram_flow,
    follow_stream,
    render_stream,
    summarize,
)

__all__ = [
    "NaturalLanguageFilterEngine",
    "ParsedQuery",
    "generate_filter",
    "FilterError",
    "compile_filter",
    "PcapHandler",
    "PcapResult",
    "Packet",
    "PcapError",
    "read_packets",
    "read_payloads",
    "TcpStream",
    "assemble_segments",
    "find_streams",
    "follow_stream",
    "follow_datagram_flow",
    "render_stream",
    "summarize",
    "hosts",
    "timeline",
    "load_settings",
    "save_settings",
]

__version__ = "1.9.1"
