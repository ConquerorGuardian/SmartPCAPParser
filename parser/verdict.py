"""
Вердикт по файлу: короткий человеческий ответ «что это за трафик
и на что смотреть».

Модуль ничего не знает про интерфейс: на вход идут пакеты, на выход —
готовая структура с текстом и командами для фильтра. GUI только рисует.

Идея простая: человек открывает дамп и не должен сам придумывать,
с чего начать. Мы говорим словами, что увидели, и даём кнопки
«показать вот это».
"""

from dataclasses import dataclass, field
from typing import Sequence

from .stats import conversations, format_bytes, format_duration, hosts, summary

# Порядок важности: сначала то, что горит.
SEVERITY_ORDER = {
    "critical": 0,
    "warning": 1,
    "info": 2,
}

# Порты, обращения к которым стоит показать человеку.
WATCH_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
}

TCP_SYN = 0x002
TCP_ACK = 0x010
TCP_RST = 0x004
TCP_SYN_ACK = TCP_SYN | TCP_ACK

# Пороги детекторов. Вынесены в константы, чтобы их было видно и можно было
# подкрутить под реальный трафик, а не искать числа по коду.
MIN_SILENT_SYN = 3          # сколько SYN без ответа уже подозрительно
MANY_SILENT_TARGETS = 5     # столько разных молчащих адресов — «критично»
RESET_WARNING = 3           # с какого числа RST писать предупреждение
ARP_MIN_PACKETS = 5         # меньше — просто шум, не находка
ARP_SHARE = 0.20            # доля ARP, после которой это уже шторм
UNDECODABLE_SHARE = 0.30    # доля неразобранных кадров, о которой стоит сказать
SCAN_MIN_PORTS = 15         # столько разных портов с одного адреса — уже скан
SCAN_CRITICAL_PORTS = 30    # столько — почти наверняка скан
ICMP_ERROR_MIN = 3          # столько ICMP-ошибок уже стоит показать
BROADCAST_SHARE = 0.25      # доля широковещательных кадров
BROADCAST_MIN = 20          # минимум таких кадров, чтобы говорить о шторме
TOP_TALKER_SHARE = 0.60     # один узел отправляет столько байт
TOP_TALKER_MIN = 100        # и минимум столько пакетов


@dataclass
class Finding:
    """Одна находка: что заметили и чем это посмотреть."""

    title: str
    detail: str
    severity: str = "info"          # critical / warning / info
    command: str = ""               # команда для поля ввода, если применима


@dataclass
class Verdict:
    """Итог по файлу целиком."""

    headline: str = ""
    overview: str = ""
    findings: list[Finding] = field(default_factory=list)
    packets: int = 0
    duration: float = 0.0
    bytes: int = 0

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "info"
        return min(
            (finding.severity for finding in self.findings),
            key=lambda severity: SEVERITY_ORDER.get(severity, 3),
        )

    def has_commands(self) -> bool:
        return any(finding.command for finding in self.findings)


# ---------------------------------------------------------------------------
# Вспомогательные проверки
# ---------------------------------------------------------------------------
def _is_private_ip(address: str) -> bool:
    """Частный ли адрес. Нужно, чтобы понять «наружу» это или внутри."""
    if not address:
        return False

    if address.startswith(("10.", "127.", "169.254.", "192.168.")):
        return True

    if address.startswith("172."):
        parts = address.split(".")
        if len(parts) > 1 and parts[1].isdigit():
            return 16 <= int(parts[1]) <= 31

    lowered = address.lower()
    if lowered in ("::1", "::"):
        return True
    return lowered.startswith(("fc", "fd", "fe80"))


def _tcp_flags(packet) -> int:
    return int(getattr(packet, "tcp_flags", 0) or 0)


def _has_flag(packet, mask: int) -> bool:
    return (_tcp_flags(packet) & mask) == mask


# ---------------------------------------------------------------------------
# Детекторы
# ---------------------------------------------------------------------------
def detect_unanswered_syn(packets: Sequence) -> list[Finding]:
    """SYN без ответного SYN+ACK — типичная картина сканирования портов."""
    attempts: dict[tuple[str, int], int] = {}
    answered: set[tuple[str, int]] = set()

    for packet in packets:
        if (packet.protocol or "").upper() != "TCP":
            continue

        flags = _tcp_flags(packet)
        if _has_flag(packet, TCP_SYN_ACK):
            answered.add((packet.src_ip, packet.src_port))
        elif _has_flag(packet, TCP_SYN) and not _has_flag(packet, TCP_ACK):
            target = (packet.dst_ip, packet.dst_port)
            attempts[target] = attempts.get(target, 0) + 1

    if not attempts:
        return []

    silent = {
        target: count
        for target, count in attempts.items()
        if target not in answered
    }
    total_silent = sum(silent.values())
    if total_silent < MIN_SILENT_SYN:
        return []

    target, count = max(silent.items(), key=lambda item: item[1])
    address, port = target
    severity = "critical" if len(silent) >= MANY_SILENT_TARGETS else "warning"
    return [Finding(
        title="Подключения без ответа",
        detail=(
            "{} попыток подключиться, ответа нет. Чаще всего у "
            "{} портов — похоже на сканирование.".format(total_silent, len(silent))
        ),
        severity=severity,
        command="покажи пакеты к {}".format(address),
    )]


def detect_resets(packets: Sequence) -> list[Finding]:
    """RST — соединения рвут: либо сервис закрыт, либо кто-то вмешался."""
    resets = [
        packet for packet in packets
        if (packet.protocol or "").upper() == "TCP" and _has_flag(packet, TCP_RST)
    ]
    if not resets:
        return []

    targets = sorted({
        "{}:{}".format(packet.dst_ip, packet.dst_port)
        for packet in resets
        if packet.dst_ip
    })
    detail = "{} соединений сброшено (RST)".format(len(resets))
    if targets:
        detail += ". Больше всего достаётся {}".format(", ".join(targets[:2]))

    return [Finding(
        title="Сбросы соединений",
        detail=detail,
        severity="warning" if len(resets) >= RESET_WARNING else "info",
        command="покажи tcp трафик",
    )]


def detect_dns_gap(packets: Sequence) -> list[Finding]:
    """Запросы DNS без ответов: имена не разрешаются или ответы не дошли."""
    queries = [
        packet for packet in packets
        if packet.dst_port == 53 and (packet.protocol or "").upper() in ("UDP", "TCP")
    ]
    answers = [
        packet for packet in packets
        if packet.src_port == 53 and (packet.protocol or "").upper() in ("UDP", "TCP")
    ]
    if not queries or len(queries) <= len(answers):
        return []

    return [Finding(
        title="DNS без ответа",
        detail="{} запросов и только {} ответов. Часть имён не разрешилась.".format(
            len(queries), len(answers)
        ),
        severity="warning" if not answers else "info",
        command="покажи dns трафик",
    )]


def detect_arp_noise(packets: Sequence) -> list[Finding]:
    """Много ARP — широковещательный шум, конфликт адресов или петля."""
    arp = [packet for packet in packets if (packet.protocol or "").upper() == "ARP"]
    if len(arp) < ARP_MIN_PACKETS or len(arp) < ARP_SHARE * len(packets):
        return []

    share = 100.0 * len(arp) / len(packets)
    return [Finding(
        title="Много ARP",
        detail="{} ARP-пакетов — {:.0f}% трафика. Проверьте конфликт адресов "
               "или петлю в сети.".format(len(arp), share),
        severity="warning",
        command="покажи arp трафик",
    )]


def detect_watch_ports(packets: Sequence) -> list[Finding]:
    """Обращения к «интересным» портам из частной сети наружу."""
    findings: list[Finding] = []
    seen: dict[int, int] = {}

    for packet in packets:
        port = packet.dst_port
        if port not in WATCH_PORTS:
            continue
        if _is_private_ip(packet.src_ip) and not _is_private_ip(packet.dst_ip):
            seen[port] = seen.get(port, 0) + 1

    for port, count in sorted(seen.items(), key=lambda item: -item[1])[:3]:
        findings.append(Finding(
            title="Обращения к {}".format(WATCH_PORTS[port]),
            detail="{} пакетов из локальной сети на порт {} — сервис обычно "
                   "не должен торчать наружу.".format(count, port),
            severity="warning" if port in (23, 445, 3389) else "info",
            command="покажи пакеты на порт {}".format(port),
        ))
    return findings


def detect_undecodable(packets: Sequence) -> list[Finding]:
    """Кадры, которые не разобрались: экзотический тип канала."""
    broken = [packet for packet in packets if (packet.protocol or "") == "?"]
    if not broken or len(broken) < UNDECODABLE_SHARE * len(packets):
        return []

    detail = "{} из {} пакетов не разобраны — этот тип кадра не поддерживается.".format(
        len(broken), len(packets)
    )
    hint = next((packet.info for packet in broken if packet.info), "")
    if hint:
        detail += " " + hint.rstrip(".") + "."

    return [Finding(
        title="Формат кадра не поддерживается",
        detail=detail,
        severity="warning",
    )]


def detect_port_scan(packets: Sequence) -> list[Finding]:
    """Один адрес стучится во много портов — похоже на скан."""
    hits: dict[tuple[str, str], set[int]] = {}

    for packet in packets:
        if (packet.protocol or "").upper() != "TCP":
            continue
        flags = _tcp_flags(packet)
        if not (flags & TCP_SYN) or (flags & TCP_ACK):
            continue
        if packet.dst_port is None or not packet.dst_ip:
            continue
        hits.setdefault((packet.src_ip, packet.dst_ip), set()).add(packet.dst_port)

    if not hits:
        return []

    (source, target), ports = max(hits.items(), key=lambda item: len(item[1]))
    if len(ports) < SCAN_MIN_PORTS:
        return []

    return [Finding(
        title="Похоже на сканирование портов",
        detail="{} обращался к {} портам на {}. {} — это перебор портов, "
               "а не обычная работа.".format(
                   source or "?", len(ports), target,
                   ", ".join(str(port) for port in sorted(ports)[:5]),
               ),
        severity="critical" if len(ports) >= SCAN_CRITICAL_PORTS else "warning",
        command="покажи пакеты к {}".format(target),
    )]


def detect_icmp_errors(packets: Sequence) -> list[Finding]:
    """ICMP «сеть недоступна» и «время истекло»: адресат не находится."""
    errors = [
        packet for packet in packets
        if (packet.protocol or "").upper() == "ICMP"
        and int(getattr(packet, "icmp_type", 0) or 0) in (3, 11)
    ]
    if len(errors) < ICMP_ERROR_MIN:
        return []

    hosts = sorted({packet.src_ip for packet in errors if packet.src_ip})
    detail = "{} ICMP-ошибок: сеть или адресат недоступны".format(len(errors))
    if hosts:
        detail += " (отвечают: {})".format(", ".join(hosts[:2]))
    return [Finding(
        title="ICMP-ошибки",
        detail=detail + ".",
        severity="warning",
        command="покажи icmp трафик",
    )]


def _is_broadcast_or_multicast(packet) -> bool:
    """Широковещательный MAC, broadcast IP или multicast IPv6."""
    if (getattr(packet, "dst_mac", "") or "").lower() == "ff:ff:ff:ff:ff:ff":
        return True
    address = getattr(packet, "dst_ip", "") or ""
    if not address:
        return False
    if address.endswith(".255") or address == "255.255.255.255":
        return True
    if address.startswith("224.") or address.startswith("239."):
        return True
    return address.lower().startswith("ff")


def detect_broadcast_storm(packets: Sequence) -> list[Finding]:
    """Слишком много широковещательных кадров: петля или шумная сеть."""
    if len(packets) < BROADCAST_MIN:
        return []

    broadcast = [packet for packet in packets if _is_broadcast_or_multicast(packet)]
    share = len(broadcast) / len(packets)
    if len(broadcast) < BROADCAST_MIN or share < BROADCAST_SHARE:
        return []

    return [Finding(
        title="Много широковещательного трафика",
        detail="{} из {} кадров ({:.0f}%) — broadcast/multicast. Обычно это "
               "шум Discovery-протоколов или петля.".format(
                   len(broadcast), len(packets), share * 100
               ),
        severity="warning",
        command="покажи arp трафик",
    )]


def detect_top_talker(packets: Sequence) -> list[Finding]:
    """Кто отправил больше всех — с него и начинать разбор."""
    if len(packets) < TOP_TALKER_MIN:
        return []

    sent: dict[str, list[int]] = {}
    for packet in packets:
        address = packet.src_ip or packet.src_mac
        if not address:
            continue
        entry = sent.setdefault(address, [0, 0])
        entry[0] += 1
        entry[1] += int(packet.length or 0)

    total_bytes = sum(value[1] for value in sent.values())
    if not total_bytes:
        return []

    address, (count, size) = max(sent.items(), key=lambda item: item[1][1])
    share = size / total_bytes
    if share < TOP_TALKER_SHARE:
        return []

    return [Finding(
        title="Самый активный узел",
        detail="{} отправил {} пакетов и {:.0f}% всех байт. Начните с него.".format(
            address, count, share * 100
        ),
        severity="info",
        command="покажи пакеты от {}".format(address),
    )]


DETECTORS = (
    detect_unanswered_syn,
    detect_resets,
    detect_dns_gap,
    detect_arp_noise,
    detect_watch_ports,
    detect_port_scan,
    detect_icmp_errors,
    detect_broadcast_storm,
    detect_top_talker,
    detect_undecodable,
)


# ---------------------------------------------------------------------------
# Сборка вердикта
# ---------------------------------------------------------------------------
def build_verdict(packets: Sequence) -> Verdict:
    """Главная функция: пакеты -> короткий понятный вывод."""
    if not packets:
        return Verdict(
            headline="В файле нет пакетов",
            overview="Откройте другой дамп: этот пустой или не разобрался.",
        )

    data = summary(packets)
    verdict = Verdict(
        headline="{} пакетов · {} · {}".format(
            data["packets"],
            format_bytes(data["bytes"]),
            format_duration(data["duration"]),
        ),
        packets=data["packets"],
        duration=data["duration"],
        bytes=data["bytes"],
    )

    verdict.overview = _build_overview(packets, data)

    findings: list[Finding] = []
    for detector in DETECTORS:
        try:
            findings.extend(detector(packets))
        except Exception:                        # noqa: BLE001
            # Один сломанный детектор не должен ломать вердикт целиком.
            continue

    findings.sort(key=lambda finding: SEVERITY_ORDER.get(finding.severity, 3))

    if not findings:
        findings.append(Finding(
            title="Явных проблем нет",
            detail="Ошибок, сбросов и подозрительных обращений не нашёл. "
                   "Можно смотреть статистику или искать по адресам.",
            severity="info",
            command="",
        ))

    verdict.findings = findings
    return verdict


def _build_overview(packets: Sequence, data: dict) -> str:
    """Одно-два предложения: чем занят трафик и кто с кем говорит."""
    counts: dict[str, int] = {}
    for packet in packets:
        name = (packet.protocol or "?").upper()
        counts[name] = counts.get(name, 0) + 1

    top = sorted(counts.items(), key=lambda item: -item[1])[:3]
    parts = ["{} {}".format(name, count) for name, count in top]
    text = "Больше всего: {}.".format(", ".join(parts))

    pairs = conversations(packets, limit=1)
    if pairs:
        conversation = pairs[0]
        text += " Активнее всех общались {} и {} — {} пакетов.".format(
            conversation.endpoint_a,
            conversation.endpoint_b,
            conversation.total_packets,
        )

    if data["addresses"]:
        text += " Узлов в файле: {}.".format(data["addresses"])

    names = hosts(packets, limit=3)
    if names:
        text += " Сайты и домены: {}.".format(
            ", ".join(host.name for host in names)
        )

    return text


def format_verdict(verdict: Verdict) -> str:
    """Текст вердикта для окна «подробнее» и для консоли."""
    lines = [verdict.headline, ""]
    if verdict.overview:
        lines.extend([verdict.overview, ""])

    for finding in verdict.findings:
        lines.append("• {} — {}".format(finding.title, finding.detail))
        if finding.command:
            lines.append("  команда: {}".format(finding.command))

    return "\n".join(lines).strip()
