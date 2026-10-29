"""
Вычислитель Wireshark display-фильтров.

Проект работает без tshark, поэтому сгенерированный фильтр нужно уметь
применять самостоятельно. Модуль разбирает подмножество синтаксиса
display-фильтров и превращает его в функцию-предикат над Packet.

Поддерживается:
- поля: ip.addr, ip.src, ip.dst, tcp.port, tcp.srcport, tcp.dstport,
  udp.port, udp.srcport, udp.dstport, eth.addr, eth.src, eth.dst;
- операторы == и !=; списки значений через запятую: tcp.port==80,443;
- логика and / or / not, скобки;
- одиночные имена протоколов: tcp, udp, icmp, arp, http, dns, tls,
  ssh, ftp, smtp, ntp, ip, ipv6.

Примеры:
    compile_filter("ip.addr==192.168.1.1")
    compile_filter("tcp.port==80 or tcp.port==443")
    compile_filter("eth.addr==aa:bb:cc:dd:ee:ff and not http")
"""

import re
from collections.abc import Callable

from .pcap_reader import Packet

Predicate = Callable[[Packet], bool]


class FilterError(ValueError):
    """Синтаксическая ошибка display-фильтра."""


# ---------------------------------------------------------------------------
# Токенизация
# ---------------------------------------------------------------------------
TOKEN_RE = re.compile(
    r"\(|\)|==|!=|<=|>=|&&|\|\||\.\.|\{|\}|,|[<>]|[^\s(),=&|!<>{}]+"
)

PROTOCOL_NAMES = {
    "ip", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "arp",
    "http", "http2", "dns", "tls", "ssl", "quic", "ssh", "ftp", "smtp", "ntp",
    "dhcp", "dhcpv6", "telnet", "pop3", "imap", "ldap", "smb", "rdp", "mysql",
    "mdns", "llmnr", "ssdp", "nbns", "netbios", "bgp", "radius", "xmpp", "irc",
    "l2tp", "ipsec", "isakmp", "gre", "igmp", "ospf", "esp", "ah", "icmp6",
    "mssql", "tds", "postgresql", "pgsql", "redis", "mongodb", "mongo",
    "sip", "snmp", "tftp", "vnc", "mqtt", "kerberos", "syslog", "stun",
    "openvpn", "socks", "nfs", "memcached",
}

# Имена Wireshark, которые отличаются от наших названий протоколов.
PROTOCOL_ALIASES = {
    "ssl": "tls",
    "tds": "mssql",
    "pgsql": "postgresql",
    "mongo": "mongodb",
    "icmp6": "icmpv6",
    "nbns": "netbios",
    "isakmp": "ipsec",
}

IP_FIELDS = {
    "ip.addr", "ip.src", "ip.dst",
    "ipv6.addr", "ipv6.src", "ipv6.dst",
}
PORT_FIELDS = {
    "tcp.port", "tcp.srcport", "tcp.dstport",
    "udp.port", "udp.srcport", "udp.dstport",
    "port", "srcport", "dstport",
}
MAC_FIELDS = {"eth.addr", "eth.src", "eth.dst", "eth"}

# Числовые поля: имя поля -> как достать число из пакета.
NUMERIC_FIELDS = {
    "frame.number": lambda p: p.number,
    "frame.len": lambda p: p.length,
    "frame.cap_len": lambda p: p.length,
    "ip.len": lambda p: p.ip_len,
    "ip.ttl": lambda p: p.ttl,
    "ipv6.hlim": lambda p: p.ttl,
    "ipv6.plen": lambda p: max(p.ip_len - 40, 0),
    "tcp.len": lambda p: p.tcp_len,
    "tcp.window_size": lambda p: p.tcp_window,
    "tcp.window_size_value": lambda p: p.tcp_window,
    "tcp.seq": lambda p: p.seq,
    "tcp.ack": lambda p: p.tcp_ack,
    "udp.length": lambda p: p.udp_len,
    "icmp.type": lambda p: p.icmp_type,
    "icmp.code": lambda p: p.icmp_code,
}

# Флаги TCP: бит в маске tcp_flags.
FLAG_FIELDS = {
    "tcp.flags.fin": 0x01,
    "tcp.flags.syn": 0x02,
    "tcp.flags.rst": 0x04,
    "tcp.flags.push": 0x08,
    "tcp.flags.psh": 0x08,
    "tcp.flags.ack": 0x10,
    "tcp.flags.urg": 0x20,
    "tcp.flags.ece": 0x40,
    "tcp.flags.cwr": 0x80,
}

# Строковые поля: имя поля -> как достать строку из пакета.
STRING_FIELDS = {
    "http.host": lambda p: p.host,
    "http.request.uri": lambda p: p.http_uri,
    "tls.handshake.extensions_server_name": lambda p: p.sni,
    "tls.sni": lambda p: p.sni,
    "dns.qry.name": lambda p: p.dns_name,
}

# Поля, у которых значение ищется в данных пакета (payload).
PAYLOAD_FIELDS = {"frame", "tcp", "udp"}

# Сравнения для числовых полей (порты) — нужны для диапазонов.
PORT_OPS = {
    "==": lambda left, right: left == right,
    "!=": lambda left, right: left != right,
    ">": lambda left, right: left > right,
    "<": lambda left, right: left < right,
    ">=": lambda left, right: left >= right,
    "<=": lambda left, right: left <= right,
}


def normalize_mac(value: str) -> str:
    """Приводит MAC к виду aa:bb:cc:dd:ee:ff (принимает :, -, . и слитный вид)."""
    digits = re.sub(r"[^0-9a-f]", "", value.strip().lower())
    if len(digits) != 12:
        return value.strip().lower()
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


def _tokenize(text: str) -> list[str]:
    tokens = TOKEN_RE.findall(text)
    if not tokens:
        raise FilterError("Пустой фильтр")
    return tokens


# ---------------------------------------------------------------------------
# Узлы фильтра
# ---------------------------------------------------------------------------
class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    # -- утилиты --------------------------------------------------------
    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, expected: str | None = None) -> str:
        if self.pos >= len(self.tokens):
            raise FilterError("Неожиданный конец фильтра")
        token = self.tokens[self.pos]
        if expected is not None and token != expected:
            raise FilterError(f"Ожидалось '{expected}', получено '{token}'")
        self.pos += 1
        return token

    def at_end(self) -> bool:
        return self.pos >= len(self.tokens)

    # -- грамматика -----------------------------------------------------
    def parse(self) -> Predicate:
        node = self.parse_or()
        if not self.at_end():
            raise FilterError(f"Лишний фрагмент фильтра: '{self.peek()}'")
        return node

    def parse_or(self) -> Predicate:
        node = self.parse_and()
        while self.peek() in ("or", "||"):
            self.take()
            right = self.parse_and()
            node = _or(node, right)
        return node

    def parse_and(self) -> Predicate:
        node = self.parse_unary()
        while self.peek() in ("and", "&&"):
            self.take()
            right = self.parse_unary()
            node = _and(node, right)
        return node

    def parse_unary(self) -> Predicate:
        if self.peek() == "not":
            self.take()
            inner = self.parse_unary()
            return _not(inner)
        return self.parse_factor()

    def parse_factor(self) -> Predicate:
        token = self.peek()
        if token == "(":
            self.take()
            node = self.parse_or()
            self.take(")")
            return node
        if token is None:
            raise FilterError("Пустое выражение")

        field = self.take().lower()
        op = self.peek()
        if op == "in":
            self.take()
            values, ranges = self.parse_in_values()
            return _set_comparison(field, values, ranges)
        if op in ("contains", "matches"):
            self.take()
            value = self.take()
            return _string_comparison(field, op, value)
        if op in ("==", "!=", "<=", ">=", "<", ">"):
            self.take()
            values = self.parse_values()
            return _comparison(field, op, values)

        # Просто имя поля означает «поле заполнено»: http.host or dns.qry.name.
        if field in STRING_FIELDS:
            return _exists(field)

        # Одиночное имя протокола: "http", "tcp", "not dns"
        if field in PROTOCOL_NAMES:
            return _protocol(field)
        raise FilterError(
            f"Неподдерживаемый фильтр: '{field}'. Поддерживаются поля ip.addr, ip.src, "
            "ip.dst, tcp.port, udp.port, eth.addr, frame.len, ip.ttl, ip.len, "
            "tcp.len, tcp.window_size, tcp.flags.*, udp.length, icmp.type, "
            "http.host, dns.qry.name, tls.sni, «tcp contains …» "
            "и имена протоколов."
        )

    def parse_values(self) -> list[str]:
        values = [self.take()]
        while self.peek() == ",":
            self.take()
            values.append(self.take())
        return values

    def parse_in_values(self) -> tuple[list[str], list[tuple[str, str]]]:
        """Разбирает набор: {80, 443, 1000..2000}."""
        values: list[str] = []
        ranges: list[tuple[str, str]] = []
        self.take("{")
        while True:
            token = self.peek()
            if token is None:
                raise FilterError("Не закрыта фигурная скобка в фильтре")
            if token == "}":
                self.take()
                break
            if token == ",":
                self.take()
                continue
            first = self.take()
            if ".." in first:
                # Токенизатор может отдать «79..81» одним куском.
                start, end = first.split("..", 1)
                ranges.append((start, end))
                continue
            if self.peek() == "..":
                self.take()
                ranges.append((first, self.take()))
            else:
                values.append(first)
        return values, ranges


# ---------------------------------------------------------------------------
# Построение предикатов
# ---------------------------------------------------------------------------
def _and(left: Predicate, right: Predicate) -> Predicate:
    return lambda packet: left(packet) and right(packet)


def _or(left: Predicate, right: Predicate) -> Predicate:
    return lambda packet: left(packet) or right(packet)


def _not(inner: Predicate) -> Predicate:
    return lambda packet: not inner(packet)


def _protocol(name: str) -> Predicate:
    alias = PROTOCOL_ALIASES.get(name, name)

    def predicate(packet: Packet) -> bool:
        if alias in ("ip", "ipv4"):
            return bool(packet.src_ip) and ":" not in packet.src_ip
        if alias == "ipv6":
            return ":" in packet.src_ip
        # Транспорт (tcp/udp/icmp/arp) или прикладной протокол (http/tls/quic...).
        return (
            packet.app.lower() == alias
            or packet.transport.lower() == alias
        )

    return predicate


def _set_comparison(field: str, values: list[str], ranges: list[tuple[str, str]]) -> Predicate:
    """Набор значений: tcp.port in {80, 443, 1000..2000}, frame.len in {64..128}."""
    if field in NUMERIC_FIELDS:
        return _numeric_set(field, values, ranges)

    if field not in PORT_FIELDS:
        raise FilterError(
            f"Набор значений поддерживается для портов и числовых полей: '{field}'"
        )

    try:
        wanted = {int(value) for value in values}
        bounds = [(int(start), int(end)) for start, end in ranges]
    except ValueError as exc:
        raise FilterError("В наборе портов должны быть числа") from exc

    transport = ""
    if field.startswith("tcp"):
        transport = "TCP"
    elif field.startswith("udp"):
        transport = "UDP"

    side = ""
    if field.endswith("srcport"):
        side = "src"
    elif field.endswith("dstport"):
        side = "dst"

    def predicate(packet: Packet) -> bool:
        if transport and packet.transport != transport:
            return False
        if not packet.has_ports():
            return False

        ports = []
        if side in ("", "src") and packet.src_port:
            ports.append(packet.src_port)
        if side in ("", "dst") and packet.dst_port:
            ports.append(packet.dst_port)

        for port in ports:
            if port in wanted:
                return True
            for start, end in bounds:
                if start <= port <= end:
                    return True
        return False

    return predicate


def _numeric_value(field: str, packet: Packet) -> int | None:
    """Значение числового поля или None, если для этого пакета оно неприменимо."""
    value = NUMERIC_FIELDS[field](packet)
    prefix = field.split(".")[0]
    if prefix in ("ip", "ipv6") and not value:
        return None
    if prefix == "tcp" and packet.transport != "TCP":
        return None
    if prefix == "udp" and packet.transport != "UDP":
        return None
    if prefix == "icmp" and packet.transport != "ICMP":
        return None
    return value


def _numeric_comparison(field: str, op: str, values: list[str]) -> Predicate:
    compare = PORT_OPS.get(op)
    if compare is None:
        raise FilterError(f"Неизвестное сравнение для числа: '{op}'")

    try:
        wanted = [int(value) for value in values]
    except ValueError as exc:
        raise FilterError(
            f"Для поля '{field}' нужно число, получено {values}"
        ) from exc

    def predicate(packet: Packet) -> bool:
        value = _numeric_value(field, packet)
        if value is None:
            return False
        return any(compare(value, number) for number in wanted)

    return predicate


def _numeric_set(field: str, values: list[str], ranges: list[tuple[str, str]]) -> Predicate:
    try:
        wanted = {int(value) for value in values}
        bounds = [(int(start), int(end)) for start, end in ranges]
    except ValueError as exc:
        raise FilterError(f"В наборе чисел должны быть числа: '{field}'") from exc

    def predicate(packet: Packet) -> bool:
        value = _numeric_value(field, packet)
        if value is None:
            return False
        if value in wanted:
            return True
        return any(start <= value <= end for start, end in bounds)

    return predicate


def _flag_comparison(field: str, op: str, values: list[str]) -> Predicate:
    bit = FLAG_FIELDS[field]
    if op not in ("==", "!="):
        raise FilterError("Для флагов TCP поддерживаются только == и !=")
    try:
        wanted = {int(value) for value in values}
    except ValueError as exc:
        raise FilterError("Флаг TCP сравнивается с 0 или 1") from exc

    def predicate(packet: Packet) -> bool:
        if packet.transport != "TCP":
            return False
        actual = 1 if packet.tcp_flags & bit else 0
        matched = actual in wanted
        return matched if op == "==" else not matched

    return predicate


def _exists(field: str) -> Predicate:
    """Поле непустое — как одиночное имя поля в Wireshark."""
    getter = STRING_FIELDS[field]
    return lambda packet: bool(getter(packet))


def _string_comparison(field: str, op: str, value: str) -> Predicate:
    """contains / matches для имён и данных пакета."""
    needle = value.strip().strip('"').strip("'")

    if field in PAYLOAD_FIELDS:
        transport = ""
        if field == "tcp":
            transport = "TCP"
        elif field == "udp":
            transport = "UDP"
        raw = needle.encode("utf-8", "ignore").lower()

        if op == "contains":
            def payload_predicate(packet: Packet) -> bool:
                if transport and packet.transport != transport:
                    return False
                return raw in packet.payload.lower()
        else:
            try:
                pattern = re.compile(needle.encode("utf-8", "ignore"), re.IGNORECASE)
            except re.error as exc:
                raise FilterError(f"Ошибка в регулярном выражении: {exc}") from exc

            def payload_predicate(packet: Packet) -> bool:
                if transport and packet.transport != transport:
                    return False
                return bool(pattern.search(packet.payload))

        return payload_predicate

    if field not in STRING_FIELDS:
        raise FilterError(
            f"Поле '{field}' не поддерживает contains/matches. Попробуйте http.host, "
            "dns.qry.name, tls.sni, tcp contains …"
        )

    getter = STRING_FIELDS[field]
    lowered = needle.lower()

    if op == "contains":
        def string_predicate(packet: Packet) -> bool:
            return lowered in getter(packet).lower()
    else:
        try:
            pattern = re.compile(needle, re.IGNORECASE)
        except re.error as exc:
            raise FilterError(f"Ошибка в регулярном выражении: {exc}") from exc

        def string_predicate(packet: Packet) -> bool:
            return bool(pattern.search(getter(packet)))

    return string_predicate


def _comparison(field: str, op: str, values: list[str]) -> Predicate:
    if field in IP_FIELDS:
        return _ip_comparison(field, op, values)
    if field in PORT_FIELDS:
        return _port_comparison(field, op, values)
    if field in MAC_FIELDS:
        return _mac_comparison(field, op, values)
    if field in NUMERIC_FIELDS:
        return _numeric_comparison(field, op, values)
    if field in FLAG_FIELDS:
        return _flag_comparison(field, op, values)
    if field in STRING_FIELDS:
        wanted = {value.strip().strip('"').lower() for value in values}
        getter = STRING_FIELDS[field]
        if op == "==":
            return lambda packet: getter(packet).lower() in wanted
        if op == "!=":
            return lambda packet: getter(packet).lower() not in wanted
        raise FilterError("Для строковых полей поддерживаются ==, !=, contains, matches")
    raise FilterError(f"Неизвестное поле фильтра: '{field}'")


def _ip_comparison(field: str, op: str, values: list[str]) -> Predicate:
    wanted = {value.strip().lower() for value in values}
    if op not in ("==", "!="):
        raise FilterError("Для IP-полей поддерживаются только == и !=")

    family = ""
    if field.startswith("ipv6"):
        family = "v6"
    elif field.startswith("ip"):
        family = "any"

    def predicate(packet: Packet) -> bool:
        if field.endswith(".src"):
            candidates = [packet.src_ip]
        elif field.endswith(".dst"):
            candidates = [packet.dst_ip]
        else:
            candidates = [packet.src_ip, packet.dst_ip]

        candidates = [address for address in candidates if address]
        if family == "v6":
            candidates = [address for address in candidates if ":" in address]
        elif family == "any":
            candidates = [address for address in candidates if ":" not in address]

        matched = any(address.lower() in wanted for address in candidates)
        return matched if op == "==" else not matched

    return predicate


def _port_comparison(field: str, op: str, values: list[str]) -> Predicate:
    compare = PORT_OPS.get(op)
    if compare is None:
        raise FilterError(f"Неизвестное сравнение для порта: '{op}'")

    try:
        wanted = [int(value) for value in values]
    except ValueError as exc:
        raise FilterError(f"Порт должен быть числом: {values}") from exc

    transport = ""
    if field.startswith("tcp"):
        transport = "TCP"
    elif field.startswith("udp"):
        transport = "UDP"

    side = ""
    if field.endswith("srcport"):
        side = "src"
    elif field.endswith("dstport"):
        side = "dst"

    def predicate(packet: Packet) -> bool:
        if transport and packet.transport != transport:
            return False
        if not packet.has_ports():
            return False

        ports = []
        if side in ("", "src") and packet.src_port:
            ports.append(packet.src_port)
        if side in ("", "dst") and packet.dst_port:
            ports.append(packet.dst_port)
        if not ports:
            return False

        if op == "==":
            return any(port in wanted for port in ports)
        if op == "!=":
            return all(port not in wanted for port in ports)
        return any(compare(port, value) for port in ports for value in wanted)

    return predicate


def _mac_comparison(field: str, op: str, values: list[str]) -> Predicate:
    wanted = {normalize_mac(value) for value in values}
    if op not in ("==", "!="):
        raise FilterError("Для MAC-адресов поддерживаются только == и !=")

    def predicate(packet: Packet) -> bool:
        if field == "eth.src":
            matched = packet.src_mac.lower() in wanted
        elif field == "eth.dst":
            matched = packet.dst_mac.lower() in wanted
        else:
            matched = packet.src_mac.lower() in wanted or packet.dst_mac.lower() in wanted
        return matched if op == "==" else not matched

    return predicate


# ---------------------------------------------------------------------------
# Публичный интерфейс
# ---------------------------------------------------------------------------
def compile_filter(filter_string: str) -> Predicate:
    """
    Компилирует display-фильтр в предикат.

    Пустая строка означает "показать все пакеты".

    Raises:
        FilterError: если фильтр не разобран.
    """
    text = (filter_string or "").strip()
    if not text:
        return lambda packet: True

    parser = _Parser(_tokenize(text))
    return parser.parse()


def is_valid_filter(filter_string: str) -> bool:
    """Проверяет фильтр без выброса исключений."""
    try:
        compile_filter(filter_string)
        return True
    except FilterError:
        return False
