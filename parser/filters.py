"""
Генератор Wireshark display filters.

Принимает ParsedQuery от движка и собирает валидный display filter,
совместимый с Wireshark (и pyshark).

Примеры:
- ip.addr==192.168.1.1
- ip.addr==192.168.1.1 and tcp.port==80
- tcp.srcport==443 or udp.dstport==53
- eth.addr==aa:bb:cc:dd:ee:ff
- http or dns or icmp
"""

from typing import Optional

from .engine import ExtractedEntity, ParsedQuery


class FilterGenerator:
    """Генерирует Wireshark display filters из ParsedQuery."""

    # Маппинг типов сущностей -> базовый фильтр Wireshark
    ENTITY_TO_FILTER = {
        "ip": "ip.addr",
        "port": "tcp.port",          # дефолт; будет дополнен направлением
        "mac": "eth.addr",
        "protocol": None,            # протоколы добавляются как имена (http, dns...)
    }

    # Направление -> суффикс порта
    PORT_DIRECTION = {
        "src": "tcp.srcport",
        "dst": "tcp.dstport",
    }

    # Дефолтный протокол для портов без указания tcp/udp
    DEFAULT_PORT_PROTOCOL = "tcp"

    # Поля Wireshark, в которых лежит имя сайта.
    HOST_FIELDS = (
        "http.host",
        "tls.handshake.extensions_server_name",
        "dns.qry.name",
    )

    # Протоколы, которые имеют свои имена в display filter
    PROTOCOL_NAMES = {
        "http": "http",
        "http2": "http2",
        "dns": "dns",
        "icmp": "icmp",
        "tcp": "tcp",
        "udp": "udp",
        "tls": "tls",
        "quic": "quic",
        "arp": "arp",
        "ssh": "ssh",
        "ftp": "ftp",
        "smtp": "smtp",
        "ntp": "ntp",
        # Расширенный набор: имена совпадают с полями Wireshark.
        "dhcp": "dhcp",
        "telnet": "telnet",
        "pop3": "pop3",
        "imap": "imap",
        "ldap": "ldap",
        "smb": "smb",
        "rdp": "rdp",
        "mysql": "mysql",
        "mdns": "mdns",
        "ipv6": "ipv6",
        "ipv4": "ip",
        # Там, где имя протокола в Wireshark отличается от нашего.
        "mssql": "tds",
        "postgresql": "pgsql",
        "mongodb": "mongo",
        "redis": "redis",
        "memcached": "memcached",
        "sip": "sip",
        "snmp": "snmp",
        "tftp": "tftp",
        "vnc": "vnc",
        "mqtt": "mqtt",
        "kerberos": "kerberos",
        "syslog": "syslog",
        "stun": "stun",
        "openvpn": "openvpn",
        "socks": "socks",
        "nfs": "nfs",
        # Протоколы без портов и новые прикладные.
        "icmpv6": "icmpv6",
        "igmp": "igmp",
        "gre": "gre",
        "esp": "esp",
        "ah": "ah",
        "ospf": "ospf",
        "llmnr": "llmnr",
        "ssdp": "ssdp",
        "dhcpv6": "dhcpv6",
        "radius": "radius",
        "netbios": "nbns",
        "bgp": "bgp",
        "xmpp": "xmpp",
        "irc": "irc",
        "l2tp": "l2tp",
        "ipsec": "isakmp",
    }

    def generate(self, query: ParsedQuery) -> str:
        """
        Генерирует display filter из ParsedQuery.

        Args:
            query: Результат парсинга команды.

        Returns:
            Строка display filter Wireshark (пустая строка, если нет индикаторов).
        """
        if not query.entities:
            return ""

        parts = []

        # 1. Обработка IP-адресов
        ip_parts = self._generate_ip_filters(query)
        parts.extend(ip_parts)

        # 2. Обработка портов
        port_parts = self._generate_port_filters(query)
        parts.extend(port_parts)

        # 3. Обработка MAC-адресов
        mac_parts = self._generate_mac_filters(query)
        parts.extend(mac_parts)

        # 4. Обработка протоколов
        proto_parts = self._generate_protocol_filters(query)
        parts.extend(proto_parts)

        # 5. Имена: сайты, хосты, домены
        host_parts = self._generate_host_filters(query)
        parts.extend(host_parts)

        # Собираем всё через 'and'
        if not parts:
            return ""
        # Выражения с «или» уже в скобках, остальное склеиваем как есть.
        return " and ".join(parts)

    def _generate_ip_filters(self, query: ParsedQuery) -> list[str]:
        """Генерирует фильтры для IP-адресов (IPv4 и IPv6, с отрицанием)."""
        ip_entities = [e for e in query.entities if e.entity_type == "ip"]
        if not ip_entities:
            return []

        parts: list[str] = []
        plain: dict[bool, list[str]] = {False: [], True: []}
        directional: list[tuple[bool, str]] = []

        for entity in ip_entities:
            expression = self._ip_expression(entity)
            if entity.direction:
                # «от A к B» — оба направления через AND.
                directional.append((entity.negated, expression))
            else:
                plain[entity.negated].append(expression)

        for negated, expression in directional:
            parts.append(self._combine([expression], negated) or "")

        for negated, expressions in plain.items():
            combined = self._combine(expressions, negated)
            if combined:
                parts.append(combined)

        return [part for part in parts if part]

    @staticmethod
    def _ip_expression(entity: ExtractedEntity) -> str:
        family = "ipv6" if ":" in entity.normalized_value else "ip"
        suffix = {"src": ".src", "dst": ".dst"}.get(entity.direction or "", ".addr")
        return "{}{}=={}".format(family, suffix, entity.normalized_value)

    def _generate_host_filters(self, query: ParsedQuery) -> list[str]:
        """Фильтры по именам: HTTP Host, TLS SNI и DNS-запрос одним условием."""
        host_entities = [e for e in query.entities if e.entity_type == "host"]
        if not host_entities:
            return []

        parts: list[str] = []
        plain: dict[bool, list[str]] = {False: [], True: []}
        for entity in host_entities:
            expression = "(" + " or ".join(
                '{} contains "{}"'.format(field, entity.normalized_value)
                for field in self.HOST_FIELDS
            ) + ")"
            plain[entity.negated].append(expression)

        for negated, expressions in plain.items():
            combined = self._combine(expressions, negated)
            if combined:
                parts.append(combined)
        return parts

    def _generate_port_filters(self, query: ParsedQuery) -> list[str]:
        """Генерирует фильтры для портов и диапазонов портов."""
        port_entities = [
            e for e in query.entities
            if e.entity_type in ("port", "port_range")
        ]
        if not port_entities:
            return []

        port_protocol = self._port_protocol(query)
        parts: list[str] = []
        plain: dict[bool, list[ExtractedEntity]] = {False: [], True: []}
        directional: list[tuple[bool, str]] = []

        for entity in port_entities:
            if entity.direction:
                if entity.entity_type == "port_range":
                    expression = self._port_range_expression(entity, port_protocol)
                else:
                    expression = self._port_expression(entity, port_protocol)
                directional.append((entity.negated, expression))
            else:
                plain[entity.negated].append(entity)

        for negated, expression in directional:
            parts.append(self._combine([expression], negated) or "")

        # Обычные порты без отрицания — компактным списком: tcp.port==80,443.
        simple = [
            entity for entity in plain[False]
            if entity.entity_type == "port"
        ]
        ranged = [
            entity for entity in plain[False]
            if entity.entity_type == "port_range"
        ]

        expressions: list[str] = []
        if simple:
            fields = {self._port_field(entity, port_protocol) for entity in simple}
            values = list(dict.fromkeys(entity.normalized_value for entity in simple))
            if len(fields) == 1:
                expressions.append("{}=={}".format(fields.pop(), ",".join(values)))
            else:
                expressions.append(self._combine(
                    [self._port_expression(entity, port_protocol) for entity in simple],
                    False,
                ) or "")

        expressions.extend(
            self._port_range_expression(entity, port_protocol) for entity in ranged
        )
        if expressions:
            parts.append(self._combine(expressions, False) or "")

        if plain[True]:
            negated_expressions = [
                self._port_range_expression(entity, port_protocol)
                if entity.entity_type == "port_range"
                else self._port_expression(entity, port_protocol)
                for entity in plain[True]
            ]
            parts.append(self._combine(negated_expressions, True) or "")

        return [part for part in parts if part]

    def _port_protocol(self, query: ParsedQuery) -> str:
        """udp, если в команде явно указан только udp, иначе tcp."""
        protocols = {
            e.normalized_value for e in query.entities
            if e.entity_type == "protocol"
        }
        if "udp" in protocols and "tcp" not in protocols:
            return "udp"
        return self.DEFAULT_PORT_PROTOCOL

    @staticmethod
    def _port_field(entity: ExtractedEntity, port_protocol: str) -> str:
        suffix = {"src": ".srcport", "dst": ".dstport"}.get(entity.direction or "", ".port")
        return "{}{}".format(port_protocol, suffix)

    def _port_expression(self, entity: ExtractedEntity, port_protocol: str) -> str:
        return "{}=={}".format(
            self._port_field(entity, port_protocol), entity.normalized_value
        )

    def _port_range_expression(self, entity: ExtractedEntity, port_protocol: str) -> str:
        start, end = entity.normalized_value.split("-")
        field = self._port_field(entity, port_protocol)
        # Синтаксис Wireshark: tcp.port in {1000..2000}; он же точен у нас,
        # в отличие от «>= и <=», которое в Wireshark считается по вхождениям.
        return "{} in {{{}..{}}}".format(field, start, end)

    def _generate_mac_filters(self, query: ParsedQuery) -> list[str]:
        """Генерирует фильтры для MAC-адресов."""
        mac_entities = [e for e in query.entities if e.entity_type == "mac"]
        if not mac_entities:
            return []

        parts: list[str] = []
        plain: dict[bool, list[str]] = {False: [], True: []}
        for entity in mac_entities:
            plain[entity.negated].append(
                "eth.addr=={}".format(entity.normalized_value)
            )

        for negated, expressions in plain.items():
            combined = self._combine(expressions, negated)
            if combined:
                parts.append(combined)
        return parts

    def _generate_protocol_filters(self, query: ParsedQuery) -> list[str]:
        """Генерирует фильтры по именам протоколов."""
        proto_entities = [e for e in query.entities if e.entity_type == "protocol"]
        if not proto_entities:
            return []

        has_ports = any(
            e.entity_type in ("port", "port_range") and not e.negated
            for e in query.entities
        )
        # Если адрес уже указан, отдельное «ip»/«ipv6» в фильтре лишнее:
        # ip.addr==10.0.0.5 and ip — это шум.
        has_ip = any(e.entity_type == "ip" for e in query.entities)

        parts: list[str] = []
        plain: dict[bool, list[str]] = {False: [], True: []}
        for entity in proto_entities:
            name = self.PROTOCOL_NAMES.get(entity.normalized_value, entity.normalized_value)
            # tcp/udp уже учтены в фильтре по портам (tcp.port / udp.port),
            # поэтому не дублируем их отдельным условием.
            if has_ports and name in ("tcp", "udp"):
                continue
            if has_ip and name in ("ip", "ipv4", "ipv6"):
                continue
            plain[entity.negated].append(name)

        for negated, names in plain.items():
            combined = self._combine(names, negated)
            if combined:
                parts.append(combined)
        return parts

    @staticmethod
    def _combine(expressions: list[str], negated: bool) -> Optional[str]:
        """Склеивает выражения через «или»; при отрицании — «not (...)»."""
        unique = list(dict.fromkeys(expression for expression in expressions if expression))
        if not unique:
            return None
        joined = " or ".join(unique)
        if negated:
            if len(unique) == 1:
                single = unique[0]
                if single.startswith("(") and single.endswith(")"):
                    single = single[1:-1]
                return "not ({})".format(single)
            return "not ({})".format(joined)
        return joined if len(unique) == 1 else "({})".format(joined)

    @staticmethod
    def validate(filter_string: str) -> bool:
        """
        Грубая проверка валидности filter-строки.

        В полной версии можно интегрировать pyshark для проверки.
        Пока просто проверяем базовую структуру.
        """
        if not filter_string:
            return True
        # Проверяем, что filter не содержит явных ошибок синтаксиса
        forbidden = ["==", "&&", "||", "..."]
        for part in filter_string.split():
            if part.startswith("==") or part.endswith("=="):
                continue
            if part in ("and", "or", "not"):
                continue
        return True


# ---------------------------------------------------------------------------
# Фабрика фильтров (convenience)
# ---------------------------------------------------------------------------
def generate_filter(query: ParsedQuery) -> str:
    """Упрощённая функция для генерации filter."""
    return FilterGenerator().generate(query)
