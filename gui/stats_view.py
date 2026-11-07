"""
Вкладка «Статистика»: расчёт области и заполнение деревьев.

Данные берутся из parser.stats, а деревья создаёт LayoutMixin._build_stats.
THEME читается через theme_module: график перекрашивается под текущую тему.

Правая кнопка по строке сайта, разговора или узла применяет к таблице готовый
фильтр: из «Сайтов и хостов» удобно вернуться к конкретным пакетам.
"""

import ipaddress
import tkinter as tk

from gui import theme as theme_module
from parser.matcher import FilterError, compile_filter
from parser.node_card import looks_like_ip
from parser.stats import (
    conversations,
    endpoints,
    format_bytes,
    format_duration,
    hosts,
    protocol_hierarchy,
    summary,
    timeline,
)

SITE_FILTER = (
    '(http.host contains "{0}" or tls.handshake.extensions_server_name '
    'contains "{0}" or dns.qry.name contains "{0}")'
)


def site_filter(name: str) -> str:
    """Фильтр по имени сайта: HTTP Host, TLS SNI или DNS-запрос."""
    name = name.strip()
    if not name:
        return ""
    return SITE_FILTER.format(name)


def node_filter(address: str) -> str:
    """Фильтр по узлу: IP-адрес или MAC, пустая строка для остального."""
    address = address.strip()
    if not address or address == "?":
        return ""
    try:
        ipaddress.ip_address(address)
    except ValueError:
        if address.count(":") == 5:
            return "eth.addr=={}".format(address.lower())
        return ""
    return "ip.addr=={}".format(address)


def conversation_filter(label: str) -> str:
    """Фильтр по паре узлов из строки разговора."""
    parts = [part.strip() for part in label.split("\u2194")]
    if len(parts) != 2:
        return ""
    first, second = (_address(part) for part in parts)
    if not first or not second:
        return ""
    return "(ip.addr=={} and ip.addr=={})".format(first, second)


def _address(label: str) -> str:
    """Убирает порт: «10.0.0.1:443» становится «10.0.0.1», IPv6 не трогаем."""
    label = label.strip()
    if label.count(":") == 1:
        head, tail = label.rsplit(":", 1)
        if tail.isdigit():
            return head
    return label


class StatsMixin:
    """График, иерархия протоколов, сайты, разговоры и узлы."""

    # ------------------------------------------------------------------
    # Статистика: расчёт и отрисовка
    # ------------------------------------------------------------------
    def _stats_scope_packets(self) -> list:
        if not self.packets:
            return []
        if self.stats_scope.get() == "Найденные" and self.current_filter:
            try:
                predicate = compile_filter(self.current_filter)
            except (FilterError, Exception):        # noqa: B014
                return self.packets
            return [packet for packet in self.packets if predicate(packet)]
        return self.packets

    def _refresh_chart(self) -> None:
        """Перерисовывает график по текущей области статистики."""
        packets = self._stats_scope_packets()
        metric = "packets" if self.chart_metric.get() == "Пакеты" else "bytes"
        self.chart.set_theme(theme_module.THEME)
        self.chart.set_data(timeline(packets), metric, theme_module.THEME)

    def _refresh_stats(self) -> None:
        # Считаем только когда вкладка видна: на файле в сотни тысяч пакетов
        # пересчёт после каждой команды заметно тормозил бы таблицу.
        if getattr(self, "_current_view", "packets") != "stats":
            return

        packets = self._stats_scope_packets()
        self._refresh_chart()

        for tree in (self.proto_tree, self.host_tree, self.conv_tree, self.endpoint_tree):
            tree.delete(*tree.get_children())

        if not packets:
            self.stats_summary_label.configure(
                text="Пока нечего считать: откройте файл или ослабьте фильтр."
            )
            return

        data = summary(packets)
        self.stats_summary_label.configure(text=(
            "Пакетов {} · {} · длительность {} · узлов {} · протоколов {}".format(
                data["packets"],
                format_bytes(data["bytes"]),
                format_duration(data["duration"]),
                data["addresses"],
                data["protocols"],
            )
        ))

        parents: dict[str, str] = {}
        for row in protocol_hierarchy(packets):
            values = (row.packets, format_bytes(row.bytes), f"{row.share:.1f}%")
            if row.level == 0:
                node = self.proto_tree.insert("", "end", text=row.name, values=values)
                if row.name != "Всего":
                    parents[row.name] = node
            else:
                self.proto_tree.insert(
                    parents.get(row.parent, ""), "end", text=row.name, values=values
                )

        for host in hosts(packets, limit=40):
            self.host_tree.insert(
                "",
                "end",
                text=host.name,
                values=(host.packets, format_bytes(host.bytes), host.source),
            )

        for conversation in conversations(packets, limit=40):
            self.conv_tree.insert(
                "",
                "end",
                text=f"{conversation.endpoint_a}  ↔  {conversation.endpoint_b}",
                values=(conversation.total_packets, format_bytes(conversation.total_bytes)),
            )

        for node in endpoints(packets, limit=40):
            self.endpoint_tree.insert(
                "",
                "end",
                text=node.address,
                values=(
                    node.packets_sent,
                    node.packets_received,
                    format_bytes(node.total_bytes),
                ),
            )

    # ------------------------------------------------------------------
    # Правая кнопка по строке: вернуться к пакетам с готовым фильтром
    # ------------------------------------------------------------------
    def _init_stats_menus(self) -> None:
        """Двойной клик и правая кнопка по сайту, разговору или узлу."""
        for tree, kind in (
            (self.host_tree, "host"),
            (self.conv_tree, "conversation"),
            (self.endpoint_tree, "endpoint"),
        ):
            tree.bind(
                "<Button-3>",
                lambda event, tree=tree, kind=kind: self._stats_menu(event, tree, kind),
            )
            tree.bind(
                "<Double-1>",
                lambda event, tree=tree, kind=kind: self._stats_open(event, tree, kind),
            )

    def _stats_menu(self, event, tree, kind: str) -> None:
        row = tree.identify_row(event.y)
        if not row:
            return
        tree.selection_set(row)
        tree.focus(row)
        text = tree.item(row, "text")

        labels = {
            "host": "Показать пакеты этого сайта",
            "conversation": "Показать пакеты этого разговора",
            "endpoint": "Показать пакеты этого узла",
        }
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(
            label=labels[kind], command=lambda: self._stats_open_row(text, kind)
        )
        if kind == "endpoint" and looks_like_ip(text):
            menu.add_command(
                label="Карточка узла",
                command=lambda value=text: self._show_node_card(value),
            )
        menu.add_command(
            label="Скопировать", command=lambda: self._copy_stats_text(text)
        )
        menu.tk_popup(event.x_root, event.y_root)

    def _stats_open(self, event, tree, kind: str) -> None:
        row = tree.identify_row(event.y)
        if row:
            self._stats_open_row(tree.item(row, "text"), kind)

    def _stats_open_row(self, text: str, kind: str) -> None:
        """Строит фильтр по строке статистики и показывает подходящие пакеты."""
        if kind == "host":
            filter_string = site_filter(text)
        elif kind == "conversation":
            filter_string = conversation_filter(text)
        else:
            filter_string = node_filter(text)

        if not filter_string:
            self._set_status(
                "Из этой строки фильтр не собрать. Выберите сайт, разговор или IP-адрес."
            )
            return
        self._show_packets_by_filter(filter_string)

    def _copy_stats_text(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Скопировано: {}".format(text))
