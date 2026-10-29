"""
Вкладка «Статистика»: расчёт области и заполнение деревьев.

Данные берутся из parser.stats, а деревья создаёт LayoutMixin._build_stats.
THEME читается через theme_module: график перекрашивается под текущую тему.
"""

from gui import theme as theme_module
from parser.matcher import FilterError, compile_filter
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
