"""
График трафика во времени.

Простой Canvas-виджет без внешних библиотек: площадь по байтам (или
столбики по пакетам), сетка, подписи и подсказка при наведении.
Виджет ничего не знает про пакеты — на вход идут готовые бакеты из
`parser.stats.timeline`.
"""

import tkinter as tk

# Поля вокруг области графика.
MARGIN_LEFT = 56
MARGIN_RIGHT = 12
MARGIN_TOP = 12
MARGIN_BOTTOM = 22

MIN_HEIGHT = 110


class TrafficChart(tk.Canvas):
    """График интенсивности трафика: байты площадью, пакеты столбиками."""

    def __init__(self, master, **kwargs) -> None:
        kwargs.setdefault("height", 150)
        kwargs.setdefault("highlightthickness", 0)
        kwargs.setdefault("bd", 0)
        super().__init__(master, **kwargs)

        self.buckets: list = []
        self.metric = "bytes"
        self._theme: dict = {}
        self._hover_index: int | None = None

        self.bind("<Configure>", lambda event: self.redraw())
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", self._on_leave)

    # ------------------------------------------------------------------
    # Данные
    # ------------------------------------------------------------------
    def set_data(self, buckets, metric: str = "bytes", theme: dict | None = None) -> None:
        self.buckets = list(buckets or [])
        self.metric = "packets" if metric == "packets" else "bytes"
        if theme is not None:
            self._theme = dict(theme)
        self._hover_index = None
        self.redraw()

    def set_theme(self, theme: dict) -> None:
        self._theme = dict(theme)
        self.redraw()

    # ------------------------------------------------------------------
    # Отрисовка
    # ------------------------------------------------------------------
    def _value(self, bucket) -> int:
        return bucket.packets if self.metric == "packets" else bucket.bytes

    def _format_value(self, value: int) -> str:
        if self.metric == "packets":
            return "{} пак.".format(value)
        from parser.stats import format_bytes
        return format_bytes(value)

    def redraw(self) -> None:
        self.delete("all")

        width = max(self.winfo_width(), 120)
        height = max(self.winfo_height(), MIN_HEIGHT)
        left, right = MARGIN_LEFT, width - MARGIN_RIGHT
        top, bottom = MARGIN_TOP, height - MARGIN_BOTTOM

        panel = self._theme.get("panel", "#1c1f26")
        border = self._theme.get("border", "#2c313c")
        muted = self._theme.get("muted", "#8b93a1")
        accent = self._theme.get("accent", "#4f8cff")
        text = self._theme.get("text", "#e6e9ef")

        self.configure(bg=panel, height=height)
        self.create_rectangle(left, top, right, bottom, outline=border)

        if not self.buckets:
            self.create_text(
                (left + right) / 2, (top + bottom) / 2,
                text="График появится после загрузки файла",
                fill=muted, font=("Segoe UI", 10),
            )
            return

        values = [self._value(bucket) for bucket in self.buckets]
        peak = max(values) or 1
        count = len(values)

        # Сетка и подписи по вертикали: 0, половина, максимум.
        for share in (0.0, 0.5, 1.0):
            y = bottom - (bottom - top) * share
            self.create_line(left, y, right, y, fill=border, dash=(2, 4))
            self.create_text(
                left - 8, y,
                text=self._format_value(int(peak * share)),
                fill=muted, anchor="e", font=("Segoe UI", 8),
            )

        if count == 1:
            step = (right - left)
            points_x = [(left + right) / 2]
        else:
            step = (right - left) / (count - 1)
            points_x = [left + index * step for index in range(count)]

        points_y = [bottom - (bottom - top) * (value / peak) for value in values]

        if self.metric == "packets" and count > 1:
            bar_width = max(2.0, step * 0.6)
            for x, y, value in zip(points_x, points_y, values):
                if value <= 0:
                    continue
                self.create_rectangle(
                    x - bar_width / 2, y, x + bar_width / 2, bottom,
                    fill=accent, outline="",
                )
        else:
            polygon = [left, bottom]
            for x, y in zip(points_x, points_y):
                polygon.extend((x, y))
            polygon.extend((points_x[-1], bottom))
            self.create_polygon(
                polygon, fill=accent, outline="", stipple="gray50",
            )
            self.create_line(
                list(zip(points_x, points_y)), fill=accent, width=2, smooth=True,
            )

        # Подписи времени: начало, середина, конец.
        first = self.buckets[0].start
        last = self.buckets[-1].start
        middle = (first + last) / 2
        for position, label in (
            (left, self._format_time(first)),
            ((left + right) / 2, self._format_time(middle)),
            (right, self._format_time(last)),
        ):
            self.create_text(
                position, bottom + 10, text=label,
                fill=muted, font=("Segoe UI", 8),
                anchor="w" if position == left else ("e" if position == right else "center"),
            )

        self.create_text(
            left + 4, top + 2,
            text="{} за интервал".format(self._format_value(peak)),
            fill=text, anchor="nw", font=("Segoe UI", 9),
        )

        if self._hover_index is not None and self._hover_index < count:
            self._draw_hover(points_x, points_y, text)

    def _draw_hover(self, points_x, points_y, text_color) -> None:
        index = self._hover_index
        bucket = self.buckets[index]
        x = points_x[index]
        y = points_y[index]

        width = max(self.winfo_width(), 120)
        height = max(self.winfo_height(), MIN_HEIGHT)
        self.create_line(x, MARGIN_TOP, x, height - MARGIN_BOTTOM,
                         fill=self._theme.get("muted", "#8b93a1"), dash=(3, 3))
        self.create_oval(x - 3, y - 3, x + 3, y + 3,
                         fill=self._theme.get("accent", "#4f8cff"), outline="")

        label = "{} · {}".format(
            self._format_time(bucket.start),
            "{} пакетов · {}".format(bucket.packets, self._format_bytes(bucket.bytes)),
        )
        anchor_x = x + 12
        anchor = "nw"
        if anchor_x + 190 > width:
            anchor_x = x - 12
            anchor = "ne"
        self.create_text(
            anchor_x, MARGIN_TOP + 4, text=label, fill=text_color,
            anchor=anchor, font=("Segoe UI", 9),
        )

    @staticmethod
    def _format_bytes(value: int) -> str:
        from parser.stats import format_bytes
        return format_bytes(value)

    @staticmethod
    def _format_time(seconds: float) -> str:
        if seconds < 60:
            return "{:.1f} с".format(seconds)
        minutes, rest = divmod(seconds, 60)
        if minutes < 60:
            return "{:.0f}:{:02.0f}".format(minutes, rest)
        hours, minutes = divmod(minutes, 60)
        return "{:.0f}:{:02.0f}:{:02.0f}".format(hours, minutes, rest)

    # ------------------------------------------------------------------
    # Наведение
    # ------------------------------------------------------------------
    def _index_at(self, x: int) -> int | None:
        if not self.buckets:
            return None
        width = max(self.winfo_width(), 120)
        left, right = MARGIN_LEFT, width - MARGIN_RIGHT
        if x < left or x > right:
            return None
        if len(self.buckets) == 1:
            return 0
        share = (x - left) / max(right - left, 1)
        index = int(round(share * (len(self.buckets) - 1)))
        return max(0, min(index, len(self.buckets) - 1))

    def _on_motion(self, event) -> None:
        index = self._index_at(event.x)
        if index != self._hover_index:
            self._hover_index = index
            self.redraw()

    def _on_leave(self, event) -> None:
        if self._hover_index is not None:
            self._hover_index = None
            self.redraw()
