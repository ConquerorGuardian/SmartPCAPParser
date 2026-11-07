"""
Таблица пакетов: строки, поиск, сортировка, контекстное меню и экспорт CSV.

Всё, что наполняет ttk.Treeview или читает из него, живёт здесь. Методы
вызываются у экземпляра SmartPcapApp: self._render(result), self._fill_table()
и так далее.

THEME и PROTOCOL_TINTS читаются через theme_module: оттенки строк зависят от
текущей темы, а импорт по значению заморозил бы палитру.
"""

import re
import tkinter as tk
from tkinter import filedialog, messagebox

from gui import theme as theme_module
from gui.theme import APP_TITLE, COLUMN_ANCHORS, SORT_KEYS
from gui.utils import MAX_ROWS, PAGE_SIZE, VIEW_LIMIT, format_count
from parser.node_card import looks_like_ip
from parser.pcap_handler import COLUMNS, PcapResult


class TableMixin:
    """Отрисовка строк, поиск, сортировка, экспорт и выделение кадра."""

    def _scroll_sideways(self, event) -> None:
        """Shift+колесо мыши: горизонтальная прокрутка длинного Info."""
        self.tree.xview_scroll(-1 if event.delta > 0 else 1, "units")

    def _show_all(self) -> None:
        """Показать все совпадения: маленькие файлы — целиком, большие — страницами."""
        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        filter_string = self.current_filter
        result = self.handler.apply(self.packets, filter_string, limit=-1)
        if result.error:
            self._set_status(f"Ошибка фильтра: {result.error}")
            return

        self._render(result)
        if len(self._rows) > VIEW_LIMIT:
            self._set_status(
                f"Найдено {format_count(len(self._rows))} совпадений — показываю "
                f"страницами по {format_count(PAGE_SIZE)}. Листайте кнопками под таблицей "
                "или используйте поиск и фильтр."
            )
        elif filter_string:
            self._set_status(
                f"Показаны все совпадения: {result.matched_packets} из {result.total_packets} пакетов. Фильтр: {filter_string}."
            )
        else:
            self._set_status(f"Показаны все пакеты в файле: {result.total_packets}.")

    def _export_csv(self) -> None:
        if not self.packets:
            self._set_status("Нечего экспортировать: сначала откройте файл.")
            return

        # Экспортируем весь результат фильтра (не только первые 5 000 строк
        # превью), и если включён поиск — только совпавшие строки. Иначе
        # «нашёл 12 строк» и «в файле 200» — неприятный сюрприз.
        result = self.handler.apply(self.packets, self.current_filter, limit=-1)
        if result.error:
            self._set_status(f"Ошибка фильтра: {result.error}")
            return

        rows = result.rows
        if self._search_text:
            needle = self._search_text.lower()
            rows = [row for row in rows if needle in self._row_text(row).lower()]

        if not rows:
            self._set_status("Нет строк для экспорта.")
            return

        default_name = "smartpcap_result.csv"
        if self.pcap_path is not None:
            default_name = f"{self.pcap_path.stem}_result.csv"

        path = filedialog.asksaveasfilename(
            title="Сохранить результат",
            defaultextension=".csv",
            initialfile=default_name,
            initialdir=self._last_dir or None,
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            self.handler.export_rows_to_csv(rows, path)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Не удалось сохранить файл:\n\n{exc}")
            return

        if self._search_text:
            self._set_status(
                f"Сохранено {format_count(len(rows))} строк (поиск «{self._search_text}»): {path}"
            )
        else:
            self._set_status(
                f"Сохранено {format_count(len(rows))} строк: {path}"
            )

    # ------------------------------------------------------------------
    # Отрисовка и сортировка
    # ------------------------------------------------------------------
    def _render(self, result: PcapResult) -> None:
        self.current_result = result
        self._rows = list(result.rows)
        if len(self._rows) > MAX_ROWS:
            # Миллион строк в Treeview — это минуты и гигабайты. Честно
            # обрезаем и говорим об этом в статусе: остальное доступно фильтром.
            self._rows = self._rows[:MAX_ROWS]
        # Текст строки для поиска считаем один раз: иначе каждая буква
        # в поле поиска пересобирает все колонки всех строк.
        self._row_texts = [self._row_text(row).lower() for row in self._rows]
        self._page = 1
        self._reset_search()
        self._fill_table()

    # ------------------------------------------------------------------
    # Страницы
    # ------------------------------------------------------------------
    def page_size(self, total: int) -> int:
        """До VIEW_LIMIT — одна страница со всеми строками, иначе PAGE_SIZE."""
        return total if total <= VIEW_LIMIT else PAGE_SIZE

    def page_count(self, total: int) -> int:
        page_size = self.page_size(total)
        if page_size <= 0:
            return 1
        return max(1, -(-total // page_size))

    def _page_bounds(self, total: int) -> tuple[int, int]:
        """(начало, конец) видимого среза строк для текущей страницы."""
        page_size = self.page_size(total)
        pages = self.page_count(total)
        self._page = min(max(1, getattr(self, "_page", 1)), pages)
        start = (self._page - 1) * page_size
        return start, min(total, start + page_size)

    def _go_page(self, delta: int) -> None:
        self._page = getattr(self, "_page", 1) + delta
        self._fill_table()
        text = getattr(self, "_pager_text", "")
        if text:
            self._set_status(text)

    def _page_first(self) -> None:
        self._page = 1
        self._fill_table()

    def _page_last(self) -> None:
        self._page = self.page_count(len(self._sorted_rows()))
        self._fill_table()

    def _update_pager(self, total: int, pages: int, start: int, shown: int) -> None:
        """Подписи и доступность кнопок под таблицей."""
        if getattr(self, "page_label", None) is None:
            return

        if total <= VIEW_LIMIT:
            text = "Все строки: {}".format(format_count(total)) if total else ""
            self.page_label.configure(text=text)
            self.prev_button.configure(state="disabled")
            self.next_button.configure(state="disabled")
            self._pager_text = ""
            return

        first = start + 1 if shown else 0
        last = start + shown
        self._pager_text = (
            "Стр. {} из {} · показаны {}–{} из {} — Ctrl+PgUp/Ctrl+PgDn".format(
                format_count(self._page), format_count(pages),
                format_count(first), format_count(last), format_count(total),
            )
        )
        self.page_label.configure(text=self._pager_text)
        self.prev_button.configure(state="normal" if self._page > 1 else "disabled")
        self.next_button.configure(state="normal" if self._page < pages else "disabled")

    # ------------------------------------------------------------------
    # Поиск по видимым строкам
    # ------------------------------------------------------------------
    ROW_TEXT_FIELDS = ("frame", "time", "protocol", "source", "src_port",
                       "destination", "dst_port", "length", "info")

    def _row_text(self, row) -> str:
        return " ".join(str(getattr(row, field, "")) for field in self.ROW_TEXT_FIELDS)

    def _reset_search(self) -> None:
        """Новый фильтр или новый файл — поиск начинается с чистого листа."""
        self._search_text = ""
        entry = getattr(self, "search_entry", None)
        if entry is not None:
            entry.delete(0, "end")
        label = getattr(self, "search_label", None)
        if label is not None:
            label.configure(text="")

    def _apply_search(self, event=None) -> None:
        if not getattr(self, "search_entry", None):
            return
        text = self.search_entry.get().strip()
        self._search_text = text
        self._page = 1
        self._fill_table()

        shown = getattr(self, "_visible_total", len(self._rows))
        total = len(self._rows)
        if text:
            self.search_label.configure(
                text=f"{shown} из {total}",
                text_color=theme_module.THEME["accent"] if shown else theme_module.THEME["danger"],
            )
            self._set_status(
                f"Поиск «{text}»: {shown} совпадений из {total} строк. Esc — снять поиск."
            )
        else:
            self.search_label.configure(text="")
            self._set_status("Поиск снят: показаны все строки текущего фильтра.")

    def _clear_search(self, event=None) -> None:
        if not getattr(self, "search_entry", None):
            return
        self._reset_search()
        self._fill_table()
        self._set_status("Поиск снят: показаны все строки текущего фильтра.")
        return "break"

    def _focus_search(self, event=None) -> None:
        entry = getattr(self, "search_entry", None)
        if entry is None:
            return
        entry.focus_set()
        entry.select_range(0, "end")
        return "break"

    def _fill_table(self) -> None:
        self.tree.delete(*self.tree.get_children())

        rows = self._sorted_rows()
        total = len(rows)
        self._visible_total = total
        start, end = self._page_bounds(total)

        for index, row in enumerate(rows[start:end], start=start):
            transport = (row.protocol or "").upper()
            tag = transport if transport in theme_module.PROTOCOL_TINTS else "other"
            tags = (f"{tag}_odd" if index % 2 else f"{tag}_even",)
            self.tree.insert("", "end", values=(
                row.frame,
                row.time,
                row.protocol,
                row.source,
                row.src_port,
                row.destination,
                row.dst_port,
                row.length,
                row.info,
            ), tags=tags)

        self._update_pager(total, self.page_count(total), start, end - start)

    def _sorted_rows(self) -> list:
        rows = self._rows
        texts = getattr(self, "_row_texts", None)
        needle = getattr(self, "_search_text", "").lower()
        if needle:
            if texts is None or len(texts) != len(rows):
                texts = [self._row_text(row).lower() for row in rows]
                self._row_texts = texts
            rows = [row for row, text in zip(rows, texts) if needle in text]

        if not self._sort_column:
            return rows

        attribute, kind = SORT_KEYS[self._sort_column]

        def sort_key(row):
            value = getattr(row, attribute, "")
            if kind == "int":
                text = str(value).strip()
                return int(text) if text.isdigit() else -1
            if kind == "float":
                try:
                    return float(value)
                except (TypeError, ValueError):
                    return 0.0
            return str(value).lower()

        return sorted(rows, key=sort_key, reverse=self._sort_reverse)

    def _on_heading_click(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False

        self._page = 1
        self._update_headings()
        self._fill_table()

    def _update_headings(self) -> None:
        for name in COLUMNS:
            anchor = COLUMN_ANCHORS.get(name, "w")
            text = name
            if name == self._sort_column:
                text = "{} {}".format(name, "▼" if self._sort_reverse else "▲")
            self.tree.heading(name, text=text, anchor=anchor)

    def _set_filter_text(self, text: str) -> None:
        self.filter_entry.configure(state="normal")
        self.filter_entry.delete(0, "end")
        if text:
            self.filter_entry.insert(0, text)
        self.filter_entry.configure(state="readonly")

    def _copy_filter(self) -> None:
        if not self.current_filter:
            self._set_status("Фильтр пока пуст: выполните команду.")
            return

        self.clipboard_clear()
        self.clipboard_append(self.current_filter)
        self._set_status(f"Фильтр скопирован в буфер обмена: {self.current_filter}")

    def _copy_selected_row(self, event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        text = "\t".join(str(value) for value in values)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Строка скопирована в буфер обмена.")

    def _selected_frame(self) -> int | None:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        if not values:
            return None
        try:
            return int(values[0])
        except (TypeError, ValueError):
            return None

    def _show_context_menu(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        self.tree.focus(row)

        menu = self._context_menu
        menu.delete(0, "end")
        menu.add_command(
            label="Детали пакета (двойной клик)", command=self._show_packet_details
        )
        menu.add_command(
            label="Поток TCP (Ctrl+T)", command=self._follow_selected_stream
        )
        try:
            frame = int(self.tree.item(row, "values")[0])
        except (IndexError, TypeError, ValueError):
            frame = None
        if frame is not None and self.pcap_path:
            menu.add_command(
                label=f"Открыть в Wireshark (пакет {frame})",
                command=lambda value=frame: self._open_in_wireshark(value),
            )

        values = self.tree.item(row, "values")
        if values:
            node_menu = tk.Menu(menu, tearoff=0)
            for candidate in dict.fromkeys((values[3], values[5])):
                candidate = str(candidate)
                if candidate and candidate != "?" and looks_like_ip(candidate):
                    node_menu.add_command(
                        label=candidate,
                        command=lambda value=candidate: self._show_node_card(value),
                    )
            if node_menu.index("end") is not None:
                menu.add_cascade(label="Карточка узла", menu=node_menu)

            source, src_port, destination, dst_port = (
                values[3], values[4], values[5], values[6]
            )
            protocol = values[2]

            menu.add_separator()
            if source and source != "?":
                menu.add_command(
                    label=f"Только от {source}",
                    command=lambda value=source: self._filter_by("src", value),
                )
            if destination and destination != "?":
                menu.add_command(
                    label=f"Только к {destination}",
                    command=lambda value=destination: self._filter_by("dst", value),
                )
            if source and source != "?" and source != destination:
                menu.add_command(
                    label=f"Фильтр по адресу {source}",
                    command=lambda value=source: self._filter_by("addr", value),
                )
            ports = [port for port in (src_port, dst_port) if port]
            for port in dict.fromkeys(ports):
                menu.add_command(
                    label=f"Только порт {port}",
                    command=lambda value=port: self._filter_by("port", value),
                )
            if protocol:
                menu.add_command(
                    label=f"Только {protocol}",
                    command=lambda value=protocol: self._filter_by("proto", value),
                )

        menu.add_separator()
        menu.add_command(
            label="Копировать строку (Ctrl+C)", command=self._copy_selected_row
        )

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _filter_by(self, kind: str, value: str) -> None:
        """Готовит команду из значения ячейки — без набора текста руками."""
        value = str(value).strip()
        if not value:
            return

        mac_like = bool(
            re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", value)
            or re.fullmatch(r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}", value)
        )

        if kind == "src":
            command = (
                f"покажи пакеты с мак адресом {value}" if mac_like
                else f"покажи пакеты от {value}"
            )
        elif kind == "dst":
            command = (
                f"покажи пакеты с мак адресом {value}" if mac_like
                else f"покажи пакеты к {value}"
            )
        elif kind == "addr":
            command = (
                f"покажи пакеты с мак адресом {value}" if mac_like
                else f"покажи пакеты с айпи {value}"
            )
        elif kind == "port":
            command = f"покажи пакеты на порт {value}"
        elif kind == "proto":
            command = f"покажи {value.lower()} трафик"
        else:
            return

        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, command)
        self._update_command_hint()
        self._apply_command()
