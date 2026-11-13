"""
Построение интерфейса: боковая панель, рабочая область, таблица, статистика.

Здесь только создание виджетов и их первичная раскладка. Логика (загрузка
файла, команды, настройки) осталась в gui/app.py; методы вызываются у
экземпляра SmartPcapApp и работают с self как обычные методы класса.

THEME и PROTOCOL_TINTS читаются через theme_module: палитра меняется при
переключении темы, а импорт по значению заморозил бы её.
"""

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from gui import theme as theme_module
from gui.chart import TrafficChart
from gui.theme import (
    ALL_QUICK_FILTERS,
    APP_SUBTITLE,
    APP_TITLE,
    COLUMN_ANCHORS,
    COLUMN_WIDTHS,
    EXAMPLE_COMMANDS,
    EXAMPLES_VISIBLE,
    EXTRA_FILTERS,
    QUICK_FILTERS,
    SIDEBAR_WIDTH,
    VERDICT_FINDINGS,
)
from parser.pcap_handler import COLUMNS
from parser.verdict import build_verdict


class LayoutMixin:
    """Виджеты главного окна: сборка интерфейса, а не поведение."""

    # ------------------------------------------------------------------
    # Построение интерфейса
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=0, minsize=SIDEBAR_WIDTH)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()

    # -- боковая панель -------------------------------------------------
    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, fg_color=theme_module.THEME["panel"], corner_radius=0, width=SIDEBAR_WIDTH
        )
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(0, weight=1)

        # Панель прокручивается: на ноутбучных 768 px по высоте иначе
        # обрезались нижние карточки и переключатель темы.
        self.sidebar_scroll = ctk.CTkScrollableFrame(
            sidebar,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=theme_module.THEME["border"],
            scrollbar_button_hover_color=theme_module.THEME["accent_hover"],
        )
        self.sidebar_scroll.grid(row=0, column=0, sticky="nsew")
        self.sidebar_scroll.grid_columnconfigure(0, weight=1)

        content = self.sidebar_scroll

        brand = ctk.CTkFrame(content, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 10))
        ctk.CTkLabel(
            brand,
            text=APP_TITLE,
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=theme_module.THEME["text"],
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand,
            text=APP_SUBTITLE,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=theme_module.THEME["muted"],
            anchor="w",
            wraplength=300,
            justify="left",
        ).pack(anchor="w", pady=(3, 0))

        # Ввод словами — главное действие, поэтому он стоит первым.
        self._build_command_card(content, row=1)
        self._build_file_card(content, row=2)
        self._build_quick_card(content, row=3)
        self._build_examples_card(content, row=4)
        self._build_history_card(content, row=5)

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.grid(row=1, column=0, sticky="ew", padx=18, pady=(6, 14))
        footer.grid_columnconfigure(0, weight=1)

        self.theme_switch = ctk.CTkSwitch(
            footer,
            text="Светлая тема",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=theme_module.THEME["muted"],
            progress_color=theme_module.THEME["accent"],
            button_color=theme_module.THEME["text"],
            button_hover_color=theme_module.THEME["accent_hover"],
            command=self._toggle_theme,
        )
        self.theme_switch.grid(row=0, column=0, sticky="w")
        if self.theme_name == "light":
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()

        # Простой режим: только файл, команда и шесть кнопок.
        self.simple_switch = ctk.CTkSwitch(
            footer,
            text="Простой режим",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=theme_module.THEME["muted"],
            progress_color=theme_module.THEME["accent"],
            button_color=theme_module.THEME["text"],
            button_hover_color=theme_module.THEME["accent_hover"],
            command=self._toggle_simple_mode,
        )
        self.simple_switch.grid(row=1, column=0, sticky="w", pady=(6, 0))
        if getattr(self, "simple_mode", True):
            self.simple_switch.select()
        else:
            self.simple_switch.deselect()

    def _card(self, parent) -> ctk.CTkFrame:
        """Карточка с рамкой — общий вид блоков боковой панели."""
        return ctk.CTkFrame(
            parent,
            fg_color=theme_module.THEME["card"],
            corner_radius=12,
            border_width=1,
            border_color=theme_module.THEME["border"],
        )

    def _card_title(self, card, text: str) -> ctk.CTkLabel:
        label = ctk.CTkLabel(
            card,
            text=text,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        )
        label.pack(anchor="w", padx=14, pady=(12, 2))
        return label

    def _build_file_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "ФАЙЛ")

        self.file_label = ctk.CTkLabel(
            card,
            text="Файл не выбран",
            anchor="w",
            justify="left",
            wraplength=280,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=theme_module.THEME["text"],
        )
        self.file_label.pack(anchor="w", padx=14, pady=(0, 2))

        self.packet_label = ctk.CTkLabel(
            card,
            text="",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=theme_module.THEME["muted"],
        )
        self.packet_label.pack(anchor="w", padx=14, pady=(0, 10))

        ctk.CTkButton(
            card,
            text="Открыть файл   Ctrl+O",
            height=36,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=theme_module.THEME["button"],
            hover_color=theme_module.THEME["button_hover"],
            border_width=1,
            border_color=theme_module.THEME["border"],
            text_color=theme_module.THEME["text"],
            command=self._open_file,
        ).pack(fill="x", padx=14, pady=(0, 6))

        ctk.CTkButton(
            card,
            text="или открыть пример дампа",
            height=26,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent",
            hover_color=theme_module.THEME["button_hover"],
            text_color=theme_module.THEME["accent"],
            command=self._load_sample,
        ).pack(fill="x", padx=14, pady=(0, 12))

        # Недавние файлы: список пуст — виджет прячется, чтобы не занимать место.
        self.recent_menu = ctk.CTkOptionMenu(
            card,
            values=[self._recent_placeholder],
            height=26,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=theme_module.THEME["button"],
            button_color=theme_module.THEME["button_hover"],
            button_hover_color=theme_module.THEME["button_hover"],
            text_color=theme_module.THEME["text"],
            dropdown_fg_color=theme_module.THEME["card"],
            dropdown_text_color=theme_module.THEME["text"],
            dropdown_hover_color=theme_module.THEME["button_hover"],
            command=self._open_recent,
        )
        self.recent_menu.pack(fill="x", padx=14, pady=(0, 12))
        self.recent_menu.pack_forget()

    def _build_command_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.configure(border_color=theme_module.THEME["accent"])
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "СПРОСИТЕ СЛОВАМИ")

        self.command_entry = ctk.CTkEntry(
            card,
            height=46,
            placeholder_text="покажи http трафик с айпи 10.88.0.5",
            font=ctk.CTkFont(family="Segoe UI", size=14),
            fg_color=theme_module.THEME["panel"],
            border_color=theme_module.THEME["border"],
            text_color=theme_module.THEME["text"],
        )
        self.command_entry.pack(fill="x", padx=14, pady=(2, 6))
        self.command_entry.bind("<Return>", self._apply_command)
        self.command_entry.bind("<KeyRelease>", self._on_command_key)
        self.command_entry.bind("<Escape>", self._clear_command)

        # Живая расшифровка: что программа поняла из введённых слов.
        self.hint_label = ctk.CTkLabel(
            card,
            text="Наберите команду — покажу, какой фильтр получится.",
            anchor="w",
            justify="left",
            wraplength=300,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=theme_module.THEME["muted"],
        )
        self.hint_label.pack(fill="x", padx=14, pady=(0, 8))

        ctk.CTkButton(
            card,
            text="Применить   Enter",
            height=40,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=theme_module.THEME["accent"],
            hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["accent_text"],
            command=self._apply_command,
        ).pack(fill="x", padx=14, pady=(0, 14))

    def _build_quick_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "БЫСТРЫЕ ФИЛЬТРЫ")

        # Шесть ходовых протоколов видны всегда: остальные либо в меню
        # «Ещё…» (простой режим), либо на панели (опытный).
        primary = ctk.CTkFrame(card, fg_color="transparent")
        primary.pack(fill="x", padx=10, pady=(4, 0))
        for column in range(3):
            primary.grid_columnconfigure(column, weight=1)

        for index, (label, command) in enumerate(QUICK_FILTERS):
            button = ctk.CTkButton(
                primary,
                text=label,
                height=26,
                width=70,
                font=ctk.CTkFont(family="Segoe UI", size=11),
                fg_color=theme_module.THEME["button"],
                hover_color=theme_module.THEME["button_hover"],
                text_color=theme_module.THEME["text"],
                command=lambda cmd=command: self._run_quick_filter(cmd),
            )
            button.grid(row=index // 3, column=index % 3, padx=3, pady=3, sticky="ew")

        self.more_button = ctk.CTkButton(
            card,
            text="Ещё…",
            height=24,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent",
            hover_color=theme_module.THEME["button_hover"],
            text_color=theme_module.THEME["accent"],
            command=self._show_more_filters,
        )
        self.more_button.pack(fill="x", padx=13, pady=(0, 10))

        self.extra_frame = ctk.CTkFrame(card, fg_color="transparent")
        self.extra_frame.pack(fill="x", padx=10, pady=(0, 12))
        for column in range(3):
            self.extra_frame.grid_columnconfigure(column, weight=1)

        for index, (label, command) in enumerate(ALL_QUICK_FILTERS[len(QUICK_FILTERS):]):
            button = ctk.CTkButton(
                self.extra_frame,
                text=label,
                height=26,
                width=70,
                font=ctk.CTkFont(family="Segoe UI", size=11),
                fg_color=theme_module.THEME["button"],
                hover_color=theme_module.THEME["button_hover"],
                text_color=theme_module.THEME["text"],
                command=lambda cmd=command: self._run_quick_filter(cmd),
            )
            button.grid(row=index // 3, column=index % 3, padx=3, pady=3, sticky="ew")

    def _build_more_menu(self) -> tk.Menu:
        """Меню остальных протоколов; собирается отдельно, чтобы проверять."""
        menu = tk.Menu(self, tearoff=0)
        for label, command in EXTRA_FILTERS:
            menu.add_command(
                label=label, command=lambda cmd=command: self._run_quick_filter(cmd)
            )
        return menu

    def _show_more_filters(self) -> None:
        """Список остальных протоколов: один клик вместо ряда кнопок."""
        menu = self._build_more_menu()
        x = self.more_button.winfo_rootx()
        y = self.more_button.winfo_rooty() + self.more_button.winfo_height()
        try:
            menu.tk_popup(x, y, 0)
        finally:
            menu.grab_release()

    def _apply_simple_mode(self) -> None:
        """Простой режим: минимум кнопок. Опытный: всё на виду."""
        simple = bool(getattr(self, "simple_mode", True))
        if simple:
            self.more_button.pack(fill="x", padx=13, pady=(0, 10))
            self.extra_frame.pack_forget()
            self.examples_card.grid_remove()
        else:
            self.more_button.pack_forget()
            self.extra_frame.pack(fill="x", padx=10, pady=(0, 12))
            self.examples_card.grid()

        self.verdict_button.configure(text="Проверить файл" if simple else "Вердикт")
        if simple and self.verdict_panel.winfo_manager():
            self.verdict_panel.grid_remove()
        elif not simple and getattr(self, "verdict", None) is not None:
            self.verdict_panel.grid()

    def _build_examples_card(self, parent, row: int) -> None:
        """Готовые команды: клик подставляет текст, менять нужно только адрес."""
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self.examples_card = card

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=14, pady=(12, 2))
        ctk.CTkLabel(
            head,
            text="ПРИМЕРЫ",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        ).pack(side="left")
        ctk.CTkButton(
            head,
            text="другие ⟳",
            width=70,
            height=20,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            fg_color="transparent",
            hover_color=theme_module.THEME["button_hover"],
            text_color=theme_module.THEME["accent"],
            command=self._shuffle_examples,
        ).pack(side="right")

        self.examples_frame = ctk.CTkFrame(card, fg_color="transparent")
        self.examples_frame.pack(fill="x", padx=10, pady=(0, 12))
        self.examples_frame.grid_columnconfigure(0, weight=1)
        self._shuffle_examples(first=True)

    def _shuffle_examples(self, first: bool = False) -> None:
        for child in self.examples_frame.winfo_children():
            child.destroy()

        if first:
            self._examples_pool = list(EXAMPLE_COMMANDS)
            self._examples_shown = self._examples_pool[:EXAMPLES_VISIBLE]
            self._examples_offset = EXAMPLES_VISIBLE
        else:
            self._examples_offset += EXAMPLES_VISIBLE
            pool = EXAMPLE_COMMANDS
            start = self._examples_offset % len(pool)
            self._examples_shown = [
                pool[(start + index) % len(pool)]
                for index in range(EXAMPLES_VISIBLE)
            ]

        for index, command in enumerate(self._examples_shown):
            button = ctk.CTkButton(
                self.examples_frame,
                text=command,
                height=26,
                anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                fg_color="transparent",
                hover_color=theme_module.THEME["button_hover"],
                text_color=theme_module.THEME["text"],
                command=lambda cmd=command: self._use_example(cmd),
            )
            button.grid(row=index, column=0, sticky="ew", padx=2, pady=1)

    def _build_history_card(self, parent, row: int) -> None:
        card = self._card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 10))
        self._card_title(card, "ИСТОРИЯ")

        self.history_frame = ctk.CTkScrollableFrame(
            card,
            fg_color="transparent",
            height=150,
            scrollbar_button_color=theme_module.THEME["button"],
            scrollbar_button_hover_color=theme_module.THEME["button_hover"],
        )
        self.history_frame.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        self.history_frame.grid_columnconfigure(0, weight=1)
        self._rebuild_history()

    # -- основная область -----------------------------------------------
    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        self._build_toolbar(main, row=0)
        self._build_tabbar(main, row=1)

        content = ctk.CTkFrame(main, fg_color="transparent")
        content.grid(row=2, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self.content = content

        self.packets_view = ctk.CTkFrame(content, fg_color="transparent")
        self.packets_view.grid(row=0, column=0, sticky="nsew")
        self.packets_view.grid_columnconfigure(0, weight=1)
        self.packets_view.grid_rowconfigure(2, weight=1)

        self.stats_view = ctk.CTkFrame(content, fg_color="transparent")
        self.stats_view.grid(row=0, column=0, sticky="nsew")
        self.stats_view.grid_columnconfigure(0, weight=1)
        self.stats_view.grid_rowconfigure(2, weight=1)
        self.stats_view.grid_remove()

        self._build_verdict(self.packets_view, row=0)
        self._build_search(self.packets_view, row=1)
        self._build_table(self.packets_view, row=2)
        self._build_stats(self.stats_view)
        self._build_status(main, row=3)

    def _secondary_button(self, parent, text: str, command, width: int = 128):
        return ctk.CTkButton(
            parent,
            text=text,
            width=width,
            height=34,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=theme_module.THEME["button"],
            hover_color=theme_module.THEME["button_hover"],
            text_color=theme_module.THEME["text"],
            command=command,
        )

    def _build_toolbar(self, parent, row: int) -> None:
        # Одна панель над таблицей: фильтр и действия в общей рамке.
        bar = ctk.CTkFrame(
            parent,
            fg_color=theme_module.THEME["card"],
            corner_radius=12,
            border_width=1,
            border_color=theme_module.THEME["border"],
        )
        bar.grid(row=row, column=0, sticky="ew", padx=16, pady=(16, 8))
        bar.grid_columnconfigure(0, weight=1)

        self.filter_entry = ctk.CTkEntry(
            bar,
            height=34,
            font=ctk.CTkFont(family="Consolas", size=13),
            state="readonly",
            fg_color=theme_module.THEME["panel"],
            border_color=theme_module.THEME["border"],
            text_color=theme_module.THEME["accent"],
            placeholder_text="здесь появится фильтр Wireshark",
        )
        self.filter_entry.grid(
            row=0, column=0, sticky="ew", padx=(12, 0), pady=(12, 0)
        )

        self._secondary_button(bar, "Копировать", self._copy_filter, width=112).grid(
            row=0, column=1, padx=(8, 0), pady=(12, 0)
        )
        self._secondary_button(bar, "Показать все", self._show_all).grid(
            row=0, column=2, padx=(8, 12), pady=(12, 0)
        )

        # Вторая строка: на узком окне кнопки иначе уезжают за правый край.
        actions = ctk.CTkFrame(bar, fg_color="transparent")
        actions.grid(
            row=1, column=0, columnspan=3, sticky="w", padx=(12, 0), pady=(8, 12)
        )
        buttons = (
            ("Поток TCP", self._follow_selected_stream, 128),
            ("Экспорт CSV", self._export_csv, 128),
            ("В Wireshark", self._open_in_wireshark, 118),
            ("Справка", self._show_help, 92),
            ("Сброс фильтра", self._clear_command, 120),
        )
        for column, (text, command, width) in enumerate(buttons):
            padx = (0, 0) if column == 0 else (8, 0)
            self._secondary_button(actions, text, command, width=width).grid(
                row=0, column=column, padx=padx
            )

    def _build_tabbar(self, parent, row: int) -> None:
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 6))
        bar.grid_columnconfigure(1, weight=1)

        self.view_switch = ctk.CTkSegmentedButton(
            bar,
            values=["Пакеты", "Статистика"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=theme_module.THEME["accent"],
            selected_hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["text"],
            fg_color=theme_module.THEME["button"],
            command=self._switch_view,
        )
        self.view_switch.set("Пакеты")
        self.view_switch.grid(row=0, column=0, sticky="w")

        # Вердикт по файлу: в простом режиме это «Проверить файл»,
        # в опытном панель показывается сама, а кнопка открывает подробности.
        self.verdict_button = self._secondary_button(
            bar, "Проверить файл", self._show_verdict_window, width=148
        )
        self.verdict_button.grid(row=0, column=2, sticky="e")

    # -- вердикт по файлу ------------------------------------------------
    def _build_verdict(self, parent, row: int) -> None:
        panel = ctk.CTkFrame(
            parent,
            fg_color=theme_module.THEME["card"],
            corner_radius=12,
            border_width=1,
            border_color=theme_module.THEME["border"],
        )
        panel.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 8))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_remove()
        self.verdict_panel = panel

        head = ctk.CTkFrame(panel, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 0))
        head.grid_columnconfigure(1, weight=1)

        self.verdict_dot = ctk.CTkLabel(
            head,
            text="●",
            width=12,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=theme_module.THEME["accent"],
        )
        self.verdict_dot.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self.verdict_title = ctk.CTkLabel(
            head,
            text="",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=theme_module.THEME["text"],
        )
        self.verdict_title.grid(row=0, column=1, sticky="w")

        ctk.CTkButton(
            head,
            text="Подробнее",
            width=110,
            height=26,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=theme_module.THEME["button"],
            hover_color=theme_module.THEME["button_hover"],
            text_color=theme_module.THEME["text"],
            command=self._show_verdict_window,
        ).grid(row=0, column=2, sticky="e")

        self.verdict_overview = ctk.CTkLabel(
            panel,
            text="",
            anchor="w",
            justify="left",
            wraplength=980,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=theme_module.THEME["muted"],
        )
        self.verdict_overview.grid(row=1, column=0, sticky="ew", padx=14, pady=(4, 6))

        self.verdict_findings = ctk.CTkFrame(panel, fg_color="transparent")
        self.verdict_findings.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 10))
        self.verdict_findings.grid_columnconfigure(1, weight=1)

    def _render_verdict(self, verdict) -> None:
        """Показывает короткий вывод словами и кнопки «показать»."""
        self.verdict = verdict
        if getattr(self, "simple_mode", True):
            # В простом режиме панель не занимает место: вердикт по кнопке.
            self.verdict_panel.grid_remove()
        else:
            self.verdict_panel.grid()

        colors = {
            "critical": theme_module.THEME["danger"],
            "warning": "#ffb86b",
            "info": theme_module.THEME["accent"],
        }
        self.verdict_dot.configure(
            text_color=colors.get(verdict.worst_severity, theme_module.THEME["accent"])
        )
        self.verdict_title.configure(text=verdict.headline)
        self.verdict_overview.configure(text=verdict.overview)

        for child in self.verdict_findings.winfo_children():
            child.destroy()

        for index, finding in enumerate(verdict.findings[:VERDICT_FINDINGS]):
            row = ctk.CTkFrame(self.verdict_findings, fg_color="transparent")
            row.grid(row=index, column=0, columnspan=2, sticky="ew", pady=1)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(
                row,
                text="•",
                width=14,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=colors.get(finding.severity, theme_module.THEME["muted"]),
            ).grid(row=0, column=0, sticky="nw")

            ctk.CTkLabel(
                row,
                text=f"{finding.title} — {finding.detail}",
                anchor="w",
                justify="left",
                wraplength=880,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=theme_module.THEME["text"],
            ).grid(row=0, column=1, sticky="w")

            if finding.command:
                ctk.CTkButton(
                    row,
                    text="Показать",
                    width=96,
                    height=24,
                    font=ctk.CTkFont(family="Segoe UI", size=11),
                    fg_color=theme_module.THEME["button"],
                    hover_color=theme_module.THEME["button_hover"],
                    text_color=theme_module.THEME["accent"],
                    command=lambda cmd=finding.command: self._run_quick_filter(cmd),
                ).grid(row=0, column=2, sticky="e", padx=(8, 0))

        hidden = len(verdict.findings) - VERDICT_FINDINGS
        if hidden > 0:
            ctk.CTkLabel(
                self.verdict_findings,
                text=f"… и ещё {hidden} — откройте «Подробнее»",
                anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=theme_module.THEME["muted"],
            ).grid(row=VERDICT_FINDINGS, column=0, columnspan=2, sticky="w", pady=(4, 0))

    def _refresh_verdict(self) -> None:
        if not self.packets:
            return
        self._render_verdict(build_verdict(self.packets))

    def _build_search(self, parent, row: int) -> None:
        """Строка поиска по видимым строкам таблицы (Ctrl+F)."""
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=row, column=0, sticky="ew", padx=16, pady=(0, 6))
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            bar,
            text="ПОИСК",
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            text_color=theme_module.THEME["muted"],
        ).grid(row=0, column=0, padx=(2, 8))

        self.search_entry = ctk.CTkEntry(
            bar,
            height=30,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=theme_module.THEME["panel"],
            border_color=theme_module.THEME["border"],
            text_color=theme_module.THEME["text"],
            placeholder_text="Ctrl+F: адрес, порт, протокол или текст из колонки Info",
        )
        self.search_entry.grid(row=0, column=1, sticky="ew")
        self.search_entry.bind("<KeyRelease>", self._apply_search)
        self.search_entry.bind("<Return>", self._apply_search)
        self.search_entry.bind("<Escape>", self._clear_search)

        self.search_label = ctk.CTkLabel(
            bar,
            text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=theme_module.THEME["muted"],
            width=90,
        )
        self.search_label.grid(row=0, column=2, padx=(8, 0))

        self._secondary_button(bar, "Сбросить", self._clear_search, width=96).grid(
            row=0, column=3, padx=(8, 0)
        )

    def _build_table(self, parent, row: int = 0) -> None:
        container = ctk.CTkFrame(
            parent,
            fg_color=theme_module.THEME["panel"],
            corner_radius=12,
            border_width=1,
            border_color=theme_module.THEME["border"],
        )
        container.grid(row=row, column=0, sticky="nsew", padx=16, pady=(0, 8))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)
        self.table_container = container

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Smart.Treeview",
            background=theme_module.THEME["row"],
            fieldbackground=theme_module.THEME["row"],
            foreground=theme_module.THEME["text"],
            rowheight=27,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Smart.Treeview.Heading",
            background=theme_module.THEME["head"],
            foreground=theme_module.THEME["muted"],
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Smart.Treeview.Heading",
            background=[("active", theme_module.THEME["button_hover"])],
            foreground=[("active", theme_module.THEME["text"])],
        )
        style.map(
            "Smart.Treeview",
            background=[("selected", theme_module.THEME["accent"])],
            foreground=[("selected", theme_module.THEME["accent_text"])],
        )

        self.tree = ttk.Treeview(
            container,
            columns=COLUMNS,
            show="headings",
            style="Smart.Treeview",
            selectmode="browse",
        )
        for column in COLUMNS:
            anchor = COLUMN_ANCHORS.get(column, "w")
            self.tree.heading(
                column,
                text=column,
                anchor=anchor,
                command=lambda col=column: self._on_heading_click(col),
            )
            self.tree.column(
                column,
                width=COLUMN_WIDTHS.get(column, 120),
                minwidth=40,
                anchor=anchor,
                # Колонки не подгоняются под ширину окна: длинный Info не
                # обрезается, а прокручивается по горизонтали.
                stretch=False,
            )

        for protocol, (even, odd) in theme_module.PROTOCOL_TINTS.items():
            self.tree.tag_configure(f"{protocol}_even", background=even)
            self.tree.tag_configure(f"{protocol}_odd", background=odd)
        self.tree.tag_configure("other_even", background=theme_module.THEME["row_alt"])
        self.tree.tag_configure("other_odd", background=theme_module.THEME["row"])

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=(10, 0))

        y_scroll = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        y_scroll.grid(row=0, column=1, sticky="ns", pady=(10, 0), padx=(0, 6))
        self.tree.configure(yscrollcommand=y_scroll.set)

        # Длинный Info не влезает по ширине: горизонтальная прокрутка и
        # Shift+колесо, чтобы не тащить ползунок мышью.
        x_scroll = ttk.Scrollbar(container, orient="horizontal", command=self.tree.xview)
        x_scroll.grid(row=1, column=0, sticky="ew", padx=(10, 0), pady=(0, 4))
        self.x_scroll = x_scroll
        self.tree.configure(xscrollcommand=x_scroll.set)
        self.tree.bind("<Shift-MouseWheel>", self._scroll_sideways)

        self.tree.bind("<Double-1>", self._show_packet_details)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Control-c>", self._copy_selected_row)

        self._build_empty_state(container)

        # Листание страниц: до VIEW_LIMIT строк оно не нужно и подпись
        # сообщает «Все строки», выше — страницы по PAGE_SIZE.
        pager = ctk.CTkFrame(container, fg_color="transparent")
        pager.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        pager.grid_columnconfigure(2, weight=1)

        self.page_first_button = self._secondary_button(
            pager, "|◀", self._page_first, width=36
        )
        self.page_first_button.grid(row=0, column=0, padx=(0, 6))
        self.prev_button = self._secondary_button(
            pager, "◀ Назад", lambda: self._go_page(-1), width=96
        )
        self.prev_button.grid(row=0, column=1, padx=(0, 8))
        self.page_label = ctk.CTkLabel(
            pager,
            text="",
            anchor="w",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=theme_module.THEME["muted"],
        )
        self.page_label.grid(row=0, column=2, sticky="ew")
        self.next_button = self._secondary_button(
            pager, "Вперёд ▶", lambda: self._go_page(1), width=104
        )
        self.next_button.grid(row=0, column=3, padx=(8, 6))
        self.page_last_button = self._secondary_button(
            pager, "▶|", self._page_last, width=36
        )
        self.page_last_button.grid(row=0, column=4)

        self._context_menu = tk.Menu(
            self,
            tearoff=0,
            bg=theme_module.THEME["card"],
            fg=theme_module.THEME["text"],
            activebackground=theme_module.THEME["accent"],
            activeforeground=theme_module.THEME["accent_text"],
            borderwidth=0,
        )
        self._context_menu.add_command(
            label="Детали пакета (двойной клик)", command=self._show_packet_details
        )
        self._context_menu.add_command(
            label="Поток TCP (Ctrl+T)", command=self._follow_selected_stream
        )
        self._context_menu.add_command(
            label="Копировать строку (Ctrl+C)", command=self._copy_selected_row
        )

    def _build_empty_state(self, container) -> None:
        """Подсказка вместо пустой таблицы, пока файл не открыт."""
        frame = ctk.CTkFrame(
            container,
            fg_color=theme_module.THEME["panel"],
            corner_radius=0,
        )
        frame.grid(row=0, column=0, columnspan=2, sticky="nsew")

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            inner,
            text="Начните с файла",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=theme_module.THEME["text"],
        ).pack(pady=(0, 10))

        steps = [
            ("1", "Откройте .pcap или .pcapng — кнопка слева или Ctrl+O"),
            ("2", "Напишите команду обычными словами в поле «Команда»"),
            ("3", "Нажмите Enter — фильтр и таблица появятся сами"),
        ]
        for number, text in steps:
            line = ctk.CTkFrame(inner, fg_color="transparent")
            line.pack(anchor="w", pady=3)
            ctk.CTkLabel(
                line,
                text=number,
                width=24,
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                text_color=theme_module.THEME["accent"],
            ).pack(side="left")
            ctk.CTkLabel(
                line,
                text=text,
                font=ctk.CTkFont(family="Segoe UI", size=13),
                text_color=theme_module.THEME["muted"],
            ).pack(side="left")

        ctk.CTkLabel(
            inner,
            text="Например: «покажи http трафик с айпи 10.77.0.10»",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=theme_module.THEME["muted"],
        ).pack(pady=(14, 0))

        ctk.CTkButton(
            inner,
            text="Открыть пример дампа",
            width=200,
            height=34,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=theme_module.THEME["button"],
            hover_color=theme_module.THEME["button_hover"],
            text_color=theme_module.THEME["text"],
            command=self._load_sample,
        ).pack(pady=(12, 0))

        self.empty_state = frame

    # -- статистика ------------------------------------------------------
    def _build_stats(self, parent) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(0, 6))
        header.grid_columnconfigure(0, weight=1)

        self.stats_summary_label = ctk.CTkLabel(
            header,
            text="Статистика появится после загрузки файла.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        )
        self.stats_summary_label.grid(row=0, column=0, sticky="w")

        self.stats_scope = ctk.CTkSegmentedButton(
            header,
            values=["Все пакеты", "Найденные"],
            font=ctk.CTkFont(family="Segoe UI", size=11),
            selected_color=theme_module.THEME["accent"],
            selected_hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["text"],
            fg_color=theme_module.THEME["button"],
            command=lambda value: self._refresh_stats(),
        )
        self.stats_scope.set("Все пакеты")
        self.stats_scope.grid(row=0, column=1, padx=(8, 0))

        self._secondary_button(
            header, "Обновить", self._refresh_stats, width=100
        ).grid(row=0, column=2, padx=(8, 0))

        body = ctk.CTkFrame(parent, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 8))
        body.grid_columnconfigure(0, weight=2, uniform="stats")
        body.grid_columnconfigure(1, weight=3, uniform="stats")
        body.grid_rowconfigure(1, weight=1)

        chart_panel = self._panel(body, "ГРАФИК ТРАФИКА")
        chart_panel.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        chart_panel.grid_columnconfigure(0, weight=1)

        self.chart_metric = ctk.CTkSegmentedButton(
            chart_panel,
            values=["Байты", "Пакеты"],
            font=ctk.CTkFont(family="Segoe UI", size=10),
            selected_color=theme_module.THEME["accent"],
            selected_hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["text"],
            fg_color=theme_module.THEME["button"],
            command=lambda value: self._refresh_chart(),
        )
        self.chart_metric.set("Байты")
        self.chart_metric.grid(row=0, column=1, sticky="e", padx=(0, 10), pady=(8, 0))

        self.chart = TrafficChart(chart_panel, height=150)
        self.chart.set_theme(theme_module.THEME)
        self.chart.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(0, weight=2, uniform="left")
        left.grid_rowconfigure(1, weight=2, uniform="left")

        proto_panel = self._panel(left, "ИЕРАРХИЯ ПРОТОКОЛОВ")
        proto_panel.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        self.proto_tree = self._stats_tree(
            proto_panel,
            columns=("packets", "bytes", "share"),
            headings=("Пакеты", "Байты", "Доля"),
            widths=(80, 90, 70),
            show="tree headings",
            tree_width=180,
        )

        host_panel = self._panel(left, "САЙТЫ И ХОСТЫ")
        host_panel.grid(row=1, column=0, sticky="nsew")
        self.host_tree = self._stats_tree(
            host_panel,
            columns=("packets", "bytes", "source"),
            headings=("Пакеты", "Байты", "Источник"),
            widths=(70, 80, 70),
            show="tree headings",
            tree_width=170,
        )

        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=1, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=3, uniform="right")
        right.grid_rowconfigure(1, weight=2, uniform="right")

        conv_panel = self._panel(right, "РАЗГОВОРЫ")
        conv_panel.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        self.conv_tree = self._stats_tree(
            conv_panel,
            columns=("packets", "bytes"),
            headings=("Пакеты", "Байты"),
            widths=(90, 100),
            show="tree headings",
            tree_width=280,
        )

        endpoint_panel = self._panel(right, "УЗЛЫ")
        endpoint_panel.grid(row=1, column=0, sticky="nsew")
        self.endpoint_tree = self._stats_tree(
            endpoint_panel,
            columns=("sent", "received", "bytes"),
            headings=("Отправлено", "Получено", "Всего"),
            widths=(100, 100, 100),
            show="tree headings",
            tree_width=180,
        )

    def _panel(self, parent, title: str) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(
            parent,
            fg_color=theme_module.THEME["panel"],
            corner_radius=12,
            border_width=1,
            border_color=theme_module.THEME["border"],
        )
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            panel,
            text=title,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 2))
        return panel

    def _stats_tree(self, panel, columns, headings, widths, show, tree_width):
        tree = ttk.Treeview(
            panel,
            columns=columns,
            show=show,
            style="Smart.Treeview",
            selectmode="browse",
        )
        if show.startswith("tree"):
            tree.heading("#0", text="", anchor="w")
            tree.column("#0", width=tree_width, anchor="w")
        for name, heading, width in zip(columns, headings, widths):
            tree.heading(name, text=heading, anchor="e")
            tree.column(name, width=width, anchor="e", stretch=True)
        tree.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        return tree

    def _build_status(self, parent, row: int) -> None:
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 14))
        bar.grid_columnconfigure(1, weight=1)

        self.status_dot = ctk.CTkLabel(
            bar,
            text="●",
            width=12,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=theme_module.THEME["accent"],
        )
        self.status_dot.grid(row=0, column=0, padx=(0, 6), sticky="w")

        self.status_label = ctk.CTkLabel(
            bar,
            text="",
            anchor="w",
            justify="left",
            wraplength=880,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=theme_module.THEME["muted"],
        )
        self.status_label.grid(row=0, column=1, sticky="ew")

        # Прогресс чтения и «Отмена»: видны только пока файл читается.
        self.load_progress = ctk.CTkProgressBar(
            bar,
            width=150,
            height=8,
            corner_radius=4,
            mode="determinate",
            progress_color=theme_module.THEME["accent"],
            fg_color=theme_module.THEME["button"],
        )
        self.load_progress.set(0)
        self.load_progress.grid(row=0, column=2, padx=(10, 8))
        self.load_progress.grid_remove()

        self.cancel_button = self._secondary_button(
            bar, "Отмена", self._cancel_load, width=84
        )
        self.cancel_button.grid(row=0, column=3)
        self.cancel_button.grid_remove()

    # ------------------------------------------------------------------
    # Вкладки
    # ------------------------------------------------------------------
    def _switch_view(self, value: str) -> None:
        self._show_view("stats" if value == "Статистика" else "packets")

    def _show_view(self, name: str) -> None:
        self._current_view = name
        if name == "stats":
            self.packets_view.grid_remove()
            self.stats_view.grid()
            self._refresh_stats()
        else:
            self.stats_view.grid_remove()
            self.packets_view.grid()
