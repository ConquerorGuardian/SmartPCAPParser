"""
Графический интерфейс Smart PCAP Parser.

Раскладка: боковая панель + рабочая область с вкладками.

Боковая панель (слева):
1. Название приложения.
2. Карточка файла: имя, число пакетов, кнопка «Открыть файл».
3. Карточка команды: ввод обычными словами + «Применить».
4. Быстрые фильтры: десять частых протоколов в один клик.
5. Примеры команд: клик подставляет текст, адрес выделен — просто печатайте.
6. История команд: повторный запуск одним кликом.
7. Переключатель темы.

Рабочая область (справа):
8. Строка display-фильтра Wireshark и кнопки действий.
9. Вкладки «Пакеты» и «Статистика».
10. Таблица пакетов: отдельные колонки портов, сортировка по клику,
    цвет фона по транспорту, окно деталей пакета по двойному клику.
11. Статистика: иерархия протоколов, разговоры, узлы.
12. Строка состояния.

Чтение файла выполняется в отдельном потоке, чтобы окно не зависало
на больших дампах.

Сам класс собран из миксинов, чтобы файл оставался читаемым:
    gui/layout.py      — построение виджетов;
    gui/table_view.py  — строки таблицы, поиск, сортировка, экспорт;
    gui/stats_view.py  — вкладка «Статистика»;
    gui/dialogs.py     — справка, детали пакета, поток TCP/UDP, вердикт.
Здесь остаётся ядро: загрузка файла, обработка команд, тема, горячие
клавиши, настройки и сохранение состояния.
"""

import queue
import re
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

# Корень проекта в sys.path, чтобы запускать и как модуль, и как скрипт.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui import theme as theme_module  # noqa: E402
from gui.dialogs import DialogsMixin  # noqa: E402
from gui.layout import LayoutMixin  # noqa: E402
from gui.stats_view import StatsMixin  # noqa: E402
from gui.table_view import TableMixin  # noqa: E402
from gui.theme import (  # noqa: E402
    APP_TITLE,
    DARK_THEME,
    EXAMPLES_VISIBLE,
    LIGHT_THEME,
    QUICK_FILTERS,
    TINTS,
)
from gui.utils import (  # noqa: E402
    HISTORY_LIMIT,
    MAX_PAYLOAD_FILE,
    PREVIEW_COUNT,
    VIEW_LIMIT,
    asset_path,
    format_count,
    resource_path,
    table_limit,
)
from parser import __version__ as APP_VERSION  # noqa: E402
from parser.engine import NaturalLanguageFilterEngine  # noqa: E402
from parser.filters import generate_filter  # noqa: E402
from parser.matcher import compile_filter  # noqa: E402
from parser.pcap_handler import PcapHandler, PcapResult  # noqa: E402
from parser.settings import RECENT_LIMIT, load_settings, save_settings  # noqa: E402
from parser.validators import is_valid_ipv6, is_valid_mac_address  # noqa: E402

__all__ = [
    "SmartPcapApp",
    "main",
    # Имена ниже нужны снаружи (tests/test_gui_smoke.py) как gui.app.<имя>,
    # поэтому импорты выше не считаются неиспользуемыми.
    "EXAMPLES_VISIBLE",
    "QUICK_FILTERS",
    "VIEW_LIMIT",
    "compile_filter",
    "table_limit",
]

# Пункт-заглушка в списке недавних файлов: выбранный, он ничего не делает.
RECENT_PLACEHOLDER = "Недавние файлы…"


class SmartPcapApp(ctk.CTk, LayoutMixin, TableMixin, StatsMixin, DialogsMixin):
    """Главное окно приложения."""

    _recent_placeholder = RECENT_PLACEHOLDER

    def __init__(self, initial_file: str | Path | None = None) -> None:
        # Настройки читаем до построения интерфейса: тема и история
        # должны примениться сразу, без мигания.
        self.settings = load_settings()
        self.theme_name = self.settings["theme"]
        theme_module.THEME = dict(LIGHT_THEME if self.theme_name == "light" else DARK_THEME)
        theme_module.PROTOCOL_TINTS = TINTS[self.theme_name]

        ctk.set_appearance_mode("light" if self.theme_name == "light" else "dark")
        ctk.set_default_color_theme("dark-blue")

        super().__init__()

        self.title("{} {}".format(APP_TITLE, APP_VERSION))
        self.geometry(self.settings["geometry"] or "1380x820")
        self.minsize(1080, 620)
        self.configure(fg_color=theme_module.THEME["bg"])

        self.engine = NaturalLanguageFilterEngine()
        self.handler = PcapHandler(preview_count=PREVIEW_COUNT)
        self.packets: list = []
        self.packet_index: dict = {}
        self.pcap_path: Path | None = None
        self.current_filter = ""
        self.current_result: PcapResult | None = None
        self._load_queue: queue.Queue = queue.Queue()
        self._load_cancel = threading.Event()
        self._load_percent: float | None = None
        self._load_started = 0.0
        self._busy = False
        self._history: list[str] = list(self.settings["history"])
        self._last_dir = self.settings["last_dir"]
        self._recent: list[str] = list(self.settings.get("recent") or [])[:RECENT_LIMIT]
        self._recent_map: dict[str, str] = {}
        self._rows: list = []
        self._row_texts: list[str] = []
        self._visible_total = 0
        self._page = 1
        self._pager_text = ""
        self._sort_column: str | None = None
        self._sort_reverse = False
        self._search_text = ""
        self._current_view = "packets"
        self._last_details_window = None
        self.simple_mode = bool(self.settings.get("simple_mode", True))

        self._build_ui()
        self._apply_columns(self.settings.get("columns") or {})
        self._apply_simple_mode()
        self._init_stats_menus()
        self.stats_scope.set(self.settings.get("stats_scope", "Все пакеты"))
        self._refresh_recent_menu()
        self._set_status("Откройте файл .pcap или .pcapng, затем опишите трафик словами.")
        self.bind("<Control-o>", lambda event: self._open_file())
        self.bind("<Control-t>", lambda event: self._follow_selected_stream())
        self.bind("<Control-l>", lambda event: self._toggle_theme())
        self.bind("<Control-f>", self._focus_search)
        self.bind("<Control-Prior>", lambda event: self._go_page(-1))
        self.bind("<Control-Next>", lambda event: self._go_page(1))
        self.bind("<F1>", lambda event: self._show_help())
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._apply_window_icon()
        self._enable_drop()

        # Файл, переданный аргументом (или перетащенный на иконку exe),
        # открываем после того, как окно уже нарисовалось.
        if initial_file:
            self.after(150, lambda: self._open_initial_file(Path(initial_file)))

    def _open_initial_file(self, path: Path) -> None:
        """Открывает файл из аргументов командной строки."""
        if not path.exists():
            self._set_status("Файл не найден: {}".format(path))
            return
        self._load_path(path)

    def _update_title(self) -> None:
        """В заголовке окна — имя открытого файла (видно и на панели задач)."""
        base = "{} {}".format(APP_TITLE, APP_VERSION)
        if self.pcap_path is not None:
            self.title("{} — {}".format(base, Path(self.pcap_path).name))
        else:
            self.title(base)

    def _on_command_key(self, event=None) -> None:
        """Показывает подсказку; стёрли команду — возвращает все пакеты."""
        self._update_command_hint()
        if not self.command_entry.get().strip():
            self._reset_filter()

    def _clear_command(self, event=None) -> None:
        """Esc: очистить ввод и вернуться ко всем пакетам."""
        self.command_entry.delete(0, "end")
        self._update_command_hint()
        self._reset_filter()

    def _reset_filter(self) -> None:
        """Снимает фильтр: в таблицу возвращаются все пакеты файла."""
        if not self.packets:
            return

        if not self.current_filter:
            # Фильтра и не было — просто напоминаем, что показано всё.
            return

        self.current_filter = ""
        self._set_filter_text("")
        result = self.handler.apply(self.packets, "", limit=-1)
        self._render(result)
        self._refresh_stats()
        self._set_status(
            "Фильтр снят: показаны все пакеты файла ({}).".format(
                format_count(len(self.packets))
            )
        )

    def _update_command_hint(self, event=None) -> None:
        """Показывает пользователю, что понято из команды, ещё до Enter."""
        text = self.command_entry.get().strip()
        if not text:
            self.hint_label.configure(
                text="Наберите команду — покажу, какой фильтр получится.",
                text_color=theme_module.THEME["muted"],
            )
            return

        query = self.engine.parse(text)
        if query.intent == "help":
            self.hint_label.configure(
                text="Открою справку по Enter.", text_color=theme_module.THEME["accent"]
            )
            return

        filter_string = generate_filter(query)
        reason = self._why_not_understood(text)

        if query.raw_filter and filter_string:
            self.hint_label.configure(
                text=f"Фильтр Wireshark как есть: {filter_string}",
                text_color=theme_module.THEME["accent"],
            )
        elif reason:
            self.hint_label.configure(text=reason, text_color=theme_module.THEME["danger"])
        elif filter_string:
            self.hint_label.configure(
                text=f"→ {filter_string}", text_color=theme_module.THEME["accent"]
            )
        else:
            self.hint_label.configure(
                text="Не нашёл адрес, порт, мак или протокол. "
                     "Пример: «http трафик с айпи 10.0.0.5».",
                text_color=theme_module.THEME["danger"],
            )

    @staticmethod
    def _why_not_understood(text: str) -> str:
        """Объясняет причину, а не просто «не понял»."""
        for match in re.finditer(r"\d{1,3}(?:\.\d{1,3}){3}", text):
            address = match.group()
            if any(int(part) > 255 for part in address.split(".")):
                return f"Адрес {address} некорректен: каждый октет 0–255."

        for token in re.split(r"[\s,;()]+", text):
            candidate = token.strip(".,;!?«»\"'")
            if candidate.count(":") < 2:
                continue
            if is_valid_mac_address(candidate):
                continue
            if not is_valid_ipv6(candidate):
                return f"Адрес {candidate} похож на IPv6, но записан с ошибкой."

        for match in re.finditer(r"\b\d{1,5}\b", text):
            value = int(match.group())
            if not 1 <= value <= 65535:
                return f"Порт {value} вне диапазона 1–65535."

        return ""

    def _use_example(self, command: str) -> None:
        """Подставляет пример и выделяет то, что пользователю нужно заменить."""
        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, command)
        self.command_entry.focus_set()

        start, end = self._variable_span(command)
        if start is not None:
            self.command_entry.select_range(start, end)
            self.command_entry.icursor(end)

        self._update_command_hint()

    @staticmethod
    def _variable_span(command: str):
        """Границы адреса или порта в примере — их и выделяем."""
        match = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", command)
        if match:
            return match.span()
        match = re.search(r"aa:bb:cc:dd:ee:ff", command)
        if match:
            return match.span()
        match = re.search(r"\b\d{1,5}\b", command)
        if match:
            return match.span()
        return None, None

    # ------------------------------------------------------------------
    # Работа с файлом
    # ------------------------------------------------------------------
    def _open_file(self) -> None:
        if self._busy:
            return

        path = filedialog.askopenfilename(
            title="Открыть файл захвата",
            initialdir=self._last_dir or None,
            filetypes=[
                ("Файлы захвата", "*.pcap *.pcapng *.cap"),
                ("Все файлы", "*.*"),
            ],
        )
        if not path:
            return

        self._load_path(Path(path))

    def _load_path(self, path: Path) -> None:
        """Читает файл в фоне — общая точка для диалога и кнопки «пример»."""
        self._last_dir = str(path.parent)
        self._load_cancel.clear()
        self._load_percent = 0.0
        self._load_started = time.monotonic()
        self._set_busy(True)
        self._set_status("Читаю файл: {}…".format(path.name))
        threading.Thread(target=self._load_worker, args=(path,), daemon=True).start()
        self.after(100, self._poll_load)

    def _load_sample(self) -> None:
        """Открывает встроенный пример дампа — посмотреть, как всё работает."""
        if self._busy:
            return

        sample = PROJECT_ROOT / "tests" / "sample_traffic.pcap"
        if not sample.exists():
            # В собранном exe путь другой — берём ресурс рядом с приложением.
            sample = resource_path("tests/sample_traffic.pcap")
        if not sample.exists():
            self._set_status("Файл примера не найден рядом с приложением.")
            return

        self._load_path(sample)

    def _load_worker(self, path: Path) -> None:
        # Тело TCP нужно для «Поток TCP» и hex в деталях, но на большом файле
        # это лишние гигабайты памяти — тогда читаем без него.
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        keep_payload = size <= MAX_PAYLOAD_FILE
        packets, error = self.handler.load(
            path,
            keep_payload=keep_payload,
            progress=self._on_load_progress,
            should_stop=self._load_cancel.is_set,
        )
        self._load_queue.put((path, packets, error))

    def _on_load_progress(self, percent: float | None) -> None:
        """Вызывается из фонового потока: только запоминаем значение."""
        self._load_percent = percent

    def _cancel_load(self) -> None:
        if not self._busy:
            return
        self._load_cancel.set()
        self._set_status("Останавливаю чтение файла…")
        if getattr(self, "cancel_button", None) is not None:
            self.cancel_button.configure(state="disabled")

    def _poll_load(self) -> None:
        try:
            path, packets, error = self._load_queue.get_nowait()
        except queue.Empty:
            self._update_load_progress()
            self.after(100, self._poll_load)
            return

        self._set_busy(False)

        if error:
            if self._load_cancel.is_set() or "отменено" in error.lower():
                self._set_status(
                    "Чтение файла отменено. Предыдущий файл остался открытым."
                )
                return
            self._set_status(f"Не удалось прочитать файл: {error}")
            messagebox.showerror(APP_TITLE, f"Не удалось прочитать файл:\n\n{error}")
            return

        self.pcap_path = path
        self.packets = packets
        self.packet_index = {packet.number: packet for packet in packets}
        self.current_filter = ""
        self._set_filter_text("")
        self.file_label.configure(text=path.name)
        self.packet_label.configure(text=f"{len(packets)} пакетов · {path.suffix}")
        self._remember_recent(path)
        self._update_title()

        if hasattr(self, "empty_state"):
            self.empty_state.grid_remove()

        self._set_status(f"Строю таблицу по {format_count(len(packets))} пакетам...")
        self.update_idletasks()
        result = self.handler.apply(packets, "", limit=-1)
        self._render(result)
        self._refresh_verdict()
        self._refresh_stats()

        try:
            big = path.stat().st_size > MAX_PAYLOAD_FILE
        except OSError:
            big = False

        status = f"Файл загружен: {format_count(len(packets))} пакетов."
        if len(self.packets) > VIEW_LIMIT:
            status += " Листайте страницы кнопками под таблицей или задайте фильтр."
        else:
            status += " Показаны все. Введите команду, например: «покажи http трафик»."
        if big:
            status += (" Файл большой — тела TCP подгружаются по требованию, "
                       "когда открываете поток.")
        self._set_status(status)

    def _update_load_progress(self) -> None:
        """Плавно двигает полоску прогресса, пока идёт чтение."""
        bar = getattr(self, "load_progress", None)
        if bar is None or not self._busy:
            return
        percent = self._load_percent
        if percent is None:
            # Сжатый файл: процент неизвестен — показываем «бегущую» полоску.
            bar.set(0.5 if int(time.monotonic() * 2) % 2 else 0.15)
            self._set_status("Читаю сжатый файл…")
            return
        bar.set(max(0.02, min(1.0, percent)))
        elapsed = time.monotonic() - self._load_started
        self._set_status(
            "Читаю файл: {:d} % · {:.1f} с".format(int(percent * 100), elapsed)
        )

    # ------------------------------------------------------------------
    # Команды и фильтры
    # ------------------------------------------------------------------
    def _apply_command(self, event=None) -> None:
        if self._busy:
            return

        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        command = self.command_entry.get().strip()
        if not command:
            self._reset_filter()
            self._set_status(
                "Поле команды пустое — показаны все пакеты. "
                "Введите команду, например: \"покажи пакеты на порт 80\"."
            )
            return

        query = self.engine.parse(command)
        if query.intent == "help":
            self._show_help()
            return

        filter_string = generate_filter(query)
        if not filter_string:
            self._set_status(
                "Не нашёл сетевых индикаторов в команде. Укажите IP, порт, MAC "
                "или протокол: например \"покажи dns трафик\"."
            )
            return

        self._push_history(command)
        self.current_filter = filter_string
        self._set_filter_text(filter_string)

        limit = -1
        result = self.handler.apply(self.packets, filter_string, limit=limit)
        if result.error:
            self._set_status(f"Ошибка фильтра: {result.error}")
            return

        self._render(result)
        self._refresh_stats()

        if result.matched_packets == 0:
            self._set_status(
                f"По фильтру \"{filter_string}\" ничего не найдено. Проверьте адрес или порт."
            )
        elif len(self._rows) > VIEW_LIMIT:
            self._set_status(
                f"Найдено {format_count(result.matched_packets)} из "
                f"{format_count(result.total_packets)} пакетов — показываю страницами. "
                "Фильтр: {}.".format(filter_string)
            )
        else:
            self._set_status(
                f"Найдено {format_count(result.matched_packets)} из {format_count(result.total_packets)} пакетов. Фильтр: {filter_string}."
            )

    def _run_quick_filter(self, command: str) -> None:
        """Кнопка-чип: подставляет готовую команду и применяет её."""
        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, command)
        self._apply_command()

    def _show_packets_by_filter(self, filter_string: str) -> None:
        """Применяет готовый фильтр (из статистики) и открывает пакеты."""
        if self._busy:
            return
        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, filter_string)
        self._apply_command()

        self.view_switch.set("Пакеты")
        self._show_view("packets")

    def _push_history(self, command: str) -> None:
        if not command:
            return
        if command in self._history:
            self._history.remove(command)
        self._history.insert(0, command)
        del self._history[HISTORY_LIMIT:]
        self._rebuild_history()

    def _rebuild_history(self) -> None:
        for child in self.history_frame.winfo_children():
            child.destroy()

        if not self._history:
            ctk.CTkLabel(
                self.history_frame,
                text="Здесь появятся выполненные команды.",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=theme_module.THEME["muted"],
                anchor="w",
                justify="left",
                wraplength=250,
            ).grid(row=0, column=0, sticky="w", padx=6, pady=6)
            return

        for index, command in enumerate(self._history):
            button = ctk.CTkButton(
                self.history_frame,
                text=command,
                height=28,
                anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                fg_color="transparent",
                hover_color=theme_module.THEME["button_hover"],
                text_color=theme_module.THEME["text"],
                command=lambda cmd=command: self._run_quick_filter(cmd),
            )
            button.grid(row=index, column=0, sticky="ew", padx=2, pady=1)

    # ------------------------------------------------------------------
    # Настройки: сохранение и восстановление
    # ------------------------------------------------------------------
    def _collect_columns(self) -> dict:
        """Текущая ширина колонок таблицы — чтобы не настраивать заново."""
        try:
            widths = {"#0": int(self.tree.column("#0", "width"))}
            for column in self.tree["columns"]:
                widths[str(column)] = int(self.tree.column(column, "width"))
            return widths
        except Exception:                             # noqa: BLE001
            return {}

    def _apply_columns(self, widths: dict) -> None:
        for name, width in (widths or {}).items():
            try:
                self.tree.column(name, width=int(width))
            except Exception:                         # noqa: BLE001
                continue

    def _current_settings(self) -> dict:
        return {
            "theme": self.theme_name,
            "geometry": self.geometry(),
            "history": list(self._history),
            "last_dir": self._last_dir,
            "columns": self._collect_columns(),
            "stats_scope": self.stats_scope.get(),
            "recent": list(self._recent),
            "simple_mode": bool(getattr(self, "simple_mode", True)),
        }

    # ------------------------------------------------------------------
    # Недавние файлы
    # ------------------------------------------------------------------
    def _remember_recent(self, path: Path) -> None:
        """Запоминает файл в списке недавних (свежие сверху, без дублей)."""
        value = str(path)
        self._recent = [item for item in self._recent if item != value]
        self._recent.insert(0, value)
        del self._recent[RECENT_LIMIT:]
        self._refresh_recent_menu()

    def _refresh_recent_menu(self) -> None:
        """Собирает подписи «файл — папка» для выпадающего списка."""
        menu = getattr(self, "recent_menu", None)
        if menu is None:
            return

        self._recent_map = {}
        labels: list[str] = []
        for item in self._recent:
            path = Path(item)
            label = "{} — {}".format(path.name, path.parent.name or str(path.parent))
            if label in self._recent_map:
                continue
            self._recent_map[label] = item
            labels.append(label)

        if not labels:
            menu.configure(values=[self._recent_placeholder])
            menu.pack_forget()
            return

        menu.configure(values=labels)
        menu.set(labels[0])
        menu.pack(fill="x", padx=14, pady=(0, 12))

    def _open_recent(self, label: str) -> None:
        if self._busy:
            return
        path = self._recent_map.get(label)
        if not path:
            return
        target = Path(path)
        if not target.exists():
            self._set_status(f"Файл больше не существует: {path}")
            self._recent = [item for item in self._recent if item != path]
            self._refresh_recent_menu()
            return
        self._load_path(target)

    def _on_close(self) -> None:
        """Сохраняет настройки и закрывает окно."""
        try:
            save_settings(self._current_settings())
        finally:
            self.destroy()

    # ------------------------------------------------------------------
    # Тема и режим интерфейса
    # ------------------------------------------------------------------
    def _toggle_theme(self) -> None:
        target = "light" if self.theme_name == "dark" else "dark"
        self._set_theme(target)

    def _toggle_simple_mode(self) -> None:
        """Простой режим прячет примеры, лишние кнопки и панель вердикта."""
        self.simple_mode = bool(self.simple_switch.get())
        self._apply_simple_mode()
        save_settings(self._current_settings())
        if self.simple_mode:
            self._set_status("Простой режим: только файл, команда и шесть фильтров.")
        else:
            self._set_status("Опытный режим: все панели на виду.")

    def _set_theme(self, name: str) -> None:
        # Палитра живёт в gui/theme.py: меняем её через модуль, иначе
        # миксины остались бы с цветами, прочитанными при импорте.
        self.theme_name = name
        theme_module.THEME = dict(LIGHT_THEME if name == "light" else DARK_THEME)
        theme_module.PROTOCOL_TINTS = TINTS[name]
        ctk.set_appearance_mode("light" if name == "light" else "dark")

        # Полная перестройка: проще и надёжнее, чем красить каждый виджет.
        self.after(10, self._rebuild_ui)

    def _capture_state(self) -> dict:
        return {
            "file_text": self.file_label.cget("text"),
            "packets_text": self.packet_label.cget("text"),
            "empty_visible": bool(self.empty_state.winfo_ismapped()),
            "command_text": self.command_entry.get(),
            "filter_text": self.current_filter,
            "status_text": self.status_label.cget("text"),
            "rows": list(self._rows),
            "history": list(self._history),
            "sort_column": self._sort_column,
            "sort_reverse": self._sort_reverse,
            "view": self._current_view,
            "verdict_visible": bool(self.verdict_panel.winfo_ismapped()),
            "scope": self.stats_scope.get(),
            "chart_metric": self.chart_metric.get(),
            "columns": self._collect_columns(),
            "page": getattr(self, "_page", 1),
        }

    def _rebuild_ui(self) -> None:
        state = self._capture_state()

        for child in self.winfo_children():
            child.destroy()

        self.configure(fg_color=theme_module.THEME["bg"])
        self._build_ui()
        self._restore_state(state)

    def _restore_state(self, state: dict) -> None:
        self.file_label.configure(text=state["file_text"])
        self.packet_label.configure(text=state["packets_text"])
        self.command_entry.delete(0, "end")
        if state["command_text"]:
            self.command_entry.insert(0, state["command_text"])
        self._set_filter_text(state["filter_text"])
        self.command_entry.bind("<Return>", self._apply_command)
        self.command_entry.bind("<KeyRelease>", self._on_command_key)
        self.command_entry.bind("<Escape>", self._clear_command)
        self._update_command_hint()

        self._history = state["history"]
        self._rebuild_history()
        self._refresh_recent_menu()

        self._sort_column = state["sort_column"]
        self._sort_reverse = state["sort_reverse"]
        self._search_text = ""
        self._page = state.get("page", 1)
        self._apply_columns(state.get("columns") or {})
        self._update_headings()

        self._fill_table()

        self.stats_scope.set(state["scope"])
        self.chart_metric.set(state.get("chart_metric", "Байты"))
        self._refresh_stats()
        self._refresh_verdict()

        if state["empty_visible"]:
            self.empty_state.grid()
        else:
            self.empty_state.grid_remove()

        if state["view"] == "stats":
            self.view_switch.set("Статистика")
            self._show_view("stats")
        else:
            self.view_switch.set("Пакеты")
            self._show_view("packets")

        self._set_status(state["status_text"])
        self.bind("<Control-o>", lambda event: self._open_file())
        self.bind("<Control-t>", lambda event: self._follow_selected_stream())
        self.bind("<Control-l>", lambda event: self._toggle_theme())
        self.bind("<F1>", lambda event: self._show_help())

    # ------------------------------------------------------------------
    # Прочее
    # ------------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.configure(cursor="watch" if busy else "")
        self.status_dot.configure(
            text_color=theme_module.THEME["muted"] if busy else theme_module.THEME["accent"]
        )

        bar = getattr(self, "load_progress", None)
        button = getattr(self, "cancel_button", None)
        if bar is not None:
            if busy:
                bar.set(0)
                bar.grid()
            else:
                bar.grid_remove()
        if button is not None:
            if busy:
                button.configure(state="normal")
                button.grid()
            else:
                button.grid_remove()

    # ------------------------------------------------------------------
    # Иконка и перетаскивание файлов
    # ------------------------------------------------------------------
    def _apply_window_icon(self) -> None:
        """Иконка окна/панели задач. Нет файла — не повод падать."""
        try:
            icon = asset_path("app.ico")
            if icon.exists():
                self.iconbitmap(default=str(icon))
        except Exception:                          # noqa: BLE001 — платформа разная
            pass

    def _enable_drop(self) -> None:
        """Перетаскивание файла в окно — если установлен tkinterdnd2.

        Без библиотеки приложение работает как обычно: перетаскивание
        просто не включено, поэтому это необязательная зависимость.
        """
        try:
            from tkinterdnd2 import TkinterDnD
        except ImportError:
            return

        try:
            TkinterDnD._require(self)
            self.tk.createcommand("smartpcap_drop", self._on_drop_files)
            self.tk.call("bind", self._w, "<<Drop>>", "smartpcap_drop %D")
            self.tk.call(
                "tkdnd::drop_target", "register", self._w, "DND_Files"
            )
        except Exception:                          # noqa: BLE001 — tkdnd мог не найтись
            pass

    def _on_drop_files(self, data: str) -> None:
        try:
            items = self.tk.splitlist(data)
        except Exception:                          # noqa: BLE001
            return
        if not items or self._busy:
            return
        self._load_path(Path(items[0]))


def main(initial_file: str | Path | None = None) -> None:
    """Запускает окно. `initial_file` — сразу открыть этот дамп."""
    app = SmartPcapApp(initial_file=initial_file)
    app.mainloop()


if __name__ == "__main__":
    main()
