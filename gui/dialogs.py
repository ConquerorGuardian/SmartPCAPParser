"""
Дополнительные окна: справка, детали пакета, поток TCP/UDP, вердикт.

Каждое окно — ctk.CTkToplevel поверх главного. Данные берутся из self.packets
и self.packet_index, поэтому миксин ничего не хранит сам.

THEME читается через theme_module: окна открываются уже в текущей теме.
"""

from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from gui import theme as theme_module
from gui.help_text import HELP_TEXT
from gui.theme import APP_TITLE
from gui.utils import (
    HEX_LIMIT,
    STREAM_PAYLOAD_LIMIT,
    _safe_stem,
    decode_tcp_flags,
    hex_dump,
)
from parser.pcap_reader import read_payloads
from parser.stats import format_bytes
from parser.streams import (
    MODE_HEX,
    MODE_TEXT,
    VIEW_BOTH,
    VIEW_CLIENT,
    VIEW_SERVER,
    conversation_frames,
    follow_datagram_flow,
    follow_stream,
    format_endpoint,
    render_stream,
    summarize,
)
from parser.verdict import format_verdict


class DialogsMixin:
    """Окна справки, деталей пакета, потока TCP/UDP и вердикта."""

    def _show_verdict_window(self) -> None:
        verdict = getattr(self, "verdict", None)
        if verdict is None:
            self._set_status("Вердикт появится после загрузки файла.")
            return

        window = ctk.CTkToplevel(self)
        window.title("Вердикт по файлу")
        window.geometry("780x600")
        window.transient(self)
        window.configure(fg_color=theme_module.THEME["bg"])

        textbox = ctk.CTkTextbox(
            window,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            wrap="word",
            fg_color=theme_module.THEME["panel"],
            border_color=theme_module.THEME["border"],
            border_width=1,
            text_color=theme_module.THEME["text"],
        )
        textbox.pack(fill="both", expand=True, padx=14, pady=12)
        textbox.insert("1.0", format_verdict(verdict))
        textbox.configure(state="disabled")

        def copy_text() -> None:
            window.clipboard_clear()
            window.clipboard_append(format_verdict(verdict))
            self._set_status("Вердикт скопирован в буфер обмена.")

        ctk.CTkButton(
            window,
            text="Копировать",
            width=130,
            height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=theme_module.THEME["accent"],
            hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["accent_text"],
            command=copy_text,
        ).pack(pady=(0, 12))

        window.verdict_textbox = textbox
        window.after(50, window.lift)

    # ------------------------------------------------------------------
    # Детали пакета
    # ------------------------------------------------------------------
    def _show_packet_details(self, event=None) -> None:
        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        if event is not None:
            row_id = self.tree.identify_row(event.y)
            if not row_id:
                return
            self.tree.selection_set(row_id)
            self.tree.focus(row_id)

        frame = self._selected_frame()
        if frame is None:
            self._set_status(
                "Выберите пакет в таблице, затем нажмите «Детали пакета»."
            )
            return

        packet = self.packet_index.get(frame)
        if packet is None:
            self._set_status(f"Пакет {frame} не найден в загруженном файле.")
            return

        window = ctk.CTkToplevel(self)
        window.title(f"Пакет {frame} — детали")
        window.geometry("820x680")
        window.minsize(640, 460)
        window.transient(self)
        window.configure(fg_color=theme_module.THEME["bg"])

        header = ctk.CTkLabel(
            window,
            text="Кадр {} · {} · {} байт · {}".format(
                packet.number,
                packet.protocol or "?",
                packet.length,
                format_bytes(packet.length),
            ),
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=theme_module.THEME["text"],
            anchor="w",
        )
        header.pack(fill="x", padx=14, pady=(12, 2))

        ctk.CTkLabel(
            window,
            text="{}  →  {}   ({})".format(
                self._endpoint_text(packet, source=True),
                self._endpoint_text(packet, source=False),
                packet.app or packet.protocol or "?",
            ),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 8))

        fields = ttk.Treeview(
            window,
            columns=("value",),
            show="tree headings",
            style="Smart.Treeview",
            selectmode="browse",
        )
        fields.heading("#0", text="Слой / поле", anchor="w")
        fields.heading("value", text="Значение", anchor="w")
        fields.column("#0", width=260, anchor="w")
        fields.column("value", width=460, anchor="w", stretch=True)
        fields.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        def add_layer(name: str, pairs) -> None:
            parent = fields.insert("", "end", text=name, open=True)
            for field, value in pairs:
                if value is None or value == "":
                    continue
                fields.insert(parent, "end", text=field, values=(value,))

        add_layer("Frame", [
            ("Номер кадра", packet.number),
            ("Время, с", f"{packet.timestamp:.6f}"),
            ("Длина, байт", packet.length),
            ("Длина в сети, байт", packet.wire_length),
            ("Пакетов в файле", len(self.packets)),
        ])
        add_layer("Ethernet", [
            ("MAC отправителя", packet.src_mac),
            ("MAC получателя", packet.dst_mac),
        ])
        add_layer("IP", [
            ("Адрес отправителя", packet.src_ip),
            ("Адрес получателя", packet.dst_ip),
            ("TTL / Hop limit", packet.ttl or None),
            ("Длина IP-пакета", packet.ip_len or None),
        ])

        if packet.protocol == "TCP":
            add_layer("TCP", [
                ("Порт отправителя", packet.src_port),
                ("Порт получателя", packet.dst_port),
                ("Sequence number", packet.seq),
                ("Acknowledgment", packet.tcp_ack or None),
                ("Окно", packet.tcp_window or None),
                ("Флаги", decode_tcp_flags(packet.tcp_flags)),
                ("Флаги, hex", f"0x{packet.tcp_flags:03x}"),
                ("Данные, байт", len(packet.payload)),
                ("Приложение", packet.app),
            ])
        elif packet.protocol == "UDP":
            add_layer("UDP", [
                ("Порт отправителя", packet.src_port),
                ("Порт получателя", packet.dst_port),
                ("Длина UDP", packet.udp_len or None),
                ("Приложение", packet.app),
            ])

        add_layer("Имена", [
            ("Сайт (HTTP Host)", packet.host),
            ("Сервер (TLS SNI)", packet.sni),
            ("Домен (DNS)", packet.dns_name),
            ("Путь запроса", packet.http_uri),
        ])

        add_layer("Приложение", [("Info", packet.info)])

        payload_label = ctk.CTkLabel(
            window,
            text="Данные (hex-дамп)",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        )
        payload_label.pack(fill="x", padx=14)

        payload_box = ctk.CTkTextbox(
            window,
            height=170,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="none",
            fg_color=theme_module.THEME["panel"],
            border_color=theme_module.THEME["border"],
            border_width=1,
            text_color=theme_module.THEME["mono"],
        )
        payload_box.pack(fill="x", padx=14, pady=(4, 12))

        if packet.payload:
            data = packet.payload[:HEX_LIMIT]
            payload_box.insert("1.0", hex_dump(data))
            if len(packet.payload) > HEX_LIMIT:
                payload_box.insert(
                    "end",
                    f"\n\n… показаны первые {HEX_LIMIT // 1024} КБ из {format_bytes(len(packet.payload))}",
                )
        else:
            payload_box.insert(
                "1.0",
                "Нет данных: у пакета нет полезной нагрузки или это не TCP.\n"
                "Тело TCP сохраняется при открытии файла, поэтому обычно\n"
                "здесь виден запрос или ответ.",
            )
        payload_box.configure(state="disabled")

        def close_window() -> None:
            window.withdraw()
            window.after(150, window.destroy)

        window.protocol("WM_DELETE_WINDOW", close_window)
        window.after(50, window.lift)
        window.after(100, window.focus_force)

        self._last_details_window = window
        window.field_tree = fields
        window.payload_box = payload_box

    @staticmethod
    def _endpoint_text(packet, source: bool = True) -> str:
        address = packet.src_ip if source else packet.dst_ip
        port = packet.src_port if source else packet.dst_port
        if not address:
            address = packet.src_mac if source else packet.dst_mac
        if port is None:
            return address or "?"
        return "{}:{}".format(address or "?", port)

    # ------------------------------------------------------------------
    # Поток TCP (Follow TCP stream)
    # ------------------------------------------------------------------
    def _load_stream_payloads(self, frame: int, kind: str = "tcp") -> None:
        """Дочитывает тела только для выбранного соединения."""
        if self.pcap_path is None:
            return

        frames = conversation_frames(self.packets, frame, kind=kind)
        if not frames:
            return

        # Если данные уже есть (файл небольшой) — ничего не делаем.
        for number in frames:
            packet = self.packet_index.get(number)
            if packet is not None and packet.payload:
                return

        self._set_status(
            f"Подгружаю данные потока из файла ({len(frames)} кадров)..."
        )
        self.update_idletasks()

        payloads = read_payloads(
            self.pcap_path, frames, max_bytes=STREAM_PAYLOAD_LIMIT
        )
        for number, data in payloads.items():
            packet = self.packet_index.get(number)
            if packet is not None:
                packet.payload = data

        loaded = sum(len(data) for data in payloads.values())
        if loaded >= STREAM_PAYLOAD_LIMIT:
            self._set_status(
                f"Поток большой: показаны первые {format_bytes(STREAM_PAYLOAD_LIMIT)} данных."
            )

    def _follow_selected_stream(self) -> None:
        if not self.packets:
            self._set_status("Сначала откройте файл .pcap или .pcapng.")
            return

        frame = self._selected_frame()
        if frame is None:
            self._set_status(
                "Выберите TCP- или UDP-пакет в таблице, затем нажмите "
                "«Поток TCP» или Ctrl+T."
            )
            return

        target = self.packet_index.get(frame)

        stream = follow_stream(self.packets, frame)
        if stream is None:
            if target is not None and target.transport == "UDP":
                # «Поток» для UDP: датаграммы в порядке захвата.
                self._load_stream_payloads(frame, kind="udp")
                stream = follow_datagram_flow(self.packets, frame)
                if stream is None:
                    self._set_status(
                        f"Пакет {frame} — UDP, но обмен для него не собрался."
                    )
                    return
            else:
                self._set_status(
                    f"Пакет {frame} — не TCP и не UDP, поток для него не "
                    "собирается."
                )
                return

        if stream.total_bytes == 0:
            # Заголовки уже в памяти, а тела не хранились (большой файл):
            # дочитываем только кадры этого соединения.
            self._load_stream_payloads(
                frame, kind="udp" if getattr(stream, "kind", "TCP") == "UDP" else "tcp"
            )
            if getattr(stream, "kind", "TCP") == "UDP":
                stream = follow_datagram_flow(self.packets, frame) or stream
            else:
                stream = follow_stream(self.packets, frame) or stream

        if stream.total_bytes == 0:
            self._set_status(
                f"В потоке {format_endpoint(stream.client)} <-> {format_endpoint(stream.server)} нет данных: только служебные пакеты "
                "(SYN/FIN/RST) или данные не попали в захват."
            )
            return

        self._set_status(summarize(stream))
        self._open_stream_window(stream)

    def _open_stream_window(self, stream) -> None:
        kind = getattr(stream, "kind", "TCP")
        window = ctk.CTkToplevel(self)
        window.title(
            f"Поток {kind}: {format_endpoint(stream.client)} <-> {format_endpoint(stream.server)}"
        )
        window.geometry("1020x700")
        window.minsize(720, 480)
        window.transient(self)
        window.configure(fg_color=theme_module.THEME["bg"])

        header = ctk.CTkLabel(
            window,
            text=(
                f"Пакетов {len(stream.packets)} · длительность {stream.duration:.3f} с · клиент -> сервер {stream.client_to_server.stream.length} байт · "
                f"сервер -> клиент {stream.server_to_client.stream.length} байт"
            ),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        )
        header.pack(fill="x", padx=14, pady=(12, 4))

        controls = ctk.CTkFrame(
            window,
            fg_color=theme_module.THEME["panel"],
            corner_radius=10,
            border_width=1,
            border_color=theme_module.THEME["border"],
        )
        controls.pack(fill="x", padx=14, pady=6)

        view_switch = ctk.CTkSegmentedButton(
            controls,
            values=["Оба", "Клиент → сервер", "Сервер → клиент"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=theme_module.THEME["accent"],
            selected_hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["text"],
            fg_color=theme_module.THEME["button"],
        )
        view_switch.set("Оба")
        view_switch.grid(row=0, column=0, padx=(12, 8), pady=8, sticky="w")

        mode_switch = ctk.CTkSegmentedButton(
            controls,
            values=["Текст", "HEX"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=theme_module.THEME["accent"],
            selected_hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["text"],
            fg_color=theme_module.THEME["button"],
        )
        mode_switch.set("Текст")
        mode_switch.grid(row=0, column=1, padx=(8, 12), pady=8, sticky="w")

        textbox = ctk.CTkTextbox(
            window,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
            fg_color=theme_module.THEME["panel"],
            border_color=theme_module.THEME["border"],
            border_width=1,
            text_color=theme_module.THEME["text"],
        )
        textbox.pack(fill="both", expand=True, padx=14, pady=6)

        buttons = ctk.CTkFrame(window, fg_color="transparent")
        buttons.pack(fill="x", padx=14, pady=(0, 12))

        def current_view() -> str:
            value = view_switch.get()
            if value.startswith("Клиент"):
                return VIEW_CLIENT
            if value.startswith("Сервер"):
                return VIEW_SERVER
            return VIEW_BOTH

        def current_mode() -> str:
            return MODE_HEX if mode_switch.get() == "HEX" else MODE_TEXT

        def render(*_args) -> None:
            text = render_stream(stream, view=current_view(), mode=current_mode())
            textbox.configure(state="normal")
            textbox.delete("1.0", "end")
            textbox.insert("1.0", text)
            textbox.configure(state="disabled")

        def copy_text() -> None:
            window.clipboard_clear()
            window.clipboard_append(textbox.get("1.0", "end-1c"))
            copy_button.configure(text="Скопировано")
            window.after(1500, lambda: copy_button.configure(text="Копировать"))

        def save_text() -> None:
            stem = f"stream_{_safe_stem(format_endpoint(stream.client))}_{_safe_stem(format_endpoint(stream.server))}"
            path = filedialog.asksaveasfilename(
                parent=window,
                title="Сохранить поток",
                defaultextension=".txt",
                initialfile=f"{stem}.txt",
                filetypes=[("Текст", "*.txt"), ("Все файлы", "*.*")],
            )
            if not path:
                return
            try:
                Path(path).write_text(
                    textbox.get("1.0", "end-1c"), encoding="utf-8"
                )
            except OSError as exc:
                messagebox.showerror(
                    APP_TITLE,
                    f"Не удалось сохранить файл:\n\n{exc}",
                    parent=window,
                )
                return
            self._set_status(f"Поток сохранён: {path}")

        copy_button = ctk.CTkButton(
            buttons,
            text="Копировать",
            width=130,
            height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=theme_module.THEME["accent"],
            hover_color=theme_module.THEME["accent_hover"],
            text_color=theme_module.THEME["accent_text"],
            command=copy_text,
        )
        copy_button.pack(side="left")

        self._secondary_button(
            buttons, "Сохранить в файл", save_text, width=150
        ).pack(side="left", padx=8)

        view_switch.configure(command=render)
        mode_switch.configure(command=render)
        render()

        # Ссылки для тестов и для отладки из консоли.
        window.stream_textbox = textbox
        window.stream_view_switch = view_switch
        window.stream_mode_switch = mode_switch
        window.stream_render = render

        def close_window() -> None:
            # Отложенное закрытие: отложенные callbacks customtkinter успевают
            # отработать на живом окне, иначе Tk ругается в stderr.
            window.withdraw()
            window.after(150, window.destroy)

        window.protocol("WM_DELETE_WINDOW", close_window)

        window.after(50, window.lift)
        window.after(100, window.focus_force)

    def _show_help(self) -> None:
        window = ctk.CTkToplevel(self)
        window.title("Как пользоваться — Smart PCAP Parser")
        window.geometry("860x740")
        window.transient(self)
        window.configure(fg_color=theme_module.THEME["bg"])

        header = ctk.CTkFrame(window, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            header,
            text="Справка",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=theme_module.THEME["text"],
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            header,
            text="Три шага, команды, колонки, статистика, детали и клавиши.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=theme_module.THEME["muted"],
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))

        textbox = ctk.CTkTextbox(
            window,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
            fg_color=theme_module.THEME["panel"],
            border_color=theme_module.THEME["border"],
            border_width=1,
            text_color=theme_module.THEME["text"],
        )
        textbox.pack(fill="both", expand=True, padx=16, pady=12)
        textbox.insert("1.0", HELP_TEXT)
        textbox.configure(state="disabled")

        window.after(50, window.lift)
        window.after(100, window.focus_force)
