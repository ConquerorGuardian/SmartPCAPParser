"""
Смоук-тест графического интерфейса.

Создаёт окно, скрывает его, прогоняет полный сценарий
(загрузка файла -> команда -> фильтр -> таблица -> «Показать все»)
и отдельно проверяет окно потока TCP.
Запуск: python -m tests.test_gui_smoke
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

SAMPLE = Path(__file__).parent / "sample_traffic.pcap"


def shutdown(app) -> None:
    """Закрывает приложение, снимая отложенные callbacks.

    Без этого Tk печатает в stderr «invalid command name ...» после destroy.
    """
    try:
        for after_id in app.tk.splitlist(app.tk.call("after", "info")):
            try:
                app.after_cancel(after_id)
            except Exception:  # noqa: BLE001
                pass
    finally:
        app.destroy()


def run_flow() -> None:
    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        packets, error = app.handler.load(SAMPLE)
        assert error is None, error
        app.pcap_path = SAMPLE
        app.packets = packets
        app.file_label.configure(text=str(SAMPLE))
        app.packet_label.configure(text=f"Пакетов: {len(packets)}")
        app.update()

        app.command_entry.insert(0, "покажи http трафик")
        app._apply_command()
        app.update()

        assert app.current_filter == "http", app.current_filter
        assert app.current_result is not None
        assert app.current_result.matched_packets == 2
        assert len(app.tree.get_children()) == 2, len(app.tree.get_children())

        app._show_all()
        app.update()
        assert len(app.tree.get_children()) == 2

        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "покажи пакеты на порт 80 и 443")
        app._apply_command()
        app.update()
        assert app.current_filter == "tcp.port==80,443", app.current_filter
        assert app.current_result.matched_packets == 5
        assert len(app.tree.get_children()) == 5

        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "просто текст без индикаторов")
        app._apply_command()
        app.update()
        assert "Не нашёл сетевых индикаторов" in app.status_label.cget("text")

        # Кнопка-чип быстрого фильтра + запись в историю.
        app._run_quick_filter("покажи dns трафик")
        app.update()
        assert app.command_entry.get() == "покажи dns трафик"
        assert app.current_filter == "dns", app.current_filter
        assert app.current_result is not None
        assert app.current_result.matched_packets == 2, app.current_result.matched_packets
        assert app._history[0] == "покажи dns трафик", app._history
        assert len(app.history_frame.winfo_children()) == len(app._history), (
            "история не обновилась"
        )

        # Колонки портов и сортировка по заголовку.
        from parser.pcap_handler import COLUMNS

        assert "Src Port" in COLUMNS and "Dst Port" in COLUMNS, COLUMNS
        first_row = app.tree.item(app.tree.get_children()[0], "values")
        assert first_row[COLUMNS.index("Src Port")].isdigit(), first_row

        app._on_heading_click("Frame")
        frames = [
            int(app.tree.item(item, "values")[0])
            for item in app.tree.get_children()
        ]
        assert frames == sorted(frames), frames
        app._on_heading_click("Frame")          # повторный клик — реверс
        frames = [
            int(app.tree.item(item, "values")[0])
            for item in app.tree.get_children()
        ]
        assert frames == sorted(frames, reverse=True), frames

        # Быстрые фильтры: частые протоколы, все команды рабочие.
        from gui import app as gui_app

        labels = [label for label, _ in gui_app.QUICK_FILTERS]
        assert labels[:10] == [
            "TCP", "UDP", "ICMP", "DNS", "DHCP", "ARP", "HTTP", "TLS", "QUIC", "SSH"
        ], labels
        for label, command in gui_app.QUICK_FILTERS:
            query = app.engine.parse(command)
            filter_string = gui_app.generate_filter(query)
            assert filter_string, f"{label}: команда «{command}» ничего не даёт"
            gui_app.compile_filter(filter_string)

        # Живая подсказка: что понято из введённой команды.
        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "покажи http трафик с айпи 192.168.1.10")
        app._update_command_hint()
        hint = app.hint_label.cget("text")
        assert hint.startswith("→"), hint
        assert "ip.addr==192.168.1.10" in hint, hint

        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "абракадабра")
        app._update_command_hint()
        assert "Не нашёл" in app.hint_label.cget("text"), app.hint_label.cget("text")

        # Точная причина, если ввод похож на индикатор, но сломан.
        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "покажи айпи 192.168.1.999")
        app._update_command_hint()
        assert "некорректен" in app.hint_label.cget("text"), app.hint_label.cget("text")

        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "покажи порт 99999")
        app._update_command_hint()
        assert "вне диапазона" in app.hint_label.cget("text"), app.hint_label.cget("text")

        # Отрицание теперь поддерживается — подсказка показывает фильтр.
        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "не http")
        app._update_command_hint()
        assert app.hint_label.cget("text") == "→ not (http)", app.hint_label.cget("text")

        # Сломанный IPv6 объясняется отдельно.
        app.command_entry.delete(0, "end")
        app.command_entry.insert(0, "покажи айпи 2001:db8:::1")
        app._update_command_hint()
        assert "IPv6" in app.hint_label.cget("text"), app.hint_label.cget("text")

        # Клик по примеру: текст подставлен, переменная часть выделена.
        app._use_example("покажи пакеты на порт 80")
        assert app.command_entry.get() == "покажи пакеты на порт 80"
        selected = app.command_entry.selection_get()
        assert selected == "80", selected

        # Пятёрка примеров листается.
        before = list(app._examples_shown)
        app._shuffle_examples()
        assert len(app._examples_shown) == gui_app.EXAMPLES_VISIBLE
        assert app._examples_shown != before

        # Стирание команды возвращает все пакеты файла.
        filtered_rows = len(app.tree.get_children())
        assert filtered_rows < len(packets), filtered_rows
        app.command_entry.delete(0, "end")
        app._on_command_key()
        app.update()
        assert app.current_filter == "", app.current_filter
        assert app.filter_entry.get() == "", app.filter_entry.get()
        assert len(app.tree.get_children()) == len(packets), (
            len(app.tree.get_children()), len(packets)
        )
        assert "все пакеты" in app.status_label.cget("text").lower(), (
            app.status_label.cget("text")
        )

        # Повторный фильтр и Esc — тот же эффект.
        app._run_quick_filter("покажи dns трафик")
        app.update()
        assert app.current_filter == "dns"
        app._clear_command()
        app.update()
        assert app.current_filter == ""
        assert app.command_entry.get() == ""
        assert len(app.tree.get_children()) == len(packets)

        # «Сброс фильтра» — то же, что Esc.
        app._run_quick_filter("покажи tcp трафик")
        app.update()
        assert app.current_filter == "tcp"
        app._clear_command()
        app.update()
        assert app.current_filter == ""
        assert len(app.tree.get_children()) == len(packets)

        print("PASS: test_gui_flow")
    finally:
        shutdown(app)


def run_stream_flow() -> None:
    """Кнопка «Поток TCP»: окно открывается, данные склеены, переключатели работают."""
    import customtkinter as ctk

    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        packets, error = app.handler.load(SAMPLE, keep_payload=True)
        assert error is None, error
        app.pcap_path = SAMPLE
        app.packets = packets
        app._render(app.handler.apply(packets, "", limit=200))
        app.update()

        def select_frame(number: int):
            for item in app.tree.get_children():
                if str(app.tree.item(item, "values")[0]) == str(number):
                    app.tree.selection_set(item)
                    app.update()
                    return item
            return None

        assert select_frame(6) is not None
        assert app._selected_frame() == 6

        app._follow_selected_stream()
        app.update()

        windows = [
            child for child in app.winfo_children()
            if isinstance(child, ctk.CTkToplevel)
        ]
        assert windows, "окно потока не открылось"
        window = windows[-1]

        text = window.stream_textbox.get("1.0", "end-1c")
        assert "GET /index.html HTTP/1.1" in text, text[:200]
        assert "HTTP/1.1 200 OK" in text

        # Переключение на одно направление.
        window.stream_view_switch.set("Клиент → сервер")
        window.stream_render()
        client_text = window.stream_textbox.get("1.0", "end-1c")
        assert "GET /index.html" in client_text
        assert "HTTP/1.1 200 OK" not in client_text

        # HEX-режим.
        window.stream_mode_switch.set("HEX")
        window.stream_render()
        hex_text = window.stream_textbox.get("1.0", "end-1c")
        assert "47 45 54 20" in hex_text, hex_text[:200]      # "GET " в hex

        # Не-TCP пакет: окно не открывается, в статусе понятное объяснение.
        windows_before = len(
            [c for c in app.winfo_children() if isinstance(c, ctk.CTkToplevel)]
        )
        assert select_frame(9) is not None
        app._follow_selected_stream()
        assert "не TCP" in app.status_label.cget("text"), app.status_label.cget("text")
        windows_after = len(
            [c for c in app.winfo_children() if isinstance(c, ctk.CTkToplevel)]
        )
        assert windows_after == windows_before, "не-TCP не должен открывать окно"

        window.destroy()

        print("PASS: test_gui_stream")
    finally:
        shutdown(app)


def run_stats_flow() -> None:
    """Вкладка «Статистика» и окно деталей пакета."""
    import customtkinter as ctk

    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        packets, error = app.handler.load(SAMPLE, keep_payload=True)
        assert error is None, error
        app.pcap_path = SAMPLE
        app.packets = packets
        app.packet_index = {packet.number: packet for packet in packets}
        app._render(app.handler.apply(packets, "", limit=200))
        app.update()

        app.command_entry.insert(0, "покажи http трафик")
        app._apply_command()
        app.update()

        # Вкладка статистики считается по всему файлу.
        app._show_view("stats")
        app.update()
        assert app._current_view == "stats"
        assert app.packets_view.winfo_manager() == "", app.packets_view.winfo_manager()

        top_rows = app.proto_tree.get_children()
        assert top_rows, "иерархия протоколов пуста"
        labels = [app.proto_tree.item(item, "text") for item in top_rows]
        assert "Всего" in labels, labels
        total_item = top_rows[labels.index("Всего")]
        total_packets = int(app.proto_tree.item(total_item, "values")[0])
        assert total_packets == len(packets), (total_packets, len(packets))

        # В иерархии есть вложенные прикладные протоколы.
        nested = [
            child for item in top_rows
            for child in app.proto_tree.get_children(item)
        ]
        assert nested, "нет вложенных прикладных протоколов"

        assert app.conv_tree.get_children(), "разговоры не посчитаны"
        assert app.endpoint_tree.get_children(), "узлы не посчитаны"

        # Панель «Сайты и хосты» заполняется именами из HTTP/DNS/TLS.
        host_rows = app.host_tree.get_children()
        assert host_rows, "сайты и хосты не посчитаны"
        host_names = [app.host_tree.item(item, "text") for item in host_rows]
        assert "example.com" in host_names, host_names

        # График трафика: бакеты по всему файлу и хоть одна нарисованная фигура.
        app.update()
        assert app.chart.buckets, "график пуст"
        assert sum(bucket.packets for bucket in app.chart.buckets) == len(packets)
        assert app.chart.find_all(), "график не нарисован"
        app.chart_metric.set("Пакеты")
        app._refresh_chart()
        app.update()
        assert app.chart.metric == "packets"
        app.chart_metric.set("Байты")
        app._refresh_chart()

        # Область «Найденные» — только пакеты под фильтром http.
        app.stats_scope.set("Найденные")
        app._refresh_stats()
        app.update()
        labels = [
            app.proto_tree.item(item, "text")
            for item in app.proto_tree.get_children()
        ]
        total_item = app.proto_tree.get_children()[labels.index("Всего")]
        assert int(app.proto_tree.item(total_item, "values")[0]) == 2, (
            app.proto_tree.item(total_item, "values")
        )

        # Детали пакета.
        app._show_view("packets")
        for item in app.tree.get_children():
            if str(app.tree.item(item, "values")[0]) == "6":
                app.tree.selection_set(item)
                break
        app._show_packet_details()
        app.update()

        windows = [
            child for child in app.winfo_children()
            if isinstance(child, ctk.CTkToplevel)
        ]
        assert windows, "окно деталей не открылось"
        window = windows[-1]

        layers = [
            window.field_tree.item(item, "text")
            for item in window.field_tree.get_children()
        ]
        assert "Frame" in layers, layers
        assert "Ethernet" in layers, layers
        assert "IP" in layers, layers
        assert "TCP" in layers, layers

        payload = window.payload_box.get("1.0", "end-1c")
        assert "47 45 54" in payload, payload[:200]      # "GET" в hex-дампе

        window.destroy()
        print("PASS: test_gui_stats")
    finally:
        shutdown(app)


def run_theme_flow() -> None:
    """Смена темы не теряет файл, фильтр и строки таблицы."""
    import time

    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        packets, error = app.handler.load(SAMPLE)
        assert error is None, error
        app.pcap_path = SAMPLE
        app.packets = packets
        app.file_label.configure(text=SAMPLE.name)
        app._render(app.handler.apply(packets, "", limit=200))
        app.update()

        app.command_entry.insert(0, "покажи dns трафик")
        app._apply_command()
        app.update()
        rows_before = len(app.tree.get_children())
        assert rows_before == 2, rows_before

        app._set_theme("light")
        for _ in range(30):
            app.update()
            if app.theme_name == "light" and app.winfo_children():
                time.sleep(0.01)
            if getattr(app, "tree", None) is not None and app.tree.get_children():
                break

        assert app.theme_name == "light"
        assert app.file_label.cget("text") == SAMPLE.name, app.file_label.cget("text")
        assert app.current_filter == "dns", app.current_filter
        assert len(app.tree.get_children()) == rows_before, len(app.tree.get_children())
        assert app.command_entry.get() == "покажи dns трафик"

        # Обратно в тёмную.
        app._set_theme("dark")
        for _ in range(30):
            app.update()
            if app.tree.get_children():
                break
        assert app.theme_name == "dark"
        assert len(app.tree.get_children()) == rows_before

        print("PASS: test_gui_theme")
    finally:
        shutdown(app)


def pump(app, predicate, timeout: float = 8.0) -> bool:
    """Крутит цикл событий, пока условие не выполнится или не выйдет время."""
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        app.update()
        if predicate():
            return True
        time.sleep(0.02)
    return False


def run_verdict_flow() -> None:
    """Вердикт по файлу, кнопка «пример дампа» и фильтр по значению ячейки."""
    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        # Кнопка «Открыть пример дампа» поднимает встроенный файл.
        app._load_sample()
        assert pump(app, lambda: bool(app.packets)), "пример дампа не загрузился"
        assert app.pcap_path is not None and app.pcap_path.name == "sample_traffic.pcap"
        assert len(app.packets) == 13, len(app.packets)

        # Вердикт показан и говорит словами.
        assert app.verdict_panel.winfo_manager() == "grid", "панель вердикта скрыта"
        headline = app.verdict_title.cget("text")
        assert "пакетов" in headline, headline
        assert app.verdict_overview.cget("text"), "обзор пустой"
        assert app.verdict.findings, "нет находок"
        assert app.verdict_findings.winfo_children(), "находки не отрисованы"

        # Находка с командой действительно применяется.
        with_command = [f for f in app.verdict.findings if f.command]
        if with_command:
            app._run_quick_filter(with_command[0].command)
            app.update()
            assert app.current_filter, "фильтр из находки не применился"

        # Фильтр по значению ячейки — без набора команды.
        app._filter_by("src", "192.168.1.10")
        app.update()
        assert app.command_entry.get() == "покажи пакеты от 192.168.1.10", (
            app.command_entry.get()
        )
        assert app.current_filter == "ip.src==192.168.1.10", app.current_filter
        assert len(app.tree.get_children()) > 0

        app._filter_by("port", "80")
        app.update()
        assert "80" in app.current_filter, app.current_filter

        app._filter_by("proto", "TCP")
        app.update()
        assert app.current_filter == "tcp", app.current_filter

        # MAC-адрес из ARP-строки превращается в фильтр по MAC.
        app._filter_by("src", "aa:bb:cc:dd:ee:ff")
        app.update()
        assert app.command_entry.get() == "покажи пакеты с мак адресом aa:bb:cc:dd:ee:ff"
        assert "eth.addr" in app.current_filter, app.current_filter

        print("PASS: test_gui_verdict")
    finally:
        shutdown(app)


def run_layout_flow() -> None:
    """Маленькое окно: панель прокручивается, ключевые блоки не пропадают."""
    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        # Ноутбук 1366x768: рабочая область по высоте около 620 px.
        app.geometry("1080x620")
        app.deiconify()
        app.update()

        minimum = app.wm_minsize()
        assert tuple(minimum) == (1080, 620), minimum
        assert app.sidebar_scroll.winfo_ismapped(), "боковая панель не показана"
        assert app.sidebar_scroll.winfo_height() > 100, app.sidebar_scroll.winfo_height()
        assert app.theme_switch.winfo_ismapped(), "переключатель темы пропал"
        assert app.command_entry.winfo_ismapped(), "поле команды пропало"
        assert app.tree.winfo_ismapped(), "таблица не показана"
        assert app.tree.winfo_height() > 80, app.tree.winfo_height()
        app.withdraw()
    finally:
        shutdown(app)


def write_big_pcap(path, count: int) -> None:
    """Пишет pcap с count одинаковыми TCP-пакетами — для проверки больших файлов."""
    import struct

    eth = bytes.fromhex("aabbccddeeff1122334455660800")
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0x4000, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", 12345, 80, 1, 0, 0x50, 0x18, 8192, 0, 0)
    frame = eth + ipv4 + tcp

    with open(path, "wb") as handle:
        handle.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index in range(count):
            handle.write(struct.pack("!IIII", 1_700_000_000 + index, 0,
                                     len(frame), len(frame)))
            handle.write(frame)


def run_search_flow() -> None:
    """Поиск по таблице (Ctrl+F): находит, считает, снимается Esc."""
    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        packets, error = app.handler.load(SAMPLE)
        assert error is None, error
        app.pcap_path = SAMPLE
        app.packets = packets
        app._render(app.handler.apply(packets, ""))
        app.update()

        total = len(app.tree.get_children())
        assert total == 13, total

        expected = sum(1 for row in app._rows if "http" in app._row_text(row).lower())
        assert expected >= 2, expected

        app.search_entry.insert(0, "http")
        app._apply_search()
        app.update()
        assert len(app.tree.get_children()) == expected, (
            len(app.tree.get_children()), expected)
        assert "из 13" in app.search_label.cget("text"), app.search_label.cget("text")
        assert "Поиск" in app.status_label.cget("text")

        # Поиск по адресу и по номеру порта.
        app.search_entry.delete(0, "end")
        app.search_entry.insert(0, "8.8.8.8")
        app._apply_search()
        app.update()
        assert len(app.tree.get_children()) >= 1
        app.search_entry.delete(0, "end")
        app.search_entry.insert(0, "443")
        app._apply_search()
        app.update()
        assert len(app.tree.get_children()) >= 1

        # Esc снимает поиск и возвращает все строки.
        app._clear_search()
        app.update()
        assert len(app.tree.get_children()) == total, len(app.tree.get_children())
        assert app.search_label.cget("text") == ""
        assert "Поиск снят" in app.status_label.cget("text")

        # Поиск работает поверх фильтра и не подменяет сам фильтр.
        app.command_entry.insert(0, "покажи tcp трафик")
        app._apply_command()
        app.update()
        assert app.current_filter == "tcp"
        filtered = len(app.tree.get_children())
        app.search_entry.insert(0, "80")
        app._apply_search()
        app.update()
        assert app.current_filter == "tcp", app.current_filter
        assert len(app.tree.get_children()) <= filtered

        # Новый фильтр начинает поиск с чистого листа.
        app._apply_command()
        app.update()
        assert app.search_entry.get() == "", app.search_entry.get()
        assert app._search_text == ""
    finally:
        shutdown(app)


def run_export_flow() -> None:
    """Экспорт CSV: сохраняется ровно то, что видно, включая поиск."""
    from gui import app as gui_app
    from gui.app import SmartPcapApp

    out = Path(__file__).parent / "_export_test.csv"
    out.unlink(missing_ok=True)
    original = gui_app.filedialog.asksaveasfilename

    app = SmartPcapApp()
    app.withdraw()
    try:
        packets, error = app.handler.load(SAMPLE)
        assert error is None, error
        app.pcap_path = SAMPLE
        app.packets = packets
        app._render(app.handler.apply(packets, ""))
        app.update()

        gui_app.filedialog.asksaveasfilename = lambda **kwargs: str(out)

        app.search_entry.insert(0, "http")
        app._apply_search()
        app.update()
        expected = len(app.tree.get_children())
        assert expected >= 2, expected

        app._export_csv()
        app.update()
        assert out.exists(), "CSV не создан"
        lines = out.read_text(encoding="utf-8").splitlines()
        assert len(lines) == expected + 1, (len(lines), expected)
        assert "поиск" in app.status_label.cget("text").lower()

        # Без поиска в файл уходят все строки текущего фильтра.
        app._clear_search()
        app.update()
        out.unlink()
        app._export_csv()
        app.update()
        lines = out.read_text(encoding="utf-8").splitlines()
        assert len(lines) == len(app._rows) + 1, (len(lines), len(app._rows))
    finally:
        gui_app.filedialog.asksaveasfilename = original
        shutdown(app)
        out.unlink(missing_ok=True)


def run_big_file_flow() -> None:
    """Файл на 9 000 пакетов: в таблице не 200 строк, а весь файл."""
    from gui.app import VIEW_LIMIT, SmartPcapApp

    path = Path(__file__).parent / "_big_test.pcap"
    write_big_pcap(path, 9000)

    app = SmartPcapApp()
    app.withdraw()
    try:
        # Читаем синхронно (тот же код, что в фоновом потоке), затем
        # обрабатываем результат как обычно — без гонок с таймерами.
        app._load_worker(path)
        app._poll_load()
        app.update()

        assert len(app.packets) == 9000, len(app.packets)
        rows = len(app.tree.get_children())
        assert rows == 9000, f"в таблице {rows} строк вместо 9000"
        assert VIEW_LIMIT >= 9000

        status = app.status_label.cget("text")
        assert "9 000" in status, status
        assert "Показаны все" in status, status

        # Фильтр тоже показывает все совпадения, а не первые 200.
        app.command_entry.insert(0, "покажи tcp трафик")
        app._apply_command()
        app.update()
        assert len(app.tree.get_children()) == 9000
        assert app.current_result.matched_packets == 9000
    finally:
        shutdown(app)
        # Windows иногда держит файл ещё мгновение после чтения в другом потоке.
        import time

        for _ in range(20):
            try:
                path.unlink()
                break
            except OSError:
                time.sleep(0.05)


def run_pagination_flow() -> None:
    """Большой результат листается страницами, поиск и сортировка сбрасывают страницу."""
    from gui import table_view
    from gui.app import SmartPcapApp

    path = Path(__file__).parent / "_pages_test.pcap"
    write_big_pcap(path, 25)

    saved_limit, saved_page = table_view.VIEW_LIMIT, table_view.PAGE_SIZE
    table_view.VIEW_LIMIT = 20
    table_view.PAGE_SIZE = 10

    app = SmartPcapApp()
    app.withdraw()
    try:
        app._load_worker(path)
        app._poll_load()
        app.update()

        assert len(app.packets) == 25, len(app.packets)
        assert len(app.tree.get_children()) == 10, len(app.tree.get_children())
        assert "Стр. 1 из 3" in app.page_label.cget("text"), app.page_label.cget("text")

        app._go_page(1)
        app.update()
        assert len(app.tree.get_children()) == 10
        assert "Стр. 2 из 3" in app.page_label.cget("text")

        app._page_last()
        app.update()
        assert len(app.tree.get_children()) == 5, len(app.tree.get_children())

        # Сортировка и поиск начинают с первой страницы.
        app._on_heading_click("Frame")
        app.update()
        assert app._page == 1, app._page

        app._go_page(1)
        app.search_entry.insert(0, "tcp")
        app._apply_search()
        app.update()
        assert app._page == 1, app._page
        assert len(app.tree.get_children()) == 10
    finally:
        table_view.VIEW_LIMIT, table_view.PAGE_SIZE = saved_limit, saved_page
        shutdown(app)
        path.unlink(missing_ok=True)


def run_recent_flow() -> None:
    """Недавние файлы: запоминаются, не дублируются, пропавшие убираются."""
    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    missing = Path(__file__).parent / "_no_such_capture.pcap"
    try:
        app._load_worker(SAMPLE)
        app._poll_load()
        app.update()

        assert app._recent and app._recent[0].endswith("sample_traffic.pcap"), app._recent
        labels = [str(value) for value in app.recent_menu.cget("values")]
        assert any("sample_traffic.pcap" in label for label in labels), labels

        app._load_worker(SAMPLE)
        app._poll_load()
        app.update()
        assert sum(1 for item in app._recent if item.endswith("sample_traffic.pcap")) == 1

        app._recent.insert(0, str(missing))
        app._refresh_recent_menu()
        label = next(
            text for text, path in app._recent_map.items() if path == str(missing)
        )
        app._open_recent(label)
        app.update()
        assert all("_no_such_capture" not in item for item in app._recent), app._recent
        assert "не существует" in app.status_label.cget("text")
    finally:
        shutdown(app)


def run_cancel_load_flow() -> None:
    """Отмена чтения: статус без диалога ошибки и без падения."""
    from gui import app as gui_app

    app = gui_app.SmartPcapApp()
    app.withdraw()
    original = gui_app.messagebox.showerror

    def boom(*args, **kwargs):
        raise AssertionError("при отмене не должно быть диалога ошибки")

    gui_app.messagebox.showerror = boom
    try:
        app._load_cancel.set()
        app._load_queue.put((SAMPLE, [], "Чтение отменено"))
        app._poll_load()
        app.update()
        assert "отменено" in app.status_label.cget("text").lower(), (
            app.status_label.cget("text")
        )
        assert app.packets == [], app.packets
    finally:
        gui_app.messagebox.showerror = original
        shutdown(app)


def test_table_limit_rule() -> None:
    """Правило «показывать всё или первую страницу» — на границах."""
    from gui.app import PREVIEW_COUNT, VIEW_LIMIT, table_limit

    assert table_limit(0) == -1
    assert table_limit(200) == -1
    assert table_limit(9000) == -1
    assert table_limit(VIEW_LIMIT) == -1
    assert table_limit(VIEW_LIMIT + 1) == PREVIEW_COUNT
    print("PASS: test_table_limit_rule")


def run_lazy_stream_flow() -> None:
    """Большой файл: тела TCP подгружаются по требованию при открытии потока."""
    import customtkinter as ctk

    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        # keep_payload=False — как для файла больше 25 МБ.
        packets, error = app.handler.load(SAMPLE, keep_payload=False)
        assert error is None, error
        assert all(not packet.payload for packet in packets)

        app.pcap_path = SAMPLE
        app.packets = packets
        app.packet_index = {packet.number: packet for packet in packets}
        app._render(app.handler.apply(packets, "", limit=200))
        app.update()

        for item in app.tree.get_children():
            if str(app.tree.item(item, "values")[0]) == "6":
                app.tree.selection_set(item)
                break
        app.update()
        assert app._selected_frame() == 6

        app._follow_selected_stream()
        app.update()

        # Данные дочитались из файла только для этого соединения.
        assert packets[5].payload, "данные кадра 6 не подгрузились"
        assert not any(packet.payload for packet in packets[:4]), (
            "подгрузились лишние кадры"
        )

        windows = [
            child for child in app.winfo_children()
            if isinstance(child, ctk.CTkToplevel)
        ]
        assert windows, "окно потока не открылось"
        text = windows[-1].stream_textbox.get("1.0", "end-1c")
        assert "GET /index.html HTTP/1.1" in text, text[:200]
        windows[-1].destroy()
    finally:
        shutdown(app)
    print("PASS: run_lazy_stream_flow")


def run_udp_stream_flow() -> None:
    """«Поток UDP»: по UDP-пакету открывается окно с датаграммами."""
    import customtkinter as ctk

    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        packets, error = app.handler.load(SAMPLE, keep_payload=True)
        assert error is None, error
        app.pcap_path = SAMPLE
        app.packets = packets
        app.packet_index = {packet.number: packet for packet in packets}
        app._render(app.handler.apply(packets, "", limit=200))
        app.update()

        for item in app.tree.get_children():
            if str(app.tree.item(item, "values")[0]) == "2":
                app.tree.selection_set(item)
                break
        app.update()
        assert app._selected_frame() == 2

        app._follow_selected_stream()
        app.update()

        windows = [
            child for child in app.winfo_children()
            if isinstance(child, ctk.CTkToplevel)
        ]
        assert windows, "окно потока UDP не открылось"
        window = windows[-1]
        assert "Поток UDP" in window.title(), window.title()
        assert "8.8.8.8:53" in window.title(), window.title()

        window.stream_mode_switch.set("HEX")
        window.stream_render()
        app.update()
        assert window.stream_textbox.get("1.0", "end-1c").strip(), "поток пуст"
        window.destroy()
    finally:
        shutdown(app)
    print("PASS: run_udp_stream_flow")


def run_initial_file_flow() -> None:
    """Файл, переданный в конструктор, открывается сам (аргумент exe)."""
    import time

    from gui.app import SmartPcapApp

    app = SmartPcapApp(initial_file=str(SAMPLE))
    app.withdraw()
    try:
        assert "Smart PCAP Parser" in app.title(), app.title()
        deadline = time.time() + 15
        while time.time() < deadline and not app.packets:
            app.update()
            time.sleep(0.05)
        assert app.pcap_path == SAMPLE, app.pcap_path
        assert len(app.packets) == 13, len(app.packets)
        assert len(app.tree.get_children()) >= 13, len(app.tree.get_children())
        assert SAMPLE.name in app.title(), app.title()
    finally:
        shutdown(app)
    print("PASS: run_initial_file_flow")


def run_missing_file_flow() -> None:
    """Несуществующий файл из аргументов не роняет окно."""
    from gui.app import SmartPcapApp

    app = SmartPcapApp()
    app.withdraw()
    try:
        app._open_initial_file(Path("нет-такого-файла.pcap"))
        app.update()
        assert app.packets == []
        assert "не найден" in app.status_label.cget("text").lower()
    finally:
        shutdown(app)
    print("PASS: run_missing_file_flow")


def display_available() -> bool:
    """Проверяет, можно ли вообще открыть окно (на серверах без экрана — нет)."""
    try:
        import tkinter

        root = tkinter.Tk()
        root.destroy()
        return True
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    try:
        import customtkinter  # noqa: F401
    except ImportError as exc:
        print("SKIP: customtkinter не установлен:", exc)
        sys.exit(0)

    if not display_available():
        print("SKIP: нет графического дисплея (тест GUI пропущен)")
        sys.exit(0)

    test_table_limit_rule()

    flows = [
        run_flow, run_stream_flow, run_stats_flow, run_theme_flow, run_verdict_flow,
        run_search_flow, run_export_flow, run_layout_flow, run_big_file_flow,
        run_lazy_stream_flow, run_udp_stream_flow, run_pagination_flow,
        run_recent_flow, run_cancel_load_flow, run_initial_file_flow,
        run_missing_file_flow,
    ]
    failed = 0
    for flow in flows:
        try:
            flow()
        except AssertionError as exc:
            print(f"FAIL: {flow.__name__}:", exc)
            failed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: {flow.__name__}:", exc)
            failed += 1

    print("")
    print("-" * 40)
    print(f"Пройдено: {len(flows) - failed}/{len(flows)}")
    if failed:
        sys.exit(1)
    print("Все тесты прошли!")
