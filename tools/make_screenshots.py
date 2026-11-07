"""Снимает картинки для docs/ из живого окна.

Запуск:  python tools/make_screenshots.py
Нужен экран (не сервер) и Pillow. Окно открывается на пару секунд само.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs"
SAMPLE = ROOT / "tests" / "sample_traffic.pcap"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".pylibs"))

from PIL import Image, ImageGrab  # noqa: E402


def pump(app, seconds: float = 0.4) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.update()
        time.sleep(0.02)


def wait_for(app, predicate, timeout: float = 30.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.update()
        if predicate():
            pump(app, 0.4)
            return True
        time.sleep(0.05)
    return False


def toplevels(app) -> list:
    import customtkinter as ctk

    return [child for child in app.winfo_children()
            if isinstance(child, ctk.CTkToplevel) and child.winfo_exists()]


def grab(widget, name: str) -> None:
    widget.update_idletasks()
    pump(widget, 0.3)
    x, y = widget.winfo_rootx(), widget.winfo_rooty()
    width, height = widget.winfo_width(), widget.winfo_height()
    if width < 200 or height < 200:
        raise RuntimeError(f"{name}: окно слишком маленькое ({width}x{height})")
    image = ImageGrab.grab(bbox=(x, y, x + width, y + height))
    # 256 цветов хватает для интерфейса, зато файл в разы легче. Без
    # дизеринга: он добавляет шум и раздувает png на пустом месте.
    image = image.convert("RGB").quantize(
        colors=256, method=Image.MEDIANCUT, dither=Image.NONE)
    path = OUT / name
    image.save(path, optimize=True)
    print("готово:", path.name, image.size,
          "{} КБ".format(round(path.stat().st_size / 1024)))


def select_frame(app, number: int) -> bool:
    for item in app.tree.get_children():
        if str(app.tree.item(item, "values")[0]) == str(number):
            app.tree.selection_set(item)
            pump(app, 0.2)
            return True
    return False


def main() -> int:
    try:
        from gui.app import SmartPcapApp
    except ImportError as exc:
        print("Нет customtkinter:", exc)
        return 1

    # Скриншоты не должны менять настройки человека, который их снимает.
    settings_file = Path.home() / ".smartpcapapp" / "settings.json"
    saved_settings = None
    if settings_file.exists():
        saved_settings = settings_file.read_bytes()

    app = SmartPcapApp()
    try:
        app.geometry("1380x820+40+40")
        app.lift()
        app._set_theme("dark")
        pump(app, 1.0)
        app.simple_switch.set(False)
        app._toggle_simple_mode()
        pump(app, 0.5)

        app._load_path(SAMPLE)
        if not wait_for(app, lambda: len(app.packets) == 13):
            print("Файл примера не загрузился")
            return 1

        grab(app, "screenshot.png")

        app.view_switch.set("Статистика")
        app._show_view("stats")
        pump(app, 1.0)
        grab(app, "stats.png")

        app.view_switch.set("Пакеты")
        app._show_view("packets")
        pump(app, 0.4)
        if select_frame(app, 6):
            app._show_packet_details()
            pump(app, 0.6)
            windows = toplevels(app)
            if windows:
                grab(windows[-1], "details.png")
                windows[-1].destroy()
                pump(app, 0.2)

        if select_frame(app, 6):
            app._follow_selected_stream()
            pump(app, 1.2)
            windows = toplevels(app)
            if windows:
                grab(windows[-1], "stream.png")
                windows[-1].destroy()
                pump(app, 0.2)

        app._show_verdict_window()
        pump(app, 1.0)
        windows = toplevels(app)
        if windows:
            grab(windows[-1], "verdict.png")
            windows[-1].destroy()
            pump(app, 0.2)

        app.simple_switch.set(True)
        app._toggle_simple_mode()
        pump(app, 0.8)
        grab(app, "simple.png")

        app._set_theme("light")
        pump(app, 1.2)
        grab(app, "theme-light.png")
    finally:
        try:
            app.destroy()
        except Exception:  # noqa: BLE001
            pass
        if saved_settings is not None:
            settings_file.write_bytes(saved_settings)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
