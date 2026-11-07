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


def _print_window(widget):
    """Снимает окно через PrintWindow: без чужих окон и краёв рабочего стола."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    user32.GetDC.argtypes = [wintypes.HWND]
    user32.GetDC.restype = wintypes.HDC
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateDIBSection.restype = wintypes.HANDLE
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HANDLE]
    gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
    gdi32.DeleteDC.argtypes = [wintypes.HDC]

    class BitmapInfoHeader(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    class BitmapInfo(ctypes.Structure):
        _fields_ = [("bmiHeader", BitmapInfoHeader),
                    ("bmiColors", wintypes.DWORD * 3)]

    gdi32.CreateDIBSection.argtypes = [
        wintypes.HDC,
        ctypes.POINTER(BitmapInfo),
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.HANDLE,
        wintypes.DWORD,
    ]

    hwnd = widget.winfo_id()
    rect = wintypes.RECT()
    user32.GetClientRect(hwnd, ctypes.byref(rect))
    width, height = rect.right, rect.bottom
    if width < 50 or height < 50:
        raise RuntimeError(f"окно {width}x{height}")

    bmi = BitmapInfo()
    bmi.bmiHeader.biSize = ctypes.sizeof(BitmapInfoHeader)
    bmi.bmiHeader.biWidth = width
    bmi.bmiHeader.biHeight = -height
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32

    hdc = user32.GetDC(hwnd)
    memory_dc = gdi32.CreateCompatibleDC(hdc)
    bits = ctypes.c_void_p()
    bitmap = gdi32.CreateDIBSection(
        hdc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0
    )
    gdi32.SelectObject(memory_dc, bitmap)
    try:
        # 2 = PW_RENDERFULLCONTENT, иначе некоторые окна выходят чёрными.
        if not user32.PrintWindow(hwnd, memory_dc, 2):
            raise RuntimeError("PrintWindow вернул 0")
        buffer = ctypes.string_at(bits, width * height * 4)
    finally:
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(memory_dc)
        user32.ReleaseDC(hwnd, hdc)

    return Image.frombuffer(
        "RGBA", (width, height), buffer, "raw", "BGRA", 0, 1
    ).convert("RGB")


def grab(widget, name: str) -> None:
    widget.update_idletasks()
    pump(widget, 0.4)
    try:
        image = _print_window(widget)
    except Exception as exc:  # noqa: BLE001
        print("PrintWindow не сработал ({}), снимаю с экрана".format(exc))
        x, y = widget.winfo_rootx(), widget.winfo_rooty()
        width, height = widget.winfo_width(), widget.winfo_height()
        image = ImageGrab.grab(bbox=(x, y, x + width, y + height)).convert("RGB")
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
