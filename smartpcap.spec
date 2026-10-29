# -*- mode: python ; coding: utf-8 -*-
"""Сборка Smart PCAP Parser в папку `dist/SmartPCAPParser`.

Запуск:  python tools/build_exe.py     (он же вызывает этот spec)

Особенности:
- `collect_all("customtkinter")` обязателен: без файлов темы CTk не стартует;
- внутрь кладём пример дампа, чтобы «Открыть пример дампа» работал в exe;
- `console=False` — оконное приложение без чёрной консоли;
- версия файла берётся из build/version_info.txt, если он есть.
"""

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(os.environ.get("SMARTPCAP_ROOT", ".")).resolve()

datas, binaries, hiddenimports = collect_all("customtkinter")
datas += [
    (str(ROOT / "tests" / "sample_traffic.pcap"), "tests"),
    (str(ROOT / "assets" / "app.ico"), "assets"),
]
hiddenimports += ["tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"]

version_file = os.environ.get("SMARTPCAP_VERSION_FILE") or ""

analysis = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff", "setuptools", "pip"],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="SmartPCAPParser",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(ROOT / "assets" / "app.ico"),
    version=version_file or None,
)

collect = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="SmartPCAPParser",
)
