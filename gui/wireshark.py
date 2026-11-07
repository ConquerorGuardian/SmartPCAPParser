"""Wireshark рядом: найти установленный и открыть в нём текущий дамп.

Программа не требует Wireshark, но если он есть, кнопка «В Wireshark»
передаёт туда файл вместе с текущим фильтром. Путь можно задать вручную
переменной окружения SMARTPCAP_WIRESHARK.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ENV_OVERRIDE = "SMARTPCAP_WIRESHARK"


def build_command(executable, dump_path, filter_string: str = "") -> list[str]:
    """Аргументы запуска: файл сразу с display-фильтром, если он есть."""
    command = [str(executable), str(dump_path)]
    filter_string = (filter_string or "").strip()
    if filter_string:
        command += ["-Y", filter_string]
    return command


def _windows_candidates() -> list[Path]:
    candidates: list[Path] = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(variable)
        if base:
            candidates.append(Path(base) / "Wireshark" / "Wireshark.exe")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(Path(local) / "Programs" / "Wireshark" / "Wireshark.exe")

    try:
        import winreg
    except ImportError:
        return candidates

    for root, key_path in (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wireshark"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Wireshark"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Wireshark"),
    ):
        try:
            with winreg.OpenKey(root, key_path) as key:
                install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
        except OSError:
            continue
        candidates.append(Path(install_dir) / "Wireshark.exe")
    return candidates


def find_wireshark() -> str | None:
    """Полный путь к Wireshark или None, если не установлен."""
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        path = Path(override)
        if path.is_file():
            return str(path)
        return shutil.which(override)

    found = shutil.which("wireshark")
    if found:
        return found

    if sys.platform == "win32":
        for candidate in _windows_candidates():
            if candidate.is_file():
                return str(candidate)
    elif sys.platform == "darwin":
        app = Path("/Applications/Wireshark.app/Contents/MacOS/Wireshark")
        if app.is_file():
            return str(app)
    return None


def open_dump(dump_path, filter_string: str = "") -> tuple[bool, str]:
    """Запускает Wireshark. Возвращает (получилось, сообщение для статуса)."""
    if not dump_path:
        return False, "Сначала откройте файл дампа."
    path = Path(dump_path)
    if not path.is_file():
        return False, f"Файл не найден: {path}"

    executable = find_wireshark()
    if not executable:
        return False, (
            "Wireshark не найден. Установите его с wireshark.org или укажите "
            f"путь в переменной {ENV_OVERRIDE}."
        )

    try:
        subprocess.Popen(
            build_command(executable, path, filter_string),
            close_fds=True,
        )
    except OSError as exc:
        return False, f"Не удалось запустить Wireshark: {exc}"
    return True, "Открываю дамп в Wireshark."
