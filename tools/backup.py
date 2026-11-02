"""Резервная копия проекта одним архивом.

Создаёт `backups/SmartPCAPParser-<версия>-<дата>.zip` со всем исходным кодом
и историей git (папка `.git`), чтобы проект можно было восстановить целиком,
даже если рабочая папка пострадает.

Запуск:
    python tools/backup.py            # обычная копия
    python tools/backup.py --list     # показать сделанные копии
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUPS = ROOT / "backups"

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
             "build", "dist", "backups", "samples", ".venv", "venv",
             ".pylibs", ".tmp", ".tmp-build", "tmp_pip", ".bench",
             "node_modules", ".idea", ".vscode", "release"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".pcap", ".pcapng", ".gz", ".exe", ".dll"}


def project_version() -> str:
    init = (ROOT / "parser" / "__init__.py").read_text(encoding="utf-8")
    for line in init.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "unknown"


def should_skip(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return True
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    return False


def make_backup(note: str = "") -> Path:
    BACKUPS.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    version = project_version()
    name = f"SmartPCAPParser-{version}-{stamp}.zip"
    target = BACKUPS / name

    count = 0
    skipped = 0
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(ROOT.rglob("*")):
            if path.is_dir() or path == target:
                continue
            relative = path.relative_to(ROOT)
            if should_skip(relative):
                continue
            try:
                archive.write(path, Path("SmartPCAPParser") / relative)
            except OSError:
                # Один нечитаемый файл не должен ломать всю копию.
                skipped += 1
                continue
            count += 1

        if note:
            archive.writestr(
                "SmartPCAPParser/BACKUP_NOTE.txt",
                "Версия: {}\nДата: {}\nКомментарий: {}\n".format(
                    version, datetime.now().isoformat(timespec="seconds"), note
                ),
            )

    size_mb = target.stat().st_size / (1024 * 1024)
    print(f"Бэкап: {target} ({count} файлов, {size_mb:.1f} МБ)")
    if skipped:
        print(f"Пропущено нечитаемых файлов: {skipped}")
    return target


def list_backups() -> None:
    if not BACKUPS.exists():
        print("Копий пока нет.")
        return
    for path in sorted(BACKUPS.glob("*.zip")):
        size_mb = path.stat().st_size / (1024 * 1024)
        stamp = datetime.fromtimestamp(path.stat().st_mtime)
        print("{:<52} {:>7.1f} МБ  {}".format(
            path.name, size_mb, stamp.strftime("%Y-%m-%d %H:%M")
        ))


def main() -> int:
    parser = argparse.ArgumentParser(description="Резервная копия проекта")
    parser.add_argument("--list", action="store_true", help="показать копии")
    parser.add_argument("--note", default="", help="комментарий к копии")
    args = parser.parse_args()

    if args.list:
        list_backups()
        return 0

    make_backup(args.note)
    print("Готово. Лежат в:", BACKUPS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
