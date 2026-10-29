"""Сборка Windows-приложения (exe) через PyInstaller.

Обычная сборка (папка, быстрый старт, рекомендуется для GitHub Releases):

    python tools/build_exe.py

Один файл (удобно переслать, но стартует медленнее):

    python tools/build_exe.py --onefile

Результат: `dist/SmartPCAPParser/...` и zip-архив
`dist/SmartPCAPParser-<версия>-windows-x64.zip`.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
SPEC = ROOT / "smartpcap.spec"
APP_NAME = "SmartPCAPParser"


def app_version() -> str:
    init = (ROOT / "parser" / "__init__.py").read_text(encoding="utf-8")
    for line in init.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "0.0.0"


def version_tuple(version: str) -> tuple[int, int, int, int]:
    parts = []
    for chunk in version.split(".")[:4]:
        digits = "".join(char for char in chunk if char.isdigit())
        parts.append(int(digits or 0))
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def write_version_file() -> Path:
    """Файл ресурсов версии для свойств exe."""
    BUILD.mkdir(exist_ok=True)
    version = app_version()
    numbers = version_tuple(version)
    dotted = ", ".join(str(number) for number in numbers)
    text = """VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({dotted}),
    prodvers=({dotted}),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Whitemoneydealer'),
      StringStruct('FileDescription', 'Smart PCAP Parser — анализ pcap простыми словами'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', '{app}'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', '{app}.exe'),
      StringStruct('ProductName', 'Smart PCAP Parser'),
      StringStruct('ProductVersion', '{version}')
    ])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""".format(dotted=dotted, version=version, app=APP_NAME)
    target = BUILD / "version_info.txt"
    target.write_text(text, encoding="utf-8")
    return target


def make_zip(folder: Path) -> Path:
    version = app_version()
    archive = DIST / "{}-{}-windows-x64.zip".format(APP_NAME, version)
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
        for path in sorted(folder.rglob("*")):
            if path.is_dir():
                continue
            zip_file.write(path, Path(APP_NAME) / path.relative_to(folder))
    return archive


def run_pyinstaller(onefile: bool) -> None:
    env = dict(os.environ)
    env["SMARTPCAP_ROOT"] = str(ROOT)
    env["SMARTPCAP_VERSION_FILE"] = str(write_version_file())

    if onefile:
        command = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--clean", "--onefile", "--windowed",
            "--name", APP_NAME,
            "--icon", str(ROOT / "assets" / "app.ico"),
            "--version-file", env["SMARTPCAP_VERSION_FILE"],
            "--collect-all", "customtkinter",
            "--add-data", "{};tests".format(ROOT / "tests" / "sample_traffic.pcap"),
            "--add-data", "{};assets".format(ROOT / "assets" / "app.ico"),
            "--distpath", str(DIST),
            "--workpath", str(BUILD),
            str(ROOT / "main.py"),
        ]
    else:
        command = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--clean",
            "--distpath", str(DIST),
            "--workpath", str(BUILD),
            str(SPEC),
        ]

    print("Сборка:", " ".join(command[:4]), "...")
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Собрать exe приложения")
    parser.add_argument("--onefile", action="store_true",
                        help="собрать один exe вместо папки")
    args = parser.parse_args()

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller не установлен. Выполните:")
        print("  pip install -r requirements-dev.txt")
        return 1

    if not (ROOT / "assets" / "app.ico").exists():
        print("Нет assets/app.ico — пересоздайте иконку: python tools/make_icon.py")
        return 1

    # Чистим только результат, чтобы сборка была воспроизводимой.
    if DIST.exists():
        shutil.rmtree(DIST, ignore_errors=True)

    try:
        run_pyinstaller(args.onefile)
    except subprocess.CalledProcessError as exc:
        print("Сборка не удалась, код", exc.returncode)
        return exc.returncode

    if args.onefile:
        exe = DIST / "{}.exe".format(APP_NAME)
        print("Готово:", exe, "{:.1f} МБ".format(exe.stat().st_size / (1024 * 1024)))
        archive = DIST / "{}-{}-windows-x64-onefile.zip".format(APP_NAME, app_version())
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.write(exe, exe.name)
        print("Архив:", archive)
        return 0

    folder = DIST / APP_NAME
    if not folder.exists():
        print("Папка сборки не появилась:", folder)
        return 1

    archive = make_zip(folder)
    size = sum(path.stat().st_size for path in folder.rglob("*") if path.is_file())
    print("Готово:", folder, "{:.1f} МБ".format(size / (1024 * 1024)))
    print("Архив:", archive, "{:.1f} МБ".format(archive.stat().st_size / (1024 * 1024)))
    print("Проверка: dist\\{}\\{}.exe --selftest".format(APP_NAME, APP_NAME))
    return 0


if __name__ == "__main__":
    sys.exit(main())
