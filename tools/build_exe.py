"""Сборка Windows-приложения (exe) через PyInstaller.

По умолчанию собирается **один файл** — его достаточно скачать и запустить.
Он распаковывается в папку `tmp` рядом с собой, а не во временную папку
Windows: на машинах со сломанной переменной `%TEMP%` обычная распаковка
падает с «Could not create temporary directory».

    python tools/build_exe.py           # dist/SmartPCAPParser.exe

Папка (стартует быстрее, но это архив из сотен файлов):

    python tools/build_exe.py --onedir  # dist/SmartPCAPParser/ + zip

Рядом с артефактами кладётся `SHA256SUMS.txt` — чтобы скачавший мог
проверить, что файл не побился при загрузке.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
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
    """Файл ресурсов версии: его видно в свойствах exe."""
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
      StringStruct('CompanyName', 'Nikita Belov'),
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_checksums() -> Path:
    """Суммы по всем артефактам в dist/: exe и zip, что там реально лежат."""
    target = DIST / "SHA256SUMS.txt"
    items = sorted(
        path for path in DIST.iterdir()
        if path.is_file() and path.suffix.lower() in {".exe", ".zip"}
    )
    lines = ["{}  {}".format(sha256(item), item.name) for item in items]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def make_zip(folder: Path) -> Path:
    archive = DIST / "{}-{}-windows-x64.zip".format(APP_NAME, app_version())
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
        for path in sorted(folder.rglob("*")):
            if path.is_dir():
                continue
            zip_file.write(path, Path(APP_NAME) / path.relative_to(folder))
    return archive


def run_pyinstaller(onedir: bool) -> Path:
    """Собирает вариант в отдельную папку и возвращает готовый артефакт.

    У onefile и onedir разные рабочие и выходные папки: когда обе сборки идут
    в один dist/, второй проход портит архив onefile, и exe падает с кодом -1.

    Одиночный файл распаковывается в папку tmp рядом с собой, а не в %TEMP%:
    на машинах, где переменная TEMP сломана, обычная распаковка падает с
    «Could not create temporary directory».
    """
    mode = "onedir" if onedir else "onefile"
    work = BUILD / mode
    out = work / "dist"
    env = dict(os.environ)
    env["SMARTPCAP_ROOT"] = str(ROOT)
    version_file = write_version_file()

    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--windowed", "--noupx",
        "--name", APP_NAME,
        "--icon", str(ROOT / "assets" / "app.ico"),
        "--version-file", str(version_file),
        "--collect-all", "customtkinter",
        "--exclude-module", "pytest",
        "--exclude-module", "mypy",
        "--exclude-module", "ruff",
        "--exclude-module", "setuptools",
        "--exclude-module", "pip",
        "--add-data", "{};tests".format(ROOT / "tests" / "sample_traffic.pcap"),
        "--add-data", "{};tests".format(ROOT / "tests" / "sample_traffic.pcapng"),
        "--add-data", "{};assets".format(ROOT / "assets" / "app.ico"),
        "--distpath", str(out),
        "--workpath", str(work / "work"),
    ]
    if not onedir:
        command.append("--onefile")
        # Относительный путь: распаковка идёт в tmp рядом с exe, откуда запуск.
        command += ["--runtime-tmpdir", "tmp"]
    command.append(str(ROOT / "main.py"))

    print("Сборка:", mode, "...")
    subprocess.run(command, cwd=ROOT, env=env, check=True)

    produced = out / (APP_NAME if onedir else "{}.exe".format(APP_NAME))
    if not produced.exists():
        raise FileNotFoundError(str(produced))
    return produced


def main() -> int:
    parser = argparse.ArgumentParser(description="Собрать exe приложения")
    parser.add_argument("--onedir", action="store_true",
                        help="собрать папку вместо одного файла")
    parser.add_argument("--both", action="store_true",
                        help="собрать и один файл, и папку (для релиза)")
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

    if DIST.exists():
        shutil.rmtree(DIST, ignore_errors=True)

    # Старый build/ от предыдущей версии ломает onefile-сборку (exe выходит
    # с кодом -1 и молчит), поэтому рабочая папка PyInstaller тоже чистится.
    if BUILD.exists():
        shutil.rmtree(BUILD, ignore_errors=True)

    modes: list[bool] = []
    if args.both:
        modes = [False, True]      # сначала один файл, потом папка
    else:
        modes = [args.onedir]

    for onedir in modes:
        try:
            produced = run_pyinstaller(onedir)
        except subprocess.CalledProcessError as exc:
            print("Сборка не удалась, код", exc.returncode)
            return exc.returncode
        except FileNotFoundError as exc:
            print("Артефакт не появился:", exc)
            return 1

        if onedir:
            folder = DIST / APP_NAME
            if folder.exists():
                shutil.rmtree(folder, ignore_errors=True)
            shutil.copytree(produced, folder)
            artifact = make_zip(folder)
        else:
            artifact = DIST / "{}.exe".format(APP_NAME)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(produced, artifact)
        print("Готово: {} ({:.1f} МБ)".format(
            artifact, artifact.stat().st_size / (1024 * 1024)))

    checksums = write_checksums()
    print("Контрольные суммы:", checksums)

    # check_exe.py умеет проверять только exe, поэтому в подсказке — именно они.
    check_targets = [
        item for item in (
            DIST / "{}.exe".format(APP_NAME),
            DIST / APP_NAME / "{}.exe".format(APP_NAME),
        ) if item.exists()
    ]
    print("Проверка: python tools/check_exe.py " + " ".join(
        item.as_posix() for item in check_targets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
