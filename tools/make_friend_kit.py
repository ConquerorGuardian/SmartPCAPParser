"""Собирает ZIP, который можно просто переслать другу.

Внутри: SmartPCAPParser.exe + короткая инструкция «что нажать». Ничего
устанавливать не нужно, Python не нужен.
"""

from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
OUT = ROOT / "release"

INSTRUCTIONS = """Smart PCAP Parser {version} — как посмотреть
====================================================

1. Распакуйте архив (или просто запустите SmartPCAPParser.exe).
2. Запустите SmartPCAPParser.exe. Установка не нужна, Python не нужен.
3. Windows может предупредить SmartScreen: «Подробнее» →
   «Выполнить в любом случае». Файл не подписан сертификатом —
   для небольших открытых программ это обычное дело.
4. Чтобы сразу увидеть возможности, нажмите «Открыть пример дампа».
5. Или откройте свой файл .pcap / .pcapng и напишите в поле команды,
   например:  http трафик с айпи 192.168.1.10
   Enter — и в таблице останутся только эти пакеты.
6. Полезное: Ctrl+F — поиск, Ctrl+L — тема, F1 — справка,
   правая кнопка по строке — фильтры в один клик, правая кнопка
   по сайту в статистике — сразу его пакеты.

Рядом с exe появится папка tmp: это служебные файлы программы, после
закрытия их можно удалить. Интернет программе не нужен.

Если что-то не работает — напишите, что нажимали и что увидели
(или пришлите скриншот). Проверить файл можно командой:
   SmartPCAPParser.exe --selftest
"""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    version = (ROOT / "parser" / "__init__.py").read_text(encoding="utf-8")
    version = version.split('__version__ = "')[1].split('"')[0]

    exe = DIST / "SmartPCAPParser.exe"
    if not exe.exists():
        print("Нет exe — сначала: python tools/build_exe.py --both")
        return 1

    staging = OUT / "friend-kit"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    shutil.copy2(exe, staging / "SmartPCAPParser.exe")
    (staging / "КАК-ЗАПУСТИТЬ.txt").write_text(
        INSTRUCTIONS.format(version=version), encoding="utf-8")

    OUT.mkdir(exist_ok=True)
    archive = OUT / "SmartPCAPParser-{}-friend.zip".format(version)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for item in sorted(staging.iterdir()):
            zf.write(item, item.name)

    print("Архив: {} ({:.1f} МБ)".format(
        archive, archive.stat().st_size / (1024 * 1024)))
    shutil.rmtree(staging, ignore_errors=True)
    print("SHA256:", sha256(archive))
    print("Можно отправлять как есть: внутри exe и инструкция.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
