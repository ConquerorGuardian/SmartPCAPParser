"""Готовит папку release/ — то, что вручную прикрепляется к релизу GitHub."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
OUT = ROOT / "release"
VERSION = "1.9.1"

FILES = [
    "SmartPCAPParser.exe",
    "SmartPCAPParser-portable.exe",
    "SmartPCAPParser-{}-windows-x64.zip".format(VERSION),
    "SHA256SUMS.txt",
]

NOTE = """ЧТО ПРИКРЕПИТЬ К РЕЛИЗУ v{version}
=====================================

Файлы в этой папке (все пять):

  1. SmartPCAPParser.exe                       — один файл, распаковка в %TEMP%
  2. SmartPCAPParser-portable.exe              — один файл, распаковка в tmp рядом
                                                 с собой, нужен, если %TEMP%
                                                 недоступен и выходит ошибка
                                                 «Could not create temporary
                                                 directory»
  3. SmartPCAPParser-{version}-windows-x64.zip — та же программа папкой,
                                                 вообще без распаковки
  4. SHA256SUMS.txt                            — контрольные суммы
  5. LICENSE                                   — лицензия MIT

Если публикуете через git-тег, всё это прикрепит GitHub Actions само:
  git tag v{version}
  git push origin v{version}

Если загружаете вручную: github.com → Releases → Draft a new release:
  Tag:      v{version}
  Title:    Smart PCAP Parser {version}
  Файлы:    перетащите из этой папки
  Описание: скопируйте из internal/RELEASE-NOTES.md

ПРОВЕРКА ПЕРЕД ЗАГРУЗКОЙ
------------------------
  SmartPCAPParser.exe --selftest     (в консоли: Итог: OK, код 0)
  certutil -hashfile SmartPCAPParser.exe SHA256
      — сравнить с первой строкой SHA256SUMS.txt

Файл НЕ подписан сертификатом: SmartScreen может предупредить. Это ожидаемо,
в описании релиза есть пояснение.
"""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()

    for name in FILES:
        source = DIST / name
        if not source.exists():
            print("НЕТ ФАЙЛА:", source)
            return 1
        shutil.copy2(source, OUT / name)
        print("скопировано:", name, "{:.1f} МБ".format(
            source.stat().st_size / (1024 * 1024)))

    shutil.copy2(ROOT / "LICENSE", OUT / "LICENSE")
    (OUT / "ОТПРАВИТЬ-В-РЕЛИЗ.txt").write_text(
        NOTE.format(version=VERSION), encoding="utf-8")

    # Контроль: суммы в папке совпадают с файлами.
    for line in (OUT / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        actual = sha256(OUT / name.strip())
        status = "OK" if actual == digest.lower() else "FAIL"
        print("{}  {}".format(status, name.strip()))

    print("Готово:", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
