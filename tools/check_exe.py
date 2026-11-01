"""Проверка собранного exe: `--selftest` должен вернуть 0.

Запуск:
    python tools/check_exe.py dist/SmartPCAPParser.exe
    python tools/check_exe.py dist/SmartPCAPParser/SmartPCAPParser.exe dist/SmartPCAPParser.exe

Так же проверяет `--version`. Скрипт нужен и для CI: PowerShell
`Start-Process -Wait` на onefile-сборке PyInstaller может зависнуть,
а обычный запуск через subprocess работает предсказуемо.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

TIMEOUT = 300


def run(exe: Path, argument: str) -> tuple[int, str]:
    started = time.time()
    result = subprocess.run(
        [str(exe), argument],
        capture_output=True,
        timeout=TIMEOUT,
        cwd=str(exe.parent),
    )
    elapsed = time.time() - started
    output = (result.stdout + result.stderr).decode("utf-8", "replace")
    print("{} {} -> код {}, {:.1f} с".format(exe.name, argument, result.returncode, elapsed))
    return result.returncode, output


def check(exe: Path) -> bool:
    if not exe.exists():
        print("НЕТ ФАЙЛА:", exe)
        return False

    code, output = run(exe, "--version")
    ok = code == 0 and "Smart PCAP Parser" in output
    if not ok:
        print("версия не напечаталась:", output[-300:])

    code, output = run(exe, "--selftest")
    ok = ok and code == 0
    if code != 0:
        print("selftest упал:", output[-800:])
    elif "OK" not in output and "Итог: OK" not in output:
        # У windowed-сборки вывод может уйти «в никуда» — тогда верим коду.
        print("вывод selftest пуст, но код 0 — считаем успехом")
    return ok


def main() -> int:
    targets = [Path(item) for item in sys.argv[1:]]
    if not targets:
        targets = [Path("dist/SmartPCAPParser.exe")]
    results = [check(target) for target in targets]
    for target, ok in zip(targets, results):
        print(("OK   " if ok else "FAIL ") + str(target))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
