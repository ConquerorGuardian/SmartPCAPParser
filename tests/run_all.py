"""
Запуск всех тестов проекта.

Использование:
    python -m tests.run_all
"""

import runpy
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

MODULES = [
    "tests.test_engine",
    "tests.test_reader",
    "tests.test_matcher",
    "tests.test_handler",
    "tests.test_streams",
    "tests.test_stats",
    "tests.test_nodecard",
    "tests.test_wireshark",
    "tests.test_verdict",
    "tests.test_settings",
    "tests.test_corpus",
    "tests.test_fuzz",
    "tests.test_golden",
    "tests.test_docs",
    "tests.test_full_pipeline",
    "tests.test_gui_smoke",
]


def run_module(name: str) -> bool:
    print("")
    print("=" * 60)
    print("Модуль:", name)
    print("=" * 60)

    try:
        runpy.run_module(name, run_name="__main__")
        return True
    except SystemExit as exc:
        if exc.code:
            print(f"::error title=Тесты {name}::модуль завершился с кодом {exc.code}")
        return not exc.code
    except Exception:  # noqa: BLE001
        detail = traceback.format_exc()
        print(detail)
        # Аннотация видна в GitHub Actions без скачивания логов.
        last = detail.strip().splitlines()[-1][:900]
        print(f"::error title=Тесты {name}::{last}")
        return False


def main() -> int:
    results = [(name, run_module(name)) for name in MODULES]

    print("")
    print("=" * 60)
    print("ИТОГИ")
    print("=" * 60)
    for name, ok in results:
        print("{:30} {}".format(name, "OK" if ok else "FAIL"))

    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main())
