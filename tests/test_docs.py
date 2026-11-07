"""Таблицы команд в документации должны совпадать с движком.

Если поменялся словарь или генератор фильтров, а README не обновили, этот
тест падает и показывает, какая строка разошлась.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.engine import NaturalLanguageFilterEngine  # noqa: E402
from parser.filters import generate_filter  # noqa: E402

BACKTICK = chr(96)
ROOT = Path(__file__).parent.parent
ENGINE = NaturalLanguageFilterEngine()


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip()).strip()


def filter_rows(path: Path) -> list[tuple[str, str]]:
    """Пары (команда, ожидаемый фильтр) из таблиц, где обе ячейки в бэктиках."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        command, expected = cells[0], cells[1]
        if not (command.startswith(BACKTICK) and command.endswith(BACKTICK)):
            continue
        if not (expected.startswith(BACKTICK) and expected.endswith(BACKTICK)):
            continue
        rows.append((
            command.strip(BACKTICK).strip(),
            expected.strip(BACKTICK).strip(),
        ))
    return rows


def check_document(name: str, minimum: int) -> None:
    path = ROOT / name
    rows = filter_rows(path)
    assert len(rows) >= minimum, (name, len(rows))
    for command, expected in rows:
        got = generate_filter(ENGINE.parse(command))
        assert normalize(got) == normalize(expected), (
            f"{name}: {command!r} -> {got!r}, в документе {expected!r}"
        )
    print(f"PASS: {name} ({len(rows)} строк)")


def test_readme_commands():
    """README: таблица команд и готовые фильтры."""
    check_document("README.md", minimum=10)


def test_examples_commands():
    """docs/EXAMPLES.md: самый большой набор фраз."""
    check_document("docs/EXAMPLES.md", minimum=50)


def test_readme_en_commands():
    """README.en.md: короткая английская версия."""
    check_document("README.en.md", minimum=5)


if __name__ == "__main__":
    tests = [
        test_readme_commands,
        test_examples_commands,
        test_readme_en_commands,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            print(f"FAIL: {test.__name__}: {exc}")
            failed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: {test.__name__}: {exc}")
            failed += 1

    print("")
    print("-" * 40)
    print(f"Пройдено: {len(tests) - failed}/{len(tests)}")
    if failed:
        sys.exit(1)
    print("Все тесты прошли!")
