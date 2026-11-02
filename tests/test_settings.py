"""Тесты настроек: сохранение темы, истории и колонок между запусками."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.settings import (
    DEFAULTS,
    HISTORY_LIMIT,
    RECENT_LIMIT,
    load_settings,
    normalize,
    save_settings,
)


def test_defaults_when_missing():
    """Нет файла — настройки по умолчанию, без исключений."""
    path = Path(__file__).parent / "_settings_missing.json"
    path.unlink(missing_ok=True)
    settings = load_settings(path)
    assert settings == DEFAULTS, settings
    print("PASS: test_defaults_when_missing")


def test_roundtrip():
    """Что сохранили, то и прочитали."""
    path = Path(__file__).parent / "_settings_roundtrip.json"
    payload = {
        "theme": "light",
        "geometry": "1200x700+40+20",
        "history": ["покажи http", "порты 80,443"],
        "last_dir": r"C:\dumps",
        "columns": {"#0": 300, "Info": 420},
        "stats_scope": "Найденные",
        "recent": [r"C:\dumps\a.pcap", r"C:\dumps\b.pcapng"],
    }
    try:
        assert save_settings(payload, path) is True
        assert path.exists()
        loaded = load_settings(path)
        assert loaded["theme"] == "light", loaded
        assert loaded["geometry"] == "1200x700+40+20", loaded
        assert loaded["history"] == ["покажи http", "порты 80,443"], loaded
        assert loaded["columns"]["#0"] == 300
        assert loaded["stats_scope"] == "Найденные"
        assert loaded["recent"] == [r"C:\dumps\a.pcap", r"C:\dumps\b.pcapng"], loaded
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_roundtrip")


def test_broken_file():
    """Битый JSON и мусор в полях не ломают запуск."""
    path = Path(__file__).parent / "_settings_broken.json"
    try:
        path.write_text("{это не json", encoding="utf-8")
        assert load_settings(path) == DEFAULTS
        path.write_text(json.dumps({
            "theme": "neon",
            "geometry": "во весь экран",
            "history": "не список",
            "columns": {"Info": "широкая", "Frame": 10_000},
            "stats_scope": "Что-то",
        }), encoding="utf-8")
        loaded = load_settings(path)
        assert loaded["theme"] == "dark", loaded
        assert loaded["geometry"] == "", loaded
        assert loaded["history"] == [], loaded
        assert loaded["columns"] == {}, loaded
        assert loaded["stats_scope"] == "Все пакеты", loaded
    finally:
        path.unlink(missing_ok=True)
    print("PASS: test_broken_file")


def test_history_cleanup():
    """История без дубликатов и не длиннее лимита."""
    history = ["покажи http", "покажи http", "  ", "dns"] + [
        f"команда {index}" for index in range(HISTORY_LIMIT + 10)
    ]
    cleaned = normalize({"history": history})["history"]
    assert cleaned[:2] == ["покажи http", "dns"], cleaned[:2]
    assert len(cleaned) == HISTORY_LIMIT, len(cleaned)
    assert normalize({"history": ["  http  "]})["history"] == ["http"]
    print("PASS: test_history_cleanup")


def test_save_to_unwritable_path():
    """Не удалось сохранить — возвращаем False, а не падаем."""
    blocker = Path(__file__).parent / "_settings_blocker"
    try:
        blocker.write_text("не папка", encoding="utf-8")
        broken = blocker / "sub" / "settings.json"
        assert save_settings({"theme": "dark"}, broken) is False
    finally:
        blocker.unlink(missing_ok=True)
    print("PASS: test_save_to_unwritable_path")


def test_recent_files_cleanup():
    """Недавние файлы: без дубликатов, мусора и длиннее лимита."""
    recent = ["C:/dumps/a.pcap", "C:/dumps/a.pcap", "", "  ", "C:/dumps/b.pcap"]
    recent += ["C:/dumps/{}.pcap".format(index) for index in range(20)]
    cleaned = normalize({"recent": recent})["recent"]
    assert cleaned[:2] == ["C:/dumps/a.pcap", "C:/dumps/b.pcap"], cleaned[:2]
    assert len(cleaned) == RECENT_LIMIT, len(cleaned)
    assert normalize({"recent": "не список"})["recent"] == []
    print("PASS: test_recent_files_cleanup")


def test_simple_mode_flag():
    """Простой режим: по умолчанию включён, мусор в поле не ломает запуск."""
    assert DEFAULTS["simple_mode"] is True
    assert normalize({})["simple_mode"] is True
    assert normalize({"simple_mode": False})["simple_mode"] is False
    assert normalize({"simple_mode": "нет"})["simple_mode"] is True
    print("PASS: test_simple_mode_flag")


def main() -> int:
    tests = [
        test_defaults_when_missing,
        test_roundtrip,
        test_broken_file,
        test_history_cleanup,
        test_recent_files_cleanup,
        test_save_to_unwritable_path,
        test_simple_mode_flag,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            print(f"FAIL: {test.__name__}: {exc}")
            failed += 1
        except Exception as exc:                       # noqa: BLE001
            print(f"FAIL: {test.__name__}: {type(exc).__name__}: {exc}")
            failed += 1

    print("")
    print("-" * 40)
    print(f"Пройдено: {len(tests) - failed}/{len(tests)}")
    if failed:
        print("Есть падения.")
        return 1
    print("Все тесты прошли!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
