"""
Настройки пользователя между запусками.

Хранятся в JSON рядом с домашней папкой — файл не мешает репозиторию и
переживает переустановку. Если файл битый или чужие права — молча
возвращаем настройки по умолчанию: приложение должно открываться всегда.
"""

import json
import re
from pathlib import Path
from typing import Any

SETTINGS_DIR = Path.home() / ".smartpcapapp"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"

# Геометрия окна в формате Tk: 1380x820 или 1380x820+120+80.
GEOMETRY_RE = re.compile(r"^\d{3,4}x\d{3,4}([+-]\d{1,4}[+-]\d{1,4})?$")

DEFAULTS: dict[str, Any] = {
    "theme": "dark",
    "geometry": "",
    "history": [],
    "last_dir": "",
    "columns": {},
    "stats_scope": "Все пакеты",
}

HISTORY_LIMIT = 40
MAX_COLUMNS = 32


def _clean_theme(value: Any) -> str:
    return value if value in ("dark", "light") else DEFAULTS["theme"]


def _clean_geometry(value: Any) -> str:
    if isinstance(value, str) and GEOMETRY_RE.match(value):
        return value
    return ""


def _clean_history(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    # Дубликаты убираем, порядок «свежие сверху» сохраняем.
    seen: list[str] = []
    for item in cleaned:
        if item not in seen:
            seen.append(item)
    return seen[:HISTORY_LIMIT]


def _clean_columns(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    cleaned: dict[str, int] = {}
    for index, (name, width) in enumerate(value.items()):
        if index >= MAX_COLUMNS:
            break
        if not isinstance(name, str) or not name:
            continue
        try:
            number = int(width)
        except (TypeError, ValueError):
            continue
        if 20 <= number <= 2000:
            cleaned[name] = number
    return cleaned


def _clean_scope(value: Any) -> str:
    return value if value in ("Все пакеты", "Найденные") else DEFAULTS["stats_scope"]


def normalize(data: Any) -> dict[str, Any]:
    """Приводит произвольный словарь к безопасным настройкам."""
    if not isinstance(data, dict):
        return dict(DEFAULTS)

    last_dir = data.get("last_dir")
    return {
        "theme": _clean_theme(data.get("theme")),
        "geometry": _clean_geometry(data.get("geometry")),
        "history": _clean_history(data.get("history")),
        "last_dir": last_dir if isinstance(last_dir, str) else "",
        "columns": _clean_columns(data.get("columns")),
        "stats_scope": _clean_scope(data.get("stats_scope")),
    }


def load_settings(path: Path | str | None = None) -> dict[str, Any]:
    """Читает настройки; при любой ошибке — значения по умолчанию."""
    target = Path(path) if path is not None else SETTINGS_FILE
    try:
        with open(target, encoding="utf-8") as handle:
            return normalize(json.load(handle))
    except (OSError, ValueError):
        return dict(DEFAULTS)


def save_settings(data: Any, path: Path | str | None = None) -> bool:
    """Сохраняет настройки. False — если записать не удалось."""
    target = Path(path) if path is not None else SETTINGS_FILE
    payload = normalize(data)
    temp = target.with_suffix(".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        temp.replace(target)
        return True
    except (OSError, ValueError):
        # Настройки — не повод падать: просто не сохранились.
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        return False
