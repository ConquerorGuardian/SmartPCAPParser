"""
Лимиты отрисовки и мелкие форматтеры, общие для модулей интерфейса.

Вынесено из gui/app.py, чтобы миксины (layout, table_view, stats_view,
dialogs) не тянули за собой gui/app.py — иначе получился бы цикл импортов.
"""

import sys
from pathlib import Path

# Сколько строк таблица рисует сразу. До VIEW_LIMIT показываем всё без
# постраничного листания: 50 000 строк заполняются за доли секунды.
# Выше — страницы по PAGE_SIZE, чтобы окно не подвисало на гигантских дампах.
VIEW_LIMIT = 50_000
PREVIEW_COUNT = 5_000
# Размер страницы при листании (и максимальное число строк, которое вообще
# держим в таблице: больше — только через фильтр/поиск).
PAGE_SIZE = PREVIEW_COUNT
MAX_ROWS = 500_000

HISTORY_LIMIT = 12
HEX_LIMIT = 64 * 1024

# Файлы больше этого размера читаются без тела TCP: иначе «Поток TCP» съест
# память целиком. Поток для них недоступен, о чём честно пишем в статусе.
MAX_PAYLOAD_FILE = 25 * 1024 * 1024
# Сколько данных потока максимум подгружаем из большого файла по требованию.
STREAM_PAYLOAD_LIMIT = 64 * 1024 * 1024

# Флаги TCP: бит -> подпись.
TCP_FLAGS = [
    (0x100, "CWR"),
    (0x080, "ECE"),
    (0x040, "URG"),
    (0x020, "ACK"),
    (0x010, "PSH"),
    (0x008, "RST"),
    (0x004, "SYN"),
    (0x002, "FIN"),
    (0x001, "NS"),
]


def format_count(value: int) -> str:
    """9123 -> «9 123»: в статусе так читается легче."""
    return f"{value:,}".replace(",", " ")


def resource_path(relative: str) -> Path:
    """Путь к ресурсу проекта: и в исходниках, и внутри собранного exe."""
    bundled = getattr(sys, "_MEIPASS", None)
    root = Path(bundled) if bundled else Path(__file__).resolve().parent.parent
    return root / relative


def asset_path(name: str) -> Path:
    """Файл из assets/ — и в исходниках, и внутри собранного exe."""
    return resource_path("assets/" + name)


def table_limit(total: int) -> int:
    """Сколько строк рисовать сразу (-1 — все).

    До VIEW_LIMIT показываем всё — «в файле 9 000 пакетов, а в таблице 200»
    выглядело как потеря данных. Выше лимита рисуем первую страницу, чтобы
    окно не подвисало, и честно пишем об этом в статусе.
    """
    return -1 if total <= VIEW_LIMIT else PREVIEW_COUNT


def _safe_stem(text: str) -> str:
    """Имя файла без символов, недопустимых в Windows."""
    cleaned = "".join(
        char if char.isalnum() or char in "-_." else "_" for char in text
    )
    return cleaned.strip("._") or "stream"


def decode_tcp_flags(flags: int) -> str:
    """0x18 -> 'PSH, ACK'."""
    names = [name for bit, name in TCP_FLAGS if flags & bit]
    return ", ".join(names) if names else "нет"


def hex_dump(data: bytes, width: int = 16) -> str:
    """Классический hex-дамп: смещение, байты, печатные символы."""
    if not data:
        return ""

    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        text_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        lines.append(
            f"{offset:08x}  {hex_part:<47}  {text_part}"
        )
    return "\n".join(lines)
