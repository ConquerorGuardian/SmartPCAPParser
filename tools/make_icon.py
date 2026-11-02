"""Иконка приложения: рисует `assets/app.ico` без внешних картинок.

Нужен Pillow (только для перерисовки иконки, приложению он не нужен):

    pip install pillow
    python tools/make_icon.py

Иконка: тёмный скруглённый квадрат, три узла сети и стрелка пакета —
читается и в 16 пикселей.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:                          # pragma: no cover
    print("Нужен Pillow: pip install pillow")
    raise SystemExit(1) from None

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"

BACKGROUND_TOP = (18, 24, 38)
BACKGROUND_BOTTOM = (11, 15, 24)
ACCENT = (88, 196, 221)
ACCENT_DARK = (46, 134, 196)
NODE = (232, 240, 248)

SCALE = 8          # рисуем крупно, потом уменьшаем — так края гладкие
SIZE = 256


def lerp(start: int, end: int, factor: float) -> int:
    return int(round(start + (end - start) * factor))


def draw_icon(size: int) -> Image.Image:
    big = size * SCALE
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Фон: вертикальный градиент в скруглённом квадрате.
    radius = int(big * 0.22)
    background = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    gradient = ImageDraw.Draw(background)
    for y in range(big):
        factor = y / max(1, big - 1)
        color = (
            lerp(BACKGROUND_TOP[0], BACKGROUND_BOTTOM[0], factor),
            lerp(BACKGROUND_TOP[1], BACKGROUND_BOTTOM[1], factor),
            lerp(BACKGROUND_TOP[2], BACKGROUND_BOTTOM[2], factor),
            255,
        )
        gradient.line([(0, y), (big, y)], fill=color)
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, big - 1, big - 1], radius=radius, fill=255)
    image.paste(background, (0, 0), mask)

    # Три узла: левый нижний, центральный, правый верхний.
    nodes = [(0.26, 0.70), (0.50, 0.50), (0.74, 0.30)]
    points = [(int(x * big), int(y * big)) for x, y in nodes]
    width = max(2, int(big * 0.022))

    for start, end in ((points[0], points[1]), (points[1], points[2])):
        draw.line([start, end], fill=ACCENT_DARK, width=width)

    node_radius = int(big * 0.075)
    for index, (x, y) in enumerate(points):
        fill = ACCENT if index == 1 else NODE
        draw.ellipse(
            [x - node_radius, y - node_radius, x + node_radius, y + node_radius],
            fill=fill,
        )

    # Стрелка пакета вдоль правой связи.
    ax, ay = int(big * 0.60), int(big * 0.40)
    draw.polygon(
        [
            (ax, ay - int(big * 0.055)),
            (ax + int(big * 0.075), ay),
            (ax, ay + int(big * 0.055)),
            (ax + int(big * 0.028), ay),
        ],
        fill=ACCENT,
    )

    return image.resize((size, size), Image.LANCZOS)


def main() -> int:
    ASSETS.mkdir(exist_ok=True)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [draw_icon(size) for size in sizes]
    frames[-1].save(ASSETS / "app.ico", format="ICO", sizes=[(s, s) for s in sizes])

    print("Готово:", ASSETS / "app.ico")
    for size in sizes:
        print("  {}x{}".format(size, size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
