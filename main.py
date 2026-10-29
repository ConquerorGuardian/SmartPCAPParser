"""
SmartPCAPParser — точка входа.

Без аргументов запускает графический интерфейс.
Консольный режим удобен для проверки движка:

    python main.py --demo
    python main.py -c "покажи http трафик"
    python main.py --file tests/sample_traffic.pcap -c "выведи пакеты на порт 80"
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.engine import NaturalLanguageFilterEngine  # noqa: E402
from parser.filters import generate_filter  # noqa: E402
from parser.pcap_handler import PcapHandler  # noqa: E402
from parser.streams import (  # noqa: E402
    MODE_HEX,
    MODE_TEXT,
    VIEW_BOTH,
    VIEW_CLIENT,
    VIEW_SERVER,
    follow_stream,
    render_stream,
    summarize,
)

DEMO_COMMANDS = [
    "найди пакеты с айпи 192.168.1.1",
    "пакеты от 10.0.0.5",
    "выведи пакеты на порт 80",
    "найди tcp порт 443",
    "покажи пакеты на порт 80 и 443",
    "покажи мак адрес aa:bb:cc:dd:ee:ff",
    "мак адрес aabb.ccdd.eeff",
    "покажи http трафик",
    "найди dns запросы",
    "покажи icmp трафик",
    "найди пакеты с айпи 192.168.1.100 на порт 8080",
    "покажи пакеты от 192.168.1.1 к 10.0.0.1",
    "просто текст без индикаторов",
    "",
]


def describe_command(command: str) -> None:
    """Печатает результат разбора одной команды."""
    print("=== Команда: {} ===".format(command or "(пустая)"))

    engine = NaturalLanguageFilterEngine()
    query = engine.parse(command)

    print(f"Намерение: {query.intent}")
    if query.entities:
        print("Сущности:")
        for entity in query.entities:
            direction = f"[{entity.direction}]" if entity.direction else ""
            print(f"   - {entity.entity_type:10} {direction:7} {entity.normalized_value}")
    else:
        print("Сущности: не найдены")

    filter_string = generate_filter(query)
    if filter_string:
        print(f"Фильтр Wireshark: {filter_string}")
    else:
        print("Фильтр Wireshark: (пусто)")


def show_packets(pcap_path: str, command: str, limit: int) -> int:
    """Применяет команду к файлу и печатает таблицу."""
    engine = NaturalLanguageFilterEngine()
    query = engine.parse(command)
    filter_string = generate_filter(query)
    if not filter_string:
        print("Не нашёл индикаторов в команде.")
        return 2

    handler = PcapHandler(preview_count=limit)
    result = handler.load_and_filter(pcap_path, filter_string, limit=limit)
    if result.error:
        print(f"Ошибка: {result.error}")
        return 1

    print(f"Фильтр: {filter_string}")
    print(f"Найдено {result.matched_packets} из {result.total_packets} пакетов")
    print("")
    header = "{:>6}  {:>10}  {:>8}  {:>17}  {:>6}  {:>17}  {:>6}  {:>6}".format(
        "Frame", "Time", "Protocol", "Source", "SPort", "Destination", "DPort",
        "Length")
    print(header)
    print("-" * len(header))
    for row in result.rows:
        print("{:>6}  {:>10}  {:>8}  {:>17}  {:>6}  {:>17}  {:>6}  {:>6}".format(
            row.frame, row.time, row.protocol, row.source, row.src_port or "-",
            row.destination, row.dst_port or "-", row.length))
    if result.matched_packets > len(result.rows):
        print(f"... показаны первые {len(result.rows)}")
    return 0


def show_stream(pcap_path: str, frame_number: int, mode: str, view: str) -> int:
    """Печатает содержимое TCP-потока, к которому относится кадр."""
    handler = PcapHandler()
    packets, error = handler.load(pcap_path, keep_payload=True)
    if error:
        print(f"Ошибка: {error}")
        return 1

    stream = follow_stream(packets, frame_number)
    if stream is None:
        print(f"Кадр {frame_number} не найден или это не TCP.")
        return 1

    print(summarize(stream))
    print("")
    print(render_stream(stream, view=view, mode=mode))
    return 0


def main() -> int:
    # Консоль Windows может не знать символов вроде "·" — не падаем на этом.
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(
        description="SmartPCAPParser — фильтры Wireshark из обычных слов",
    )
    parser.add_argument("--demo", action="store_true",
                        help="показать разбор примеров команд")
    parser.add_argument("-c", "--command", type=str, default="",
                        help="команда на русском языке")
    parser.add_argument("--file", type=str, default="",
                        help="применить команду к файлу .pcap/.pcapng")
    parser.add_argument("--limit", type=int, default=20,
                        help="сколько строк показать в консоли (по умолчанию 20)")
    parser.add_argument("--follow", type=int, default=0, metavar="N",
                        help="показать TCP-поток кадра N")
    parser.add_argument("--hex", action="store_true",
                        help="вместе с --follow: hex-дамп вместо текста")
    parser.add_argument("--dir", choices=["both", "client", "server"], default="both",
                        help="вместе с --follow: какое направление показать")
    parser.add_argument("--cli", action="store_true",
                        help="не запускать GUI")

    args = parser.parse_args()

    if args.file and args.follow:
        view = {"both": VIEW_BOTH, "client": VIEW_CLIENT,
                "server": VIEW_SERVER}[args.dir]
        mode = MODE_HEX if args.hex else MODE_TEXT
        return show_stream(args.file, args.follow, mode, view)

    if args.file:
        if not args.command:
            parser.error("для --file нужна команда: -c \"...\"")
        return show_packets(args.file, args.command, args.limit)

    if args.command:
        describe_command(args.command)
        return 0

    if args.demo:
        for command in DEMO_COMMANDS:
            describe_command(command)
        return 0

    if args.cli:
        parser.print_help()
        return 0

    from gui.app import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
