"""
SmartPCAPParser — точка входа.

Без аргументов запускает графический интерфейс.
Консольный режим удобен для проверки движка:

    python main.py --demo
    python main.py -c "покажи http трафик"
    python main.py --file tests/sample_traffic.pcap -c "выведи пакеты на порт 80"
    python main.py --version
    python main.py --selftest
"""

import argparse
import os
import sys
import tempfile
import time
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# У собранного exe без консоли падение иначе не увидеть. Файл живёт в %TEMP%,
# а если тот недоступен (бывает на чужой машине) — рядом с exe.
def crash_log_path() -> Path:
    """Куда писать трейсбек: первая папка, в которую реально можно писать."""
    folders = []
    for variable in ("TEMP", "TMP"):
        value = os.environ.get(variable)
        if value:
            folders.append(Path(value))
    if getattr(sys, "frozen", False):
        folders.append(Path(sys.executable).resolve().parent)
    folders.append(Path.cwd())
    for folder in folders:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            probe = folder / ".smartpcap_write_test"
            probe.write_text("", encoding="utf-8")
            probe.unlink()
            return folder / "smartpcap_crash.txt"
        except OSError:
            continue
    return Path("smartpcap_crash.txt")


CRASH_LOG = crash_log_path()
if sys.stdout is None:
    try:
        with CRASH_LOG.open("a", encoding="utf-8") as _start_log:
            _start_log.write(
                "start {} {}\n".format(
                    time.strftime("%Y-%m-%d %H:%M:%S"), sys.argv[1:]
                )
            )
    except OSError:
        pass

from parser.engine import NaturalLanguageFilterEngine  # noqa: E402
from parser.filters import generate_filter  # noqa: E402
from parser.matcher import compile_filter  # noqa: E402
from parser.pcap_handler import PcapHandler  # noqa: E402
from parser.streams import (  # noqa: E402
    MODE_HEX,
    MODE_TEXT,
    VIEW_BOTH,
    VIEW_CLIENT,
    VIEW_SERVER,
    follow_datagram_flow,
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


def app_version() -> str:
    """Версия приложения — из parser/__init__.py, чтобы был один источник."""
    try:
        from parser import __version__

        return __version__
    except Exception:                        # noqa: BLE001 — версия не критична
        return "unknown"


def resource_path(relative: str) -> Path:
    """Путь к ресурсу и в исходниках, и внутри собранного exe (PyInstaller)."""
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        candidate = Path(bundled) / relative
        if candidate.exists():
            return candidate
    return PROJECT_ROOT / relative


def describe_command(command: str) -> None:
    """Печатает результат разбора одной команды."""
    print(f"=== Команда: {command or '(пустая)'} ===")

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


def run_selftest() -> int:
    """Самопроверка собранного приложения: чтение, фильтры, потоки.

    Печатает отчёт, если есть консоль, и всегда пишет его в файл
    `smartpcap_selftest.txt` во временной папке — это позволяет проверить
    exe, собранный без консоли.
    """
    sample = resource_path("tests/sample_traffic.pcap")
    lines: list[str] = []
    failures = 0

    def check(name: str, ok: bool, extra: str = "") -> None:
        nonlocal failures
        if not ok:
            failures += 1
        lines.append(("OK   " if ok else "FAIL ") + name + ((" — " + extra) if extra else ""))

    check("файл примера найден", sample.exists(), str(sample))
    packets, error = PcapHandler().load(str(sample), keep_payload=True)
    check("дамп прочитан", error is None and len(packets) == 13,
          "пакетов {}".format(len(packets) if packets else 0) if not error else str(error))

    try:
        engine = NaturalLanguageFilterEngine()
        filter_string = generate_filter(engine.parse("покажи сайт example.com"))
        matched = sum(1 for packet in packets if compile_filter(filter_string)(packet))
        check("фильтр по имени сайта", matched == 3, "совпадений {}".format(matched))
    except Exception as exc:                 # noqa: BLE001 — проверяем любой сбой
        check("фильтр по имени сайта", False, "{}: {}".format(type(exc).__name__, exc))

    try:
        stream = follow_stream(packets, 6)
        check("поток TCP", stream is not None and stream.total_bytes > 0)
    except Exception as exc:                 # noqa: BLE001
        check("поток TCP", False, "{}: {}".format(type(exc).__name__, exc))

    try:
        datagram = follow_datagram_flow(packets, 2)
        check("поток UDP", datagram is not None and datagram.total_bytes > 0)
    except Exception as exc:                 # noqa: BLE001
        check("поток UDP", False, "{}: {}".format(type(exc).__name__, exc))

    try:
        from gui.app import SmartPcapApp

        check("интерфейс собран", isinstance(SmartPcapApp, type))
    except Exception as exc:                 # noqa: BLE001 — в т.ч. нет дисплея
        check("интерфейс собран", False, "{}: {}".format(type(exc).__name__, exc))

    icon = resource_path("assets/app.ico")
    check("иконка на месте", icon.exists(), str(icon))

    lines.append("")
    lines.append("Версия: {}".format(app_version()))
    lines.append("Python: {}".format(sys.version.split()[0]))
    lines.append("Итог: {}".format("OK" if not failures else "ошибок {}".format(failures)))
    report = "\n".join(lines)

    if sys.stdout is not None:
        try:
            print(report)
        except Exception:                    # noqa: BLE001 — консоли может не быть
            pass
    try:
        target = Path(tempfile.gettempdir()) / "smartpcap_selftest.txt"
        target.write_text(report + "\n", encoding="utf-8")
        if sys.stdout is not None:
            print("Отчёт: {}".format(target))
    except OSError:
        pass

    return 0 if not failures else 1


def build_parser() -> argparse.ArgumentParser:
    """Аргументы командной строки (вынесено для тестов)."""
    parser = argparse.ArgumentParser(
        prog="smartpcap",
        description="SmartPCAPParser — фильтры Wireshark из обычных слов",
        epilog=(
            "Примеры:\n"
            "  smartpcap                                  открыть приложение\n"
            "  smartpcap dump.pcap                        открыть файл в окне\n"
            "  smartpcap --file dump.pcap -c \"покажи http трафик\"\n"
            "  smartpcap --file dump.pcap --follow 6 --hex\n"
            "  smartpcap --demo\n"
            "  smartpcap --selftest"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version",
                        version="Smart PCAP Parser {}".format(app_version()))
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
    parser.add_argument("--selftest", action="store_true",
                        help="проверить сборку без окна и выйти")
    parser.add_argument("--cli", action="store_true",
                        help="не запускать GUI")
    parser.add_argument("path", nargs="?", default="", metavar="ФАЙЛ",
                        help="открыть .pcap/.pcapng в окне приложения")
    parser.add_argument("--open", dest="open_path", default="", metavar="ФАЙЛ",
                        help="то же, что и просто указать файл")
    return parser


def _install_crash_log() -> None:
    """Пишет трейсбек в %TEMP% или рядом с exe: без консоли иначе не увидеть."""
    global CRASH_LOG
    CRASH_LOG = crash_log_path()

    def hook(exc_type, exc, tb):
        try:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            text = "".join(traceback.format_exception(exc_type, exc, tb))
            with CRASH_LOG.open("a", encoding="utf-8") as file:
                file.write("\n=== {} ===\n{}\n".format(stamp, text))
        except Exception:                    # noqa: BLE001 — лог не должен мешать
            pass

    sys.excepthook = hook


def main() -> int:
    # У exe без консоли (--windowed) sys.stdout/sys.stderr равны None,
    # и любой print падал бы с AttributeError. Подменяем на «в никуда»:
    # код возврата при этом остаётся рабочим.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")

    # Консоль Windows может не знать символов вроде "·" — не падаем на этом.
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

    parser = build_parser()
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

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

    # `SmartPCAPParser.exe dump.pcap` (или файл перетащили на иконку)
    # открывает окно сразу с этим файлом. Ошибку в пути покажет окно.
    from gui.app import main as gui_main

    initial_file = args.open_path or args.path
    try:
        gui_main(initial_file or None)
    finally:
        # Окно закрылось штатно: метка запуска из журнала больше не нужна.
        # Если приложение упало, файл останется вместе с трейсбеком.
        try:
            CRASH_LOG.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    _install_crash_log()
    sys.exit(main())
