"""Golden-тесты: фиксированные фильтры → фиксированные номера кадров.

Смысл: если правка в reader/matcher/engine незаметно поменяет семантику,
эти тесты упадут с конкретным расхождением. Плюс проверяется, что все
команды из подсказок и примеров интерфейса дают рабочий фильтр.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.engine import NaturalLanguageFilterEngine
from parser.filters import FilterGenerator, generate_filter
from parser.matcher import FilterError, compile_filter
from parser.pcap_reader import read_packets

SAMPLE = Path(__file__).parent / "sample_traffic.pcap"
PACKETS, _ = read_packets(SAMPLE, keep_payload=True)

# фильтр → кадры, которые обязаны совпасть (дамп tests/sample_traffic.pcap)
GOLDEN = [
    ("arp", [1]),
    ("dns", [2, 3]),
    ("http", [6, 7]),
    ("tls", [8]),
    ("ssh", [12]),
    ("icmp", [9, 10]),
    ("quic", [13]),
    ("tcp.port==80", [4, 5, 6, 7]),
    ("udp.port==53", [2, 3]),
    ("icmp.type==8", [9]),
    ("tcp.flags.syn==1 and tcp.flags.ack==0", [4, 11]),
    ("tcp.flags.syn==1 and tcp.flags.ack==1", [5]),
    ("frame.len > 100", [6, 7]),
    ("tcp.len > 0", [6, 7, 8, 12]),
    ("frame.len in {54..80}", [2, 4, 5, 11, 12, 13]),
    ("frame.number <= 4", [1, 2, 3, 4]),
    ('http.host contains "example"', [6]),
    ("dns.qry.name == example.com", [2, 3]),
    ("http.host or dns.qry.name", [2, 3, 6]),
    ("not arp", [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
    ("ip.ttl == 64", [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
]


def matched_frames(filter_string: str) -> list[int]:
    predicate = compile_filter(filter_string)
    return [packet.number for packet in PACKETS if predicate(packet)]


def test_golden_filters():
    """Каждый golden-фильтр даёт ровно ожидаемые кадры."""
    failures = []
    for filter_string, expected in GOLDEN:
        actual = matched_frames(filter_string)
        if actual != expected:
            failures.append("{}: ожидалось {}, получено {}".format(
                filter_string, expected, actual))
    assert not failures, "; ".join(failures)
    print("PASS: test_golden_filters ({} фильтров)".format(len(GOLDEN)))


def test_golden_is_deterministic():
    """Повторный разбор того же фильтра даёт тот же результат."""
    for filter_string, expected in GOLDEN[:6]:
        assert matched_frames(filter_string) == expected
        assert matched_frames(filter_string) == expected
    print("PASS: test_golden_is_deterministic")


def test_engine_commands_all_compile():
    """Все команды из приложения превращаются в рабочий фильтр."""
    try:
        from gui.theme import EXAMPLE_COMMANDS, QUICK_FILTERS
    except ImportError:                       # структура GUI могла отличаться
        from gui.app import EXAMPLE_COMMANDS, QUICK_FILTERS

    engine = NaturalLanguageFilterEngine()

    def as_command(pair) -> str:
        """В QUICK_FILTERS пара может быть (заголовок, команда) или наоборот."""
        first, second = pair
        for candidate in (second, first):
            try:
                if generate_filter(engine.parse(candidate)):
                    return candidate
            except Exception:              # noqa: BLE001 — проверяем оба варианта
                continue
        return second

    commands = [as_command(pair) for pair in QUICK_FILTERS]
    commands += list(EXAMPLE_COMMANDS)
    assert len(commands) >= 40, len(commands)

    broken = []
    for command in commands:
        try:
            filter_string = generate_filter(engine.parse(command))
        except Exception as exc:              # noqa: BLE001 — ловим всё
            broken.append("{} ({}: {})".format(command, type(exc).__name__, exc))
            continue
        if not filter_string:
            broken.append("{} (пустой фильтр)".format(command))
            continue
        try:
            compile_filter(filter_string)
        except FilterError as exc:
            broken.append("{} → {} ({})".format(command, filter_string, exc))

    assert not broken, "сломались команды: " + "; ".join(broken[:6])
    print("PASS: test_engine_commands_all_compile ({} команд)".format(len(commands)))


def test_filter_validate():
    """FilterGenerator.validate отличает рабочий фильтр от мусора."""
    assert FilterGenerator.validate("") is True
    assert FilterGenerator.validate("http and tcp.port==443") is True
    assert FilterGenerator.validate('http.host contains "example"') is True
    assert FilterGenerator.validate("tcp.port==80 and") is False
    assert FilterGenerator.validate("совсем не фильтр") is False
    print("PASS: test_filter_validate")


def test_selftest_entrypoint():
    """`--selftest` проходит на тестовом дампе."""
    import main as entry

    assert entry.run_selftest() == 0
    print("PASS: test_selftest_entrypoint")


def test_version_is_single_source():
    """Версия в одном месте и совпадает с тем, что печатает CLI."""
    import main as entry
    import parser

    assert parser.__version__.count(".") == 2, parser.__version__
    assert entry.app_version() == parser.__version__
    print("PASS: test_version_is_single_source")


def main() -> int:
    tests = [
        test_golden_filters,
        test_golden_is_deterministic,
        test_engine_commands_all_compile,
        test_filter_validate,
        test_selftest_entrypoint,
        test_version_is_single_source,
    ]

    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            print("FAIL: {}: {}".format(test.__name__, exc))
            failed += 1
        except Exception as exc:                       # noqa: BLE001
            print("FAIL: {}: {}: {}".format(test.__name__, type(exc).__name__, exc))
            failed += 1

    print("")
    print("-" * 40)
    print("Пройдено: {}/{}".format(len(tests) - failed, len(tests)))
    if failed:
        print("Есть падения.")
        return 1
    print("Все тесты прошли!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
