"""
Прогон на реальных дампах.

Папка samples/ не входит в репозиторий: файлы скачиваются скриптом
tools/fetch_samples.py (или любым своим способом). Если папки нет,
тест не падает, а честно говорит, что проверять нечего.

Смысл теста: на синтетике всё всегда хорошо. Здесь ловятся настоящие
проблемы — экзотические типы кадров, сжатые файлы, странные протоколы.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.engine import NaturalLanguageFilterEngine
from parser.filters import generate_filter
from parser.matcher import compile_filter
from parser.pcap_handler import PcapHandler
from parser.stats import conversations, endpoints, protocol_hierarchy, summary
from parser.verdict import build_verdict

SAMPLES = PROJECT_ROOT / "samples"
MAX_BYTES = 5_000_000

COMMANDS = (
    "покажи tcp трафик",
    "покажи udp трафик",
    "покажи http трафик",
    "покажи dns трафик",
    "покажи icmp трафик",
    "покажи arp трафик",
    "покажи tls трафик",
    "покажи http трафик с айпи 192.168.1.1",
    "покажи пакеты на порт 443",
    "порты 1024-65535",
    "не http",
    "покажи пакеты с айпи 2001:db8::1",
    "покажи пакеты с мак адресом ff:ff:ff:ff:ff:ff",
    "покажи всё кроме 8.8.8.8",
)


def sample_files() -> list[Path]:
    if not SAMPLES.exists():
        return []
    return sorted(
        path for path in SAMPLES.iterdir()
        if path.is_file() and path.stat().st_size <= MAX_BYTES
    )


def test_corpus_reads_and_filters():
    files = sample_files()
    if not files:
        print("SKIP: test_corpus_reads_and_filters (нет папки samples/)")
        return

    handler = PcapHandler()
    engine = NaturalLanguageFilterEngine()
    total_packets = 0
    failures: list[str] = []

    for path in files:
        packets, error = handler.load(path)
        if error:
            failures.append(f"{path.name}: чтение — {error}")
            continue
        if not packets:
            failures.append(f"{path.name}: 0 пакетов")
            continue

        total_packets += len(packets)

        for command in COMMANDS:
            query = engine.parse(command)
            filter_string = generate_filter(query)
            try:
                predicate = compile_filter(filter_string)
                handler.apply(packets, filter_string)
            except Exception as exc:                   # noqa: BLE001
                failures.append(
                    f"{path.name}: команда «{command}» → {filter_string}: {exc}"
                )
                continue
            # Фильтр должен быть вычислим и не падать на каждом пакете.
            for packet in packets[:50]:
                predicate(packet)

        try:
            build_verdict(packets)
            summary(packets)
            protocol_hierarchy(packets)
            conversations(packets)
            endpoints(packets)
        except Exception as exc:                       # noqa: BLE001
            failures.append(
                f"{path.name}: вердикт/статистика — {type(exc).__name__}: {exc}"
            )

    assert not failures, "проблемы на реальных дампах:\n  " + "\n  ".join(failures[:12])
    print(f"PASS: test_corpus_reads_and_filters ({len(files)} файлов, {total_packets} пакетов)")


def test_corpus_gzip():
    """Сжатые дампы (.pcap.gz, .pcapng.gz) читаются как обычные."""
    files = [path for path in sample_files() if path.suffix == ".gz"]
    if not files:
        print("SKIP: test_corpus_gzip (нет сжатых файлов)")
        return

    handler = PcapHandler()
    for path in files:
        packets, error = handler.load(path)
        assert error is None, f"{path.name}: {error}"
        assert packets, f"{path.name}: ноль пакетов"
    print(f"PASS: test_corpus_gzip ({len(files)} файлов)")


def test_corpus_undecodable_are_reported():
    """Если кадры не разбираются, вердикт говорит об этом, а не молчит."""
    files = sample_files()
    if not files:
        print("SKIP: test_corpus_undecodable_are_reported (нет папки samples/)")
        return

    handler = PcapHandler()
    checked = 0
    for path in files:
        packets, error = handler.load(path)
        if error or not packets:
            continue
        broken = sum(1 for packet in packets if (packet.protocol or "") == "?")
        if broken and broken >= 0.3 * len(packets):
            verdict = build_verdict(packets)
            titles = [finding.title for finding in verdict.findings]
            assert "Формат кадра не поддерживается" in titles, (
                f"{path.name}: вердикт не заметил {broken} неразобранных пакетов, находки: {titles}"
            )
            checked += 1

    print(f"PASS: test_corpus_undecodable_are_reported ({checked} файлов)")


def main() -> int:
    tests = [
        test_corpus_reads_and_filters,
        test_corpus_gzip,
        test_corpus_undecodable_are_reported,
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
