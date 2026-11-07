"""Тесты запуска Wireshark: аргументы и поиск программы."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gui.wireshark import (  # noqa: E402
    ENV_OVERRIDE,
    build_command,
    find_wireshark,
    open_dump,
)


def test_command_with_filter():
    """Фильтр уходит в Wireshark через -Y, как в документации."""
    command = build_command(
        r"C:\Program Files\Wireshark\Wireshark.exe", r"C:\dump.pcap", "tcp.port==80"
    )
    assert command == [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        "-Y",
        "tcp.port==80",
        "-r",
        r"C:\dump.pcap",
    ], command
    print("PASS: test_command_with_filter")


def test_command_with_frame():
    """Номер пакета уходит через -g: Wireshark открывает нужную строку."""
    command = build_command("wireshark", "dump.pcap", "tcp.port==80", 6)
    assert command == [
        "wireshark",
        "-Y",
        "tcp.port==80",
        "-g",
        "6",
        "-r",
        "dump.pcap",
    ], command
    command = build_command("wireshark", "dump.pcap", "", 6)
    assert command == ["wireshark", "-g", "6", "-r", "dump.pcap"], command
    print("PASS: test_command_with_frame")


def test_command_without_filter():
    """Пустой фильтр не добавляет лишних аргументов."""
    command = build_command("wireshark", "dump.pcapng", "   ")
    assert command == ["wireshark", "-r", "dump.pcapng"], command
    print("PASS: test_command_without_filter")


def test_override_points_to_file():
    """SMARTPCAP_WIRESHARK задаёт путь вручную."""
    handle = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
    handle.close()
    path = Path(handle.name)
    old = os.environ.get(ENV_OVERRIDE)
    os.environ[ENV_OVERRIDE] = str(path)
    try:
        assert find_wireshark() == str(path), find_wireshark()
    finally:
        if old is None:
            os.environ.pop(ENV_OVERRIDE, None)
        else:
            os.environ[ENV_OVERRIDE] = old
        path.unlink(missing_ok=True)
    print("PASS: test_override_points_to_file")


def test_open_without_file():
    """Без открытого дампа кнопка честно говорит, что открывать нечего."""
    ok, message = open_dump("")
    assert not ok
    assert "Сначала откройте файл" in message, message
    ok, message = open_dump("нет-такого-файла.pcap")
    assert not ok
    assert "не найден" in message.lower(), message
    print("PASS: test_open_without_file")


if __name__ == "__main__":
    tests = [
        test_command_with_filter,
        test_command_with_frame,
        test_command_without_filter,
        test_override_points_to_file,
        test_open_without_file,
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
