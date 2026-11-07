"""
Обработка PCAP-файлов: загрузка, фильтрация, превью, экспорт.

Модуль собран поверх собственного ридера (pcap_reader) и собственного
вычислителя фильтров (matcher), поэтому не требует установленного
Wireshark/tshark.

Типовой сценарий:

    handler = PcapHandler(preview_count=200)
    result = handler.load_and_filter("capture.pcap", "ip.addr==192.168.1.1")
    for row in result.rows:
        print(row.frame, row.source, "->", row.destination)
"""

import csv
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .matcher import FilterError, compile_filter
from .pcap_reader import Packet, PcapError, read_packets

COLUMNS = [
    "Frame",
    "Time",
    "Protocol",
    "Source",
    "Src Port",
    "Destination",
    "Dst Port",
    "Length",
    "Info",
]


@dataclass
class PacketRow:
    """Строка таблицы результатов."""

    frame: int
    time: str
    protocol: str
    source: str
    destination: str
    length: int
    info: str
    src_port: str = ""
    dst_port: str = ""

    def to_dict(self) -> dict:
        return {
            "Frame": self.frame,
            "Time": self.time,
            "Protocol": self.protocol,
            "Source": self.source,
            "Src Port": self.src_port,
            "Destination": self.destination,
            "Dst Port": self.dst_port,
            "Length": self.length,
            "Info": self.info,
        }


@dataclass
class PcapResult:
    """Результат обработки файла захвата."""

    total_packets: int = 0          # пакетов в файле
    matched_packets: int = 0        # пакетов, прошедших фильтр
    rows: list[PacketRow] = field(default_factory=list)   # превью
    filter_applied: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class PcapHandler:
    """Загрузка, фильтрация и экспорт пакетов."""

    DEFAULT_PREVIEW_COUNT = 200

    def __init__(self, preview_count: int = DEFAULT_PREVIEW_COUNT) -> None:
        self.preview_count = preview_count
        # Файл прочитан не до конца: текст предупреждения для интерфейса.
        self.last_warning: str | None = None

    # ------------------------------------------------------------------
    # Основная работа
    # ------------------------------------------------------------------
    def load_and_filter(
        self,
        pcap_path: str | Path,
        display_filter: str,
        limit: int | None = None,
    ) -> PcapResult:
        """
        Читает файл, применяет фильтр и возвращает превью строк.

        Args:
            pcap_path: Путь к .pcap/.pcapng.
            display_filter: Display-фильтр Wireshark (поддерживается подмножество).
            limit: Сколько строк вернуть в превью; None — использовать preview_count,
                -1 — вернуть все совпадения.

        Returns:
            PcapResult. При ошибке поле error заполнено, rows пуст.
        """
        display_filter = (display_filter or "").strip()

        packets, error = self.load(pcap_path)
        if error is not None:
            return PcapResult(filter_applied=display_filter, error=error)

        return self.apply(packets, display_filter, limit=limit)

    def load(self, pcap_path: str | Path,
             keep_payload: bool = False,
             progress=None,
             should_stop=None) -> tuple[list[Packet], str | None]:
        """
        Читает файл и возвращает (пакеты, ошибка).

        Разбор делается один раз: результат можно применять к разным фильтрам.

        Args:
            pcap_path: Путь к .pcap/.pcapng.
            keep_payload: Хранить данные TCP — нужно для сборки потока.
            progress: Обратный вызов прогресса (доля 0..1 или None).
            should_stop: Проверка отмены чтения; True — прекратить.
        """
        try:
            warnings: list[str] = []
            packets, _linktype = read_packets(
                pcap_path,
                keep_payload=keep_payload,
                progress=progress,
                should_stop=should_stop,
                warnings=warnings,
            )
            self.last_warning = " ".join(dict.fromkeys(warnings)) or None
            return packets, None
        except PcapError as exc:
            self.last_warning = None
            return [], str(exc)

    def apply(
        self,
        packets: list[Packet],
        display_filter: str,
        limit: int | None = None,
    ) -> PcapResult:
        """Применяет фильтр к уже прочитанным пакетам."""
        display_filter = (display_filter or "").strip()

        try:
            predicate = compile_filter(display_filter)
        except FilterError as exc:
            return PcapResult(total_packets=len(packets),
                              filter_applied=display_filter,
                              error=str(exc))

        if limit is None:
            limit = self.preview_count
        if limit < 0:
            limit = None

        first_timestamp = packets[0].timestamp if packets else 0.0
        rows: list[PacketRow] = []
        matched = 0

        for packet in packets:
            if not predicate(packet):
                continue
            matched += 1
            if limit is None or len(rows) < limit:
                rows.append(self._to_row(packet, first_timestamp))

        return PcapResult(
            total_packets=len(packets),
            matched_packets=matched,
            rows=rows,
            filter_applied=display_filter,
        )

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    @staticmethod
    def _to_row(packet: Packet, first_timestamp: float) -> PacketRow:
        relative = packet.timestamp - first_timestamp
        data = packet.to_row(relative_time=relative)
        return PacketRow(
            frame=data["Frame"],
            time=data["Time"],
            protocol=data["Protocol"],
            source=data["Source"],
            destination=data["Destination"],
            length=data["Length"],
            info=data["Info"],
            src_port=data["Src Port"],
            dst_port=data["Dst Port"],
        )

    # ------------------------------------------------------------------
    # Экспорт
    # ------------------------------------------------------------------
    def export_to_csv(self, result: PcapResult, output_path: str | Path) -> str:
        """Экспортирует строки результата в CSV (UTF-8 с BOM для Excel)."""
        rows: Iterable[PacketRow] = result.rows
        return self.export_rows_to_csv(rows, output_path)

    def export_rows_to_csv(
        self,
        rows: Iterable[PacketRow],
        output_path: str | Path,
    ) -> str:
        """Экспортирует произвольный набор строк в CSV."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS, delimiter=";")
            writer.writeheader()
            for row in rows:
                writer.writerow(row.to_dict())

        return str(output_path)
