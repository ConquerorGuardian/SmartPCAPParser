"""Скачивание корпуса реальных дампов из открытого репозитория Wireshark.

Нужен, чтобы проверять приложение на настоящем трафике, а не только на
синтетическом примере. Файлы кладутся в samples/ и в репозиторий не
попадают (.gitignore), поэтому tests/test_corpus.py без них просто
пропускается.

Запуск:
    python tools/fetch_samples.py
"""

import json
import urllib.request
from pathlib import Path

API = "https://api.github.com/repos/wireshark/wireshark/contents/test/captures"
TARGET = Path(__file__).resolve().parent.parent / "samples"
SUFFIXES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz")
LIMIT = 34
MAX_BYTES = 4_000_000

# Что интересно проверить в первую очередь.
PREFERRED = (
    "http", "dns", "dhcp", "icmp", "arp", "ipv6", "ipsec", "tcp", "udp",
    "tls", "ssl", "ftp", "smtp", "telnet", "smb", "ntp", "vlan", "gre",
    "sip", "radius", "ldap", "kerberos", "quic", "igmp", "bootp", "snmp",
    "ssh", "http2", "eap", "mdns", "llmnr", "trill", "mpls", "ppp",
)


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def main() -> int:
    TARGET.mkdir(exist_ok=True)
    listing = json.loads(fetch(API).decode("utf-8"))
    files = [
        item for item in listing
        if item.get("type") == "file"
        and item["name"].lower().endswith(SUFFIXES)
        and item.get("size", 0) <= MAX_BYTES
    ]

    def rank(item: dict) -> tuple:
        name = item["name"].lower()
        for index, key in enumerate(PREFERRED):
            if name.startswith(key) or key in name:
                return (index, name)
        return (len(PREFERRED), name)

    files.sort(key=rank)
    chosen = files[:LIMIT]

    total = 0
    for item in chosen:
        destination = TARGET / item["name"]
        if destination.exists() and destination.stat().st_size == item["size"]:
            total += item["size"]
            continue
        try:
            data = fetch(item["download_url"])
        except Exception as exc:                       # noqa: BLE001
            print("  пропуск {}: {}".format(item["name"], exc))
            continue
        destination.write_bytes(data)
        total += len(data)
        print("{:>9}  {}".format(len(data), item["name"]))

    print("")
    print("всего файлов: {}".format(len(list(chosen))))
    print("всего байт: {}".format(total))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
