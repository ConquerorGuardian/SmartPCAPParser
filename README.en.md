# Smart PCAP Parser

Type a Russian phrase, get a Wireshark display filter and the matching packets.
No tshark, no Wireshark, no AI.

Instead of `ip.addr==192.168.1.10 and tcp.port==80` you write
`покажи http трафик с айпи 192.168.1.10`. The app builds the filter, shows it
above the table and applies it to the capture. The same line can be pasted into
Wireshark.

![Main window](docs/screenshot.png)

The UI is Russian only. Filter syntax, protocol names and generated Wireshark
strings are language independent, so the app also works as a plain pcap viewer.

## Run

The released `SmartPCAPParser.exe` needs no Python. Windows SmartScreen shows a
warning for an unsigned build: "More info" → "Run anyway". Details in
[docs/FAQ.md](docs/FAQ.md) (Russian).

From source:

```bash
pip install -r requirements.txt
python main.py
```

Python 3.11+, `customtkinter`, standard library for everything else.

## Phrases

| You type | You get |
| --- | --- |
| `пакеты с айпи 192.168.1.1` | `ip.addr==192.168.1.1` |
| `пакеты от 10.0.0.5` | `ip.src==10.0.0.5` |
| `на порт 80` | `tcp.port==80` |
| `порты 80 и 443` | `tcp.port==80,443` |
| `покажи http трафик` | `http` |
| `покажи сайт example.com` | Host, SNI or DNS name |
| `не http` | `not (http)` |
| `покажи почту` | `(smtp or pop3 or imap)` |

Word order and endings do not matter. Everyday names work too: `общая папка` is
`smb`, `пинг` is `icmp`. A ready filter is accepted as is:

```
tcp.port==443
ip.addr==10.0.0.1 and http
frame.len > 1000
```

## Simple and experienced mode

First start is simple: open a file, type a phrase, Enter. Six protocol buttons,
the rest under "Ещё…", no side cards. One switch at the bottom left brings back
examples, all 22 buttons and the verdict strip. The choice is remembered.

## Streams and details

"Поток TCP" (`Ctrl+T`) reassembles a connection by address:port, orders
segments by sequence number, drops duplicates and marks gaps. UDP gets a
datagram view. Both windows have direction and text/hex switches, copy and save.

Double click a row for the layer breakdown: Frame, Ethernet, IP, TCP/UDP,
names, application, hex dump.

## Verdict

Experienced mode shows a short plain-language summary above the table: packet
count, volume, duration, top protocols, busiest pair, visible sites. Then
findings: unanswered SYN, RST, DNS without answers, ARP noise, SMB/RDP/Telnet/
VNC/MySQL/FTP from local hosts, port scans, ICMP errors, broadcast storm, top
talker, undecodable frames. Each finding has a button that applies its filter.
Simple mode opens the same text with "Проверить файл".

## Statistics

Traffic chart, protocol hierarchy, hosts, conversations, endpoints, over the
whole file or the current filter. Right click a row to jump back to packets
with the right filter.

## Limits

- IPv6 extension chains up to four headers.
- Not the whole Wireshark syntax: `tcp.analysis.*` and `http.response.*` are
  missing.
- Headers stay in memory, payloads are read on demand up to 64 MB per stream.
  Up to 50 000 rows are shown at once, bigger results are paged by 5 000.
- ATM, MTP2 and Frame Relay frames are not decoded.
- No TLS decryption.
- Findings are structural, not reputation based. The app says "this host sends
  one way only" or "this repeats on a schedule", not "this is C2".

## Build and tests

```bash
python tools/build_exe.py          # single file
python tools/build_exe.py --onedir # folder
python -m tests.run_all            # 180 checks
python tools/bench.py --mb 100     # speed
```

## License

MIT, see [LICENSE](LICENSE). Russian version: [README.md](README.md).
