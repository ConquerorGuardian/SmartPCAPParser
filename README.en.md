# Smart PCAP Parser

Turn a Russian sentence into a Wireshark display filter and see the matching
packets right away. No tshark, no Wireshark, no AI.

Wireshark wants filters like this:

```
ip.addr==192.168.1.10 and tcp.port==80
```

Here you type this:

```
покажи http трафик с айпи 192.168.1.10
```

The app pulls the addresses, ports and protocols out of the phrase, builds a
valid display filter, applies it to the capture and fills the table. The filter
itself can be copied into Wireshark.

The phrase language is Russian. Filter syntax, protocol names and the generated
Wireshark strings are language independent, so the app also works as a plain
pcap viewer with a human front end.

## Features

- Reads `.pcap` and `.pcapng`, including `.gz`, with the standard library only.
- Ethernet with VLAN, raw IP, loopback, Linux SLL/SLL2, plain IPv4/IPv6 frames.
- IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6, IGMP, GRE, ESP, AH, OSPF.
- Application protocols: HTTP, HTTP/2, DNS, TLS, QUIC, SSH, FTP, SMTP, NTP,
  DHCP, DHCPv6, Telnet, POP3, IMAP, LDAP, SMB, RDP, MySQL, mDNS, LLMNR, SSDP,
  NetBIOS, RADIUS, BGP, XMPP, IRC, L2TP, IPsec, MSSQL, PostgreSQL, MongoDB,
  Redis, Memcached, NFS, SIP, SNMP, TFTP, VNC, MQTT, Kerberos, Syslog, STUN,
  OpenVPN, SOCKS.
- Some protocols are recognised by content, not by port: HTTP/2 preface, HTTP
  request lines, TLS handshake, SSH banner, SIP methods, MQTT CONNECT, DNS over
  TCP.
- Names from traffic: HTTP Host, TLS SNI and DNS query, shown in the table,
  searchable, summarised in statistics and in the verdict.
- IPv4 and IPv6 defragmentation before TCP/UDP decoding.
- Follow TCP stream and follow UDP conversation, as text or hex.
- Own filter evaluator: addresses, ports, MACs, numeric fields, TCP flags,
  string fields, `contains`, `matches`, `in {…}`.
- A ready Wireshark filter can be pasted as is: `tcp.port==443`,
  `ip.addr==10.0.0.1 and http`, `frame.len > 1000`.
- Table, search, sorting, paging, CSV export, packet details with hex dump.
- Statistics: traffic chart, protocol hierarchy, conversations, endpoints,
  hosts, on the whole file or on the current filter.
- Plain-language verdict with findings, each one can be applied as a filter.
- Dark and light theme, settings and recent files survive restarts.
- 178 checks in 12 test modules, 54 real captures in the corpus run.

## Install and run

One file, no installer, no Python. Take it from
[Releases](../../releases):

| File | What it is |
| --- | --- |
| `SmartPCAPParser.exe` | the whole app in one file, about 13 MB |
| `SmartPCAPParser-<version>-windows-x64.zip` | the same app as a folder |
| `SHA256SUMS.txt` | checksums |

Direct link to the latest build:

```
https://github.com/Whitemoneydealer/SmartPCAPParser/releases/latest/download/SmartPCAPParser.exe
```

Open a capture with the «Открыть файл» button, by dropping it into the window,
or from the command line:

```
SmartPCAPParser.exe C:\dumps\capture.pcap
```

A file dropped on the exe icon opens too. The exe is not code-signed, so
SmartScreen may warn, which is normal here. Check a build with
`SmartPCAPParser.exe --selftest` (exit code 0). Updating means replacing the
exe, settings stay.

From source:

```bash
git clone https://github.com/Whitemoneydealer/SmartPCAPParser.git
cd SmartPCAPParser
pip install -r requirements.txt
python main.py
```

The only runtime dependency is `customtkinter`. On Windows `run.bat` does the
same and tells you what to install if something is missing. Optional:
`pip install tkinterdnd2` enables drag and drop into the window.

CLI:

```bash
python main.py --version
python main.py --demo
python main.py dump.pcap
python main.py --file tests/sample_traffic.pcap -c "покажи http трафик"
python main.py --file tests/sample_traffic.pcap --follow 6 --hex
python main.py --selftest
```

## Build

```bash
pip install -r requirements-dev.txt
python tools/make_icon.py                # regenerate assets/app.ico, needs Pillow
python tools/build_exe.py                # one file
python tools/build_exe.py --both         # file and folder, the way CI does it
python tools/check_exe.py dist/SmartPCAPParser.exe
```

`dist/SHA256SUMS.txt` is written next to the artifacts. A `v*` tag runs the
tests, builds both variants, self-tests them and publishes to Releases.

## Tests

```bash
python -m tests.run_all      # all modules
python -m tests.test_engine  # one module
```

Golden tests pin filter behaviour to packet numbers on a fixed capture. GUI
smoke tests open the real window and walk the main flows.

Real captures:

```bash
python tools/fetch_samples.py   # 54 files into samples/
python -m tests.test_corpus
```

## Benchmarks

`python tools/bench.py --mb 40` on a synthetic dump, 237 000 packets:

| Step | Result |
| --- | --- |
| Parse headers | 2.5 s, about 94 000 packets per second |
| Parse with payloads | 2.7 s |
| Filter `tcp.port==80 and frame.len > 100` | 0.30 s |
| Assemble one TCP stream | 0.09 s |

## How it works

```
phrase -> engine -> filters -> matcher -> pcap_reader -> GUI
                                    \-> stats / verdict / streams
```

| Module | Purpose |
| --- | --- |
| `parser/engine.py` | phrase parsing: addresses, ports, MACs, names, protocols |
| `parser/filters.py` | display filter construction |
| `parser/matcher.py` | compile and evaluate the filter on packets |
| `parser/pcap_reader.py` | pcap/pcapng, headers, defragmentation, names |
| `parser/streams.py` | TCP streams, UDP conversations |
| `parser/stats.py` | timeline, hierarchy, conversations, endpoints, hosts |
| `parser/verdict.py` | summary and findings |
| `parser/settings.py` | UI settings between runs |
| `gui/app.py` | loading, commands, theme, settings |
| `gui/layout.py` | widgets |
| `gui/table_view.py` | packet table |
| `gui/stats_view.py`, `gui/chart.py` | statistics tab and chart |
| `gui/dialogs.py`, `gui/help_text.py` | help, details, stream, verdict |

Every module starts with a short description of what it does.

## Limitations

- IPv6: no extension header chain deeper than four.
- Not the whole Wireshark syntax: `tcp.analysis.*` and `http.response.*` are
  missing.
- Headers of the whole file stay in memory. Payloads are read on demand, up to
  64 MB per stream. The table keeps 500 000 rows, use filters on bigger files.
- Exotic link types (ATM, MTP2, Frame Relay) are reported as unsupported.
- No TLS decryption.

 
