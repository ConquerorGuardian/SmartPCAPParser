# Примеры команд

Слева то, что вы пишете, справа фильтр, который получится. Всё проверено на
текущей версии.

## Протоколы

| Команда | Фильтр |
| --- | --- |
| `покажи http трафик` | `http` |
| `покажи только dns` | `dns` |
| `только tls` | `tls` |
| `покажи https` | `tls` |
| `покажи tcp` | `tcp` |
| `покажи udp` | `udp` |
| `покажи icmp` | `icmp` |
| `покажи quic` | `quic` |
| `покажи http2` | `http2` |
| `покажи ipv6` | `ipv6` |
| `покажи arp` | `arp` |
| `покажи dhcp` | `dhcp` |
| `покажи ntp` | `ntp` |
| `покажи ssh` | `ssh` |
| `покажи smb` | `smb` |
| `покажи rdp` | `rdp` |
| `покажи ftp` | `ftp` |
| `покажи telnet` | `telnet` |
| `покажи ldap` | `ldap` |
| `покажи snmp` | `snmp` |
| `покажи sip` | `sip` |
| `покажи mqtt` | `mqtt` |
| `покажи ssdp` | `ssdp` |
| `покажи netbios` | `nbns` |
| `покажи ospf` | `ospf` |
| `покажи bgp` | `bgp` |
| `покажи syslog` | `syslog` |
| `покажи kerberos` | `kerberos` |
| `покажи radius` | `radius` |
| `покажи openvpn` | `openvpn` |
| `покажи gre` | `gre` |
| `покажи esp` | `esp` |
| `покажи igmp` | `igmp` |
| `покажи tftp` | `tftp` |
| `покажи vnc` | `vnc` |

## Группы

| Команда | Фильтр |
| --- | --- |
| `покажи почту` | `(smtp or pop3 or imap)` |
| `покажи базы данных` | `(mysql or tds or pgsql or mongo or redis or memcached)` |
| `покажи туннели` | `(openvpn or l2tp or isakmp or gre)` |
| `покажи локальную сеть` | `(arp or llmnr or nbns or ssdp or mdns)` |
| `покажи веб` | `(http or tls)` |
| `покажи все сайты` | `(http or tls or dns)` |
| `покажи удалённый доступ` | `(rdp or ssh or vnc or telnet)` |
| `покажи видеосвязь` | `(sip or stun)` |
| `покажи мониторинг` | `(snmp or syslog)` |
| `покажи файловые серверы` | `(ftp or smb or nfs)` |
| `покажи маршрутизация` | `(bgp or ospf or icmp or igmp)` |

## Адреса и порты

| Команда | Фильтр |
| --- | --- |
| `пакеты с айпи 192.168.1.10` | `ip.addr==192.168.1.10` |
| `пакеты от 10.0.0.5` | `ip.src==10.0.0.5` |
| `пакеты к 8.8.8.8` | `ip.dst==8.8.8.8` |
| `айпи 2001:db8::1` | `ipv6.addr==2001:db8::1` |
| `пакеты на порт 443` | `tcp.port==443` |
| `пакеты на порт 80` | `tcp.port==80` |
| `покажи tcp порт 22` | `tcp.port==22` |
| `покажи udp порт 53` | `udp.port==53` |
| `порты 80 и 443` | `tcp.port==80,443` |
| `покажи порт 80-90` | `tcp.port in {80..90}` |
| `порты от 20 до 23` | `tcp.port in {20..23}` |
| `покажи mac адрес 00:1a:2b:3c:4d:5e` | `eth.addr==00:1a:2b:3c:4d:5e` |

## Сайты

| Команда | Что получится |
| --- | --- |
| `покажи сайт example.com` | HTTP Host, TLS SNI или DNS-имя с `example.com` |
| `покажи трафик на сайт github.com` | то же для `github.com` |
| `покажи все сайты` | `(http or tls or dns)` |

Полный фильтр для имени:

```
(http.host contains "example.com" or tls.handshake.extensions_server_name contains "example.com" or dns.qry.name contains "example.com")
```

## Комбинации

| Команда | Фильтр |
| --- | --- |
| `покажи dns и http` | `(http or dns)` |
| `покажи http или tls` | `(tls or http)` |
| `покажи ssh и rdp` | `(ssh or rdp)` |
| `покажи http с айпи 10.0.0.1` | `ip.addr==10.0.0.1 and http` |
| `покажи http и 192.168.1.10` | `ip.addr==192.168.1.10 and http` |
| `пакеты с айпи 10.0.0.1 и порт 80` | `ip.addr==10.0.0.1 and tcp.port==80` |
| `покажи tcp от 192.168.0.10` | `ip.src==192.168.0.10 and tcp` |
| `пакеты от 192.168.1.1 на порт 443` | `ip.src==192.168.1.1 and tcp.port==443` |
| `покажи http с mac 00:11:22:33:44:55` | `eth.addr==00:11:22:33:44:55 and http` |
| `покажи dns сервер 1.1.1.1` | `ip.addr==1.1.1.1 and dns` |

## Исключения

| Команда | Фильтр |
| --- | --- |
| `покажи http кроме 192.168.1.10` | `not (ip.addr==192.168.1.10) and http` |
| `покажи http кроме порта 80` | `not (tcp.port==80) and http` |
| `покажи dns кроме 8.8.8.8` | `not (ip.addr==8.8.8.8) and dns` |
| `покажи всё кроме arp` | `not (arp)` |

## Весь файл

`покажи весь трафик` и `покажи пакеты` снимают фильтр, видно все пакеты.

## Готовый фильтр Wireshark

Синтаксис можно вставить как есть, приложение отличит его от фразы.

| Вставили | Что будет |
| --- | --- |
| `tcp.port==443` | по порту 443 |
| `ip.addr==10.0.0.1 and http` | адрес и протокол |
| `eth.addr==00:11:22:33:44:55` | по MAC |
| `frame.len > 1000` | крупные кадры |
| `tcp.flags.syn==1` | только SYN |
| `udp.port in {53..54}` | диапазон портов |
| `http.host contains "example.com"` | по имени хоста |

Поддерживаемые поля: `ip.addr`, `ip.src`, `ip.dst`, `ipv6.*`, `tcp.port`,
`udp.port`, `tcp.srcport`, `tcp.dstport`, `eth.addr`, `eth.src`, `eth.dst`,
`frame.number`, `frame.len`, `ip.len`, `ip.ttl`, `tcp.len`,
`tcp.window_size`, `tcp.seq`, `tcp.ack`, `tcp.flags.*`, `udp.length`,
`icmp.type`, `icmp.code`, `http.host`, `http.request.uri`, `tls.sni`,
`tls.handshake.extensions_server_name`, `dns.qry.name`, `tcp contains …`,
`udp contains …` и имена протоколов.

## Чего нет

- размеров и времени по-русски («пакеты больше 1000 байт»), но
  `frame.len > 1000` работает;
- `tcp.analysis.*` и `http.response.*`;
- регулярных выражений из фразы;
- расшифровки TLS.

## Проверить самому

```bash
python main.py --file tests/sample_traffic.pcap -c "покажи сайт example.com"
tshark -r tests/sample_traffic.pcap -Y "http"
```
