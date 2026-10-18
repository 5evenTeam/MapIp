# MapIp — Network Host Mapper

**MapIp maps the hosts on your own network.** It does not geolocate IP
addresses. It does not report physical location, country, or ISP. It is not an
IP-to-location tool.

MapIp is a cross-platform network host discovery and inventory tool with a
terminal UI and a command line that share one core. It is inspired by the
ergonomics of Nmap, Angry IP Scanner and Advanced IP Scanner, but it ships as
a single self-contained binary with no runtime and gives you continuous
monitoring, change detection and multi-protocol name resolution out of the
box.

## What it does

- **Discovery** — ARP, ICMP, TCP ping, UDP ping. Works without root or
  administrator privileges on Windows (via `SendARP` / `IcmpSendEcho`).
- **Inventory** — MAC address, OUI vendor (IEEE registry, 46,000+ prefixes),
  TTL-based OS family, reverse DNS, mDNS, NetBIOS, LLMNR, HTTP/HTTPS title.
- **Port scan** — concurrent TCP connect scan with banner grabbing and service
  detection (optional, `--port-scan`).
- **Continuous monitoring** — rescan and diff: new hosts, missing hosts,
  opened/closed ports, MAC and hostname changes.
- **Wake-on-LAN** — send a magic packet to any discovered MAC.
- **RemoteMap** — consent-based, encrypted remote host access between machines
  you own (`mapip remotemap`). See [docs/remotemap.md](docs/remotemap.md).
- **Export** — table, CSV, JSON, HTML report, Nmap-compatible XML.

## What it does not do

- It does not geolocate IP addresses.
- It does not perform third-party IP lookups.
- It does not send telemetry.
- It does not install hidden agents, backdoors or persistence.
- It does not scan networks you do not own or have written permission to scan.

## Install

### From source (Go 1.24+)

```sh
git clone https://github.com/5evenTeam/mapip.git
cd mapip
go build -o mapip ./cmd/mapip
./mapip scan
```

## Quick start

```sh
# scan the local subnet, auto-detected
mapip scan

# scan a specific range with ports
mapip scan -t 192.168.1.0/24 --port-scan

# write a report
mapip scan -t 10.0.0.1-10.0.0.50 --format xml -o hosts.xml

# interactive TUI
mapip tui

# wake a device
mapip wol 00:11:22:33:44:55

# RemoteMap: connect to a host you set up on another machine
mapip remotemap client --host 192.168.1.40 --key-file ~/.mapip/remotemap/key.txt info
```

## TUI keys

`s` rescan · `w` watch mode · `tab` devices/changes · `/` filter ·
`↑/↓` scroll · `g`/`G` top/bottom · `e`/`c`/`x` export · `h` help · `q` quit

## Output formats

| Format | Flag | Notes |
|---|---|---|
| table | `--format table` (default) | colored terminal table |
| json | `--format json` | machine readable |
| csv | `--format csv` | spreadsheet friendly |
| html | `--format html` | standalone report page |
| xml | `--format xml` | Nmap-compatible, drops into existing tooling |

## Architecture

```
mapip  (Go, single static binary)
   ├── mapip scan       CLI
   ├── mapip tui        terminal UI (bubbletea)
   ├── mapip serve      local REST + SSE API
   └── mapip remotemap  host agent + client
```

One binary, several interfaces. No runtime, no installer, no background service.

## Data and privacy

- MapIp makes **no outbound network requests** other than the probes you ask
  it to send to hosts on your own network. There is no telemetry, no update
  check, no analytics, no third-party IP-to-location lookup.
- Scan history is stored locally in `~/.mapip/snapshots/` as JSON.
- RemoteMap is off unless you start the host agent, listens only where you tell
  it, and connects only to the client you run. There is no relay or cloud
  service, and every session is logged by the host.
- The IEEE OUI registry is embedded in the binary; no download is needed at
  runtime.

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. Please keep code comment-free, as per
the project convention: a port scanner should not have comments.
