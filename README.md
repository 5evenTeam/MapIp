# MapIp — Network Host Mapper

**MapIp maps the hosts on your own network.** It does not geolocate IP
addresses. It does not report physical location, country, or ISP. It is not an
IP-to-location tool.

MapIp is a cross-platform network host discovery and inventory tool with a
terminal UI, a command line, and a desktop application that share one core.
It is inspired by the ergonomics of Nmap, Angry IP Scanner and Advanced IP
Scanner, but it ships as a single self-contained binary with no runtime and
gives you continuous monitoring, change detection and SNMP-free name
resolution out of the box.

## What it does

- **Discovery** — ARP, ICMP, TCP ping, UDP ping. Works without root or
  administrator privileges on Windows (via `SendARP` / `IcmpSendEcho`).
- **Inventory** — MAC address, OUI vendor (IEEE registry, 46,000+ prefixes),
  TTL-based OS family, reverse DNS, mDNS, NetBIOS, LLMNR, HTTP/HTTPS title.
- **Port scan** — concurrent TCP connect scan with banner grabbing and service
  detection (optional, `--port-scan`).
- **Continuous monitoring** — rescan and diff: new hosts, missing hosts,
  opened/closed ports, MAC and hostname changes, with a desktop alert.
- **Wake-on-LAN** — send a magic packet to any discovered MAC.
- **Export** — table, CSV, JSON, HTML report, Nmap-compatible XML.
- **Interfaces** — list local interfaces and the primary subnet.

## What it does not do

- It does not geolocate IP addresses.
- It does not perform third-party IP lookups.
- It does not send telemetry.
- It does not scan networks you do not own or have written permission to scan.

## Install

### Windows (installer)

Download `MapIp Setup 0.1.0.exe` from the [latest release](https://github.com/5evenTeam/mapip/releases)
and run it. The installer bundles the engine and the desktop application.
No separate runtime is required.

### From source (Go 1.22+)

```sh
git clone https://github.com/5evenTeam/mapip.git
cd mapip
go build -o mapip ./cmd/mapip
./mapip scan
```

### Desktop app

```sh
cd desktop
npm install
npm run build
npm run start
```

The desktop app launches `mapip serve` itself and connects to it over a local
token-protected API.

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

# local API for the desktop app
mapip serve --addr 127.0.0.1:8765
```

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
mapip-core  (Go, single static binary)
   ├── mapip            CLI
   ├── mapip tui        terminal UI (bubbletea)
   └── MapIp Desktop    Electron GUI  (primary UI)
```

One core, three clients. The core runs a local REST + Server-Sent Events API
on `127.0.0.1` with a bearer token generated at startup; the desktop app
spawns it and reads the token from its stdout. This mirrors the OpenCode
pattern: a shared core, multiple front ends.

## Data and privacy

- MapIp makes **no outbound network requests** other than the probes you ask
  it to send to hosts on your own network. There is no telemetry, no update
  check, no analytics, no third-party IP-to-location lookup.
- Scan history is stored locally in `~/.mapip/snapshots/` as JSON.
- The IEEE OUI registry is embedded in the binary; no download is needed at
  runtime.

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. Please keep code comment-free, as per
the project convention: a port scanner should not have comments.
