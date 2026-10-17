# Usage

## Commands

### `mapip scan`

Discover hosts and optionally scan ports.

```
mapip scan [flags]
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `-t, --targets SPEC` | local subnet | CIDR, range (`10.0.0.1-10.0.0.50`), list (`10.0.0.1,10.0.0.2`) or hostname |
| `-p, --ports LIST` | default set | comma-separated ports or ranges (`80,443,8000-8100`) |
| `--port-scan` | false | enable the TCP port scan |
| `--no-enrich` | false | skip reverse DNS, MAC/vendor and name resolution |
| `-T, --timeout MS` | 1200 | per-probe timeout in milliseconds |
| `--concurrency N` | 64 | parallel probes |
| `-o, --output FILE` | stdout | write the report to a file |
| `--format FMT` | table | `table`, `json`, `csv`, `html`, `xml` |

When no targets are given, MapIp detects the primary local subnet and scans it.

### `mapip tui`

Interactive terminal UI. Same flags as `scan` for targets, ports, timeout and
port scanning. Keys: `s` rescan, `↑/↓` scroll, `g` top, `q` quit.

### `mapip serve`

Run the local API used by the desktop application.

```
mapip serve [--addr HOST:PORT] [--token TOKEN]
```

Prints the listen address and the bearer token on stdout. The desktop app reads
these. The token is generated randomly when not provided.

### `mapip wol <mac>`

Send a Wake-on-LAN magic packet.

```
mapip wol 00:11:22:33:44:55 [-b 255.255.255.255]
```

### `mapip interfaces`

List local interfaces, their addresses and the primary subnet.

### `mapip version`

Print the version and the no-geolocation statement.

## Environment

- Scan history: `~/.mapip/snapshots/*.json`
- No configuration file is required; everything is flags.

## Notes

- MapIp does not geolocate IP addresses. It does not report country, city or
  ISP. It maps the hosts on your own network only.
- Run scans only on networks you own or have written permission to test.
- Some probes (ICMP) may require elevated privileges on Linux/macOS; on Windows
  MapIp uses the Win32 `IcmpSendEcho` API which works without elevation.
