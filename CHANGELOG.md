# Changelog

## 0.4.0 — RemoteMap

- **RemoteMap**: consent-based remote host access between machines you own,
  added as `mapip remotemap host` (agent) and `mapip remotemap client`.
- Authenticated and encrypted wire protocol: HMAC-SHA256 challenge/response,
  HKDF-SHA256 key derivation and AES-256-GCM with per-direction keys.
- Client operations: `info`, `ping`, `list`, `get`, `exec` (opt-in) and an
  interactive `shell`.
- File access is confined to a single `--root` directory; paths that escape it,
  including via symlinks, are refused.
- The host agent is visible and logs every connection, authentication and
  operation. It is not a service and leaves nothing behind when stopped.
- `exec` is off unless the host owner passes `--allow-shell`, and `--allow`
  can restrict which client addresses may connect.
- New `mapip remotemap key` helper to generate a key and print its fingerprint.
- 12 new tests covering the handshake, wrong-key rejection, path confinement,
  streamed downloads, the `--allow-shell` opt-in and the RFC 5869 HKDF vector.

## 0.3.0

- API: `POST /api/scan` now accepts `deep` (NetBreak service/version detection)
  and `udp_ports` (UDP probes through the NetBreak engine).
- `/api/health` now reports a `capabilities` object (`deep`, `engine`).
- Ports supplied to the API are validated and de-duplicated (1-65535).
- Exposed `portscan.NetBreakAvailable` for capability checks.
- Dropped the stale Electron `desktop` CI job (MapIp is TUI + CLI + API only).

## 0.2.0 — NetBreak engine integration

- TCP port scanning via the `netbreak-engine` binary with graceful fallback to
  the built-in connect scan.
- UDP port scanning through the NetBreak engine (`-udp-ports`).
- Deep service/version detection (`--deep`) delegating to NetBreak `-sV`.
- New `serve` command: local REST + SSE API for the desktop app.

## 0.1.0 — initial release

- Network host discovery (ARP, ICMP, TCP ping, UDP ping).
- MAC + OUI vendor (embedded IEEE registry, 46,000+ prefixes).
- TTL-based OS family detection.
- Reverse DNS, mDNS, NetBIOS, LLMNR name resolution.
- Concurrent TCP port scan with banner grabbing and service detection.
- HTTP/HTTPS title extraction.
- Continuous monitoring with change detection (new, missing, opened/closed
  ports, MAC/hostname changes).
- Wake-on-LAN.
- Export: table, CSV, JSON, HTML report, Nmap-compatible XML.
- Terminal UI (bubbletea) and Electron desktop GUI.
- Local REST + SSE API with bearer-token auth.
- Scan history stored in `~/.mapip/snapshots/`.
- 40+ tests across discovery, enrichment, port scanning, output, storage,
  OUI and network utilities.
