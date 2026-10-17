# Changelog

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
