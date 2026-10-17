package main

import (
	"fmt"
	"os"
)

const version = "0.2.0"

const disclaimer = "MapIp maps the hosts on your own network. It does not geolocate IP addresses."

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"scan"}
	}

	switch args[0] {
	case "scan":
		cmdScan(args[1:])
	case "serve":
		cmdServe(args[1:])
	case "tui", "ui":
		cmdTUI(args[1:])
	case "wol":
		cmdWOL(args[1:])
	case "interfaces", "ifaces":
		cmdInterfaces(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("mapip %s\n%s\n", version, disclaimer)
	case "help", "--help", "-h":
		usage()
	default:
		cmdScan(args)
	}
}

func usage() {
	fmt.Printf(`mapip %s — network host mapper

%s

Usage:
  mapip scan [flags]            discover hosts and optionally scan ports
  mapip tui                     interactive terminal UI
  mapip serve [--addr HOST:PORT] start the local API for the desktop app
  mapip wol <mac>               send a wake-on-lan magic packet
  mapip interfaces              list local interfaces and the primary subnet

Scan flags:
  -t, --targets SPEC   CIDR, range, list or hostname (default: local subnet)
  -p, --ports LIST     ports to scan when -ports is set
      --port-scan      enable the TCP port scan
      --no-enrich      skip reverse DNS and MAC/vendor lookup
  -T, --timeout MS     per-probe timeout in milliseconds (default 1200)
  -o, --output FILE    write a report to FILE
      --format FMT     table, json, csv, html or xml (default table)

Examples:
  mapip scan
  mapip scan -t 192.168.1.0/24 --port-scan
  mapip scan -t 10.0.0.1-10.0.0.50 --format json -o hosts.json

No geolocation. No telemetry. No third-party IP lookup services.
`, version, disclaimer)
}
