package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/5evenTeam/mapip/internal/netutil"
	"github.com/5evenTeam/mapip/internal/tui"
)

func cmdTUI(args []string) {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	var spec string
	var portsCSV string
	var timeoutMs int
	var portScan bool

	fs.StringVar(&spec, "t", "", "targets: CIDR, range, list or hostname")
	fs.StringVar(&spec, "targets", "", "targets: CIDR, range, list or hostname")
	fs.StringVar(&portsCSV, "p", "", "comma-separated ports")
	fs.StringVar(&portsCSV, "ports", "", "comma-separated ports")
	fs.IntVar(&timeoutMs, "T", 1200, "per-probe timeout in ms")
	fs.IntVar(&timeoutMs, "timeout", 1200, "per-probe timeout in ms")
	fs.BoolVar(&portScan, "port-scan", false, "run the TCP port scan")
	_ = fs.Parse(args)

	if spec == "" {
		if cidr, err := netutil.PrimaryLocalCIDR(); err == nil {
			spec = cidr
		}
	}

	if err := tui.Run(spec, parsePorts(portsCSV), portScan, time.Duration(timeoutMs)*time.Millisecond); err != nil {
		fmt.Fprintln(os.Stderr, "tui error:", err)
		os.Exit(1)
	}
}
