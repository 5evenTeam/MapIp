package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/5evenTeam/mapip/internal/discovery"
	"github.com/5evenTeam/mapip/internal/netutil"
)

var (
	targets   string
	timeoutms int
	ports     string
)

func main() {
	flag.StringVar(&targets, "t", "127.0.0.1", "targets: CIDR/range/list")
	flag.IntVar(&timeoutms, "T", 1000, "timeout ms")
	flag.StringVar(&ports, "p", "80,443,22,3389,445,53,139", "tcp ports")
	ui := flag.Bool("ui", false, "launch TUI (bubbletea)")
	flag.Parse()
	if *ui {
		runTUI()
		return
	}
	list, _ := netutil.ParseTargets(targets)
	plist := parsePorts(ports)
	fmt.Println("MapIp — network host mapper (NOT geolocation)")
	fmt.Println("https://github.com/5evenTeam/mapip")
	for _, ip := range list {
		h, ok := discovery.TCPPing(ip, plist, time.Duration(timeoutms)*time.Millisecond)
		if ok {
			fmt.Printf("[%s] UP (rtt=%.1fms) open:%d\n", h.IP, h.RTTMs, len(h.Ports))
			continue
		}
		fmt.Printf("[%s] DOWN/filtered (rtt=%.1fms)\n", h.IP, h.RTTMs)
	}
}

func parsePorts(s string) []int {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	var out []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var v int
		fmt.Sscanf(p, "%d", &v)
		if v > 0 && v < 65536 {
			out = append(out, v)
		}
	}
	return out
}
