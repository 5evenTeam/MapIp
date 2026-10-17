package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/5evenTeam/mapip/internal/discovery"
	"github.com/5evenTeam/mapip/internal/model"
	"github.com/5evenTeam/mapip/internal/netutil"
	"github.com/5evenTeam/mapip/internal/output"
	"github.com/5evenTeam/mapip/internal/portscan"
	"github.com/5evenTeam/mapip/internal/store"
)

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var spec string
	var portsCSV string
	var timeoutMs int
	var portScan bool
	var noEnrich bool
	var outFile string
	var format string
	var concurrency int

	fs.StringVar(&spec, "t", "", "targets: CIDR, range, list or hostname")
	fs.StringVar(&spec, "targets", "", "targets: CIDR, range, list or hostname")
	fs.StringVar(&portsCSV, "p", "", "comma-separated ports")
	fs.StringVar(&portsCSV, "ports", "", "comma-separated ports")
	fs.IntVar(&timeoutMs, "T", 1200, "per-probe timeout in ms")
	fs.IntVar(&timeoutMs, "timeout", 1200, "per-probe timeout in ms")
	fs.BoolVar(&portScan, "port-scan", false, "run the TCP port scan")
	fs.BoolVar(&noEnrich, "no-enrich", false, "skip reverse DNS and vendor lookup")
	fs.StringVar(&outFile, "o", "", "output file")
	fs.StringVar(&outFile, "output", "", "output file")
	fs.StringVar(&format, "format", "table", "table, json, csv, html or xml")
	fs.IntVar(&concurrency, "concurrency", 64, "parallel probes")
	_ = fs.Parse(args)

	fmt.Printf("mapip %s — %s\n\n", version, disclaimer)

	if spec == "" {
		cidr, err := netutil.PrimaryLocalCIDR()
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not detect the local subnet:", err)
			os.Exit(1)
		}
		spec = cidr
		fmt.Printf("no targets given, using the local subnet %s\n\n", cidr)
	}

	ips, err := netutil.ParseTargets(spec)
	if err != nil || len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "no usable targets in:", spec)
		os.Exit(1)
	}
	ips = netutil.NormalizeTargets(ips)

	ports := parsePorts(portsCSV)
	if portScan && len(ports) == 0 {
		ports = portscan.DefaultPorts()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	opts := discovery.Options{
		Targets:     ips,
		Timeout:     time.Duration(timeoutMs) * time.Millisecond,
		Concurrency: concurrency,
		Ports:       ports,
		PortScan:    portScan,
		Enrich:      !noEnrich,
	}

	started := time.Now()
	fmt.Printf("scanning %d address(es)...\n", len(ips))

	last := 0
	res := discovery.ScanAll(ctx, opts, func(p discovery.Progress) {
		if p.Total < 256 && p.Done%10 == 0 && p.Done != last {
			last = p.Done
			fmt.Printf("\r  %d/%d probed", p.Done, p.Total)
		}
		if p.Found {
			if p.Total < 256 {
				fmt.Print("\r")
			}
			fmt.Printf("  up  %-16s %s\n", p.Host.IP, hostLabel(p.Host))
		}
	})
	if len(ips) >= 256 {
		fmt.Printf("\r  %d/%d probed\n", len(ips), len(ips))
	}

	report := model.ScanReport{
		Targets:  ips,
		Hosts:    res.Hosts,
		Started:  started,
		Finished: time.Now(),
	}

	st := store.New("")
	if path, err := st.Save(store.Snapshot{TakenAt: report.Finished, Targets: ips, Hosts: res.Hosts}); err == nil {
		fmt.Printf("\nhistory: %s\n", path)
	}

	fmt.Printf("\n%d host(s) up in %s\n\n", len(report.Hosts), report.Finished.Sub(report.Started).Round(time.Millisecond))

	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not create", outFile, ":", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := writeFormat(f, format, report); err != nil {
			fmt.Fprintln(os.Stderr, "write failed:", err)
			os.Exit(1)
		}
		fmt.Println("report written to", outFile)
		return
	}
	if err := writeFormat(os.Stdout, format, report); err != nil {
		fmt.Fprintln(os.Stderr, "write failed:", err)
	}
}

func writeFormat(f *os.File, format string, report model.ScanReport) error {
	switch strings.ToLower(format) {
	case "json":
		return output.WriteJSON(f, report)
	case "csv":
		return output.WriteCSV(f, report)
	case "html":
		return output.WriteHTML(f, report)
	case "xml", "nmap":
		return output.WriteNmapXML(f, report)
	default:
		return output.WriteTable(f, report)
	}
}

func hostLabel(h model.Host) string {
	parts := []string{}
	if h.Hostname != "" {
		parts = append(parts, h.Hostname)
	}
	if h.Vendor != "" {
		parts = append(parts, h.Vendor)
	}
	if h.MAC != "" {
		parts = append(parts, h.MAC)
	}
	if h.OS != "" {
		parts = append(parts, h.OS)
	}
	if len(h.Ports) > 0 {
		ps := make([]string, 0, len(h.Ports))
		for _, p := range h.Ports {
			ps = append(ps, strconv.Itoa(p.Port))
		}
		parts = append(parts, "ports:"+strings.Join(ps, ","))
	}
	return strings.Join(parts, "  ")
}

func parsePorts(s string) []int {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 == nil && err2 == nil && lo > 0 && hi < 65536 && lo <= hi {
				for v := lo; v <= hi; v++ {
					out = append(out, v)
				}
			}
			continue
		}
		if v, err := strconv.Atoi(p); err == nil && v > 0 && v < 65536 {
			out = append(out, v)
		}
	}
	return out
}
