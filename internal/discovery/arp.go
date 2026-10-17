package discovery

import (
	"bufio"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

var macRe = regexp.MustCompile(`(?i)([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})`)
var ipRe = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

func ARPTable() map[string]string {
	table := map[string]string{}
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("arp", "-a").Output()
		if err != nil {
			return table
		}
		for _, line := range strings.Split(string(out), "\n") {
			ifm := ipRe.FindStringSubmatch(line)
			m := macRe.FindStringSubmatch(line)
			if len(ifm) == 2 && len(m) == 2 {
				table[ifm[1]] = normalizeMAC(m[1])
			}
		}
	case "linux":
		f, err := os.Open("/proc/net/arp")
		if err != nil {
			return table
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		first := true
		for s.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(s.Text())
			if len(fields) >= 4 {
				table[fields[0]] = normalizeMAC(fields[3])
			}
		}
	default:
		out, err := exec.Command("arp", "-an").Output()
		if err != nil {
			return table
		}
		for _, line := range strings.Split(string(out), "\n") {
			ifm := ipRe.FindStringSubmatch(line)
			m := macRe.FindStringSubmatch(line)
			if len(ifm) == 2 && len(m) == 2 {
				table[ifm[1]] = normalizeMAC(m[1])
			}
		}
	}
	return table
}

func normalizeMAC(m string) string {
	m = strings.ReplaceAll(m, "-", ":")
	return strings.ToLower(m)
}
