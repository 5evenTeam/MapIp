package portscan

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/5evenTeam/mapip/internal/model"
)

func findNetBreakEngine() string {
	if dir := os.Getenv("NETBREAK_ENGINE_DIR"); dir != "" {
		name := "netbreak-engine"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	candidates := []string{}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, "netbreak-engine.exe")
	} else {
		candidates = append(candidates, "netbreak-engine")
	}
	// search relative to cwd and the known NetBreak checkout
	candidates = append(candidates,
		filepath.Join("engines", "go", "bin", "netbreak-engine"+exeSuffix()),
		filepath.Join("..", "NetBreak", "engines", "go", "bin", "netbreak-engine"+exeSuffix()),
		filepath.Join("..", "..", "NetBreak", "engines", "go", "bin", "netbreak-engine"+exeSuffix()),
	)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("netbreak-engine"); err == nil {
		return p
	}
	return ""
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

type nbEvent struct {
	Event   string  `json:"event"`
	Port    int     `json:"port,omitempty"`
	Proto   string  `json:"proto,omitempty"`
	State   string  `json:"state,omitempty"`
	Reason  string  `json:"reason,omitempty"`
	RTT     float64 `json:"rtt_ms,omitempty"`
	Message string  `json:"message,omitempty"`
}

func ScanViaNetBreak(ctx context.Context, ip string, ports []int, udpPorts []int, timeout time.Duration) []model.Port {
	engine := findNetBreakEngine()
	if engine == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	resultMap := map[int]model.Port{}
	var mu interface{}
	_ = mu

	// TCP scan
	if len(ports) > 0 {
		spec := joinPorts(ports)
		cmd := exec.CommandContext(ctx, engine, "scan", "-host", ip, "-p", spec, "-timeout", fmtFloat(timeout.Seconds()), "-concurrency", "200")
		out, err := cmd.Output()
		if err == nil {
			parseNetBreakOutput(out, ip, "tcp", resultMap)
		}
	}

	// UDP scan
	if len(udpPorts) > 0 {
		spec := joinPorts(udpPorts)
		cmd := exec.CommandContext(ctx, engine, "udpscan", "-host", ip, "-p", spec, "-timeout", fmtFloat(timeout.Seconds()), "-concurrency", "150")
		out, err := cmd.Output()
		if err == nil {
			parseNetBreakOutput(out, ip, "udp", resultMap)
		}
	}

	out := make([]model.Port, 0, len(resultMap))
	for _, p := range resultMap {
		out = append(out, p)
	}
	sortPorts(out)
	return out
}

func parseNetBreakOutput(data []byte, ip, fallbackProto string, out map[int]model.Port) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev nbEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Event != "port" {
			continue
		}
		proto := ev.Proto
		if proto == "" {
			proto = fallbackProto
		}
		state := ev.State
		if state == "" {
			state = "open"
		}
		// normalize open|filtered
		p := model.Port{
			Port:    ev.Port,
			Proto:   proto,
			State:   state,
			Service: guessServiceNB(ev.Port, proto),
			Banner:  "",
		}
		if ev.RTT > 0 {
			// store rtt in banner field? no - keep service
		}
		out[ev.Port] = p
	}
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

func fmtFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}

func guessServiceNB(port int, proto string) string {
	// reuse portscan's GuessService for tcp; for udp return common names
	if proto == "tcp" {
		return GuessService(port)
	}
	switch port {
	case 53:
		return "domain"
	case 67, 68:
		return "dhcp"
	case 69:
		return "tftp"
	case 123:
		return "ntp"
	case 137:
		return "netbios-ns"
	case 138:
		return "netbios-dgm"
	case 161:
		return "snmp"
	case 162:
		return "snmptrap"
	case 500:
		return "isakmp"
	case 514:
		return "syslog"
	case 520:
		return "route"
	case 1900:
		return "upnp"
	case 5353:
		return "mdns"
	}
	return ""
}

func NetBreakAvailable() bool {
	return findNetBreakEngine() != ""
}
