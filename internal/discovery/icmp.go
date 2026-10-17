package discovery

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/5evenTeam/mapip/internal/model"
)

var (
	ttlRe  = regexp.MustCompile(`(?i)TTL=(\d+)`)
	rttRe  = regexp.MustCompile(`(?i)(?:time|Round Trip)<?(\d+(?:\.\d+)?)\s*ms>?`)
	lossRe = regexp.MustCompile(`(?i)(\d+)%\s*(?:packet\s+)?loss`)
)

func ICMPPing(ip string, timeout time.Duration) (model.Host, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+500*time.Millisecond)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		ms := int(timeout / time.Millisecond)
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(ms), ip)
	} else {
		secs := int(timeout/time.Second) + 1
		if secs < 1 {
			secs = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(secs), ip)
	}

	out, err := cmd.CombinedOutput()
	alive, ttl, rtt := parsePing(string(out))
	if ctx.Err() != nil {
		return model.Host{IP: ip, Alive: false}, false
	}
	if !alive {
		return model.Host{IP: ip, Alive: false, RTTMs: rtt}, false
	}
	_ = err
	return model.Host{IP: ip, Alive: true, TTL: ttl, RTTMs: rtt, OS: osFromTTL(ttl)}, true
}

func parsePing(out string) (alive bool, ttl int, rtt float64) {
	if m := lossRe.FindStringSubmatch(out); m != nil {
		if m[1] == "100" {
			return false, 0, 0
		}
	}
	if m := ttlRe.FindStringSubmatch(out); m != nil {
		ttl, _ = strconv.Atoi(m[1])
		alive = true
	}
	if m := rttRe.FindStringSubmatch(out); m != nil {
		rtt, _ = strconv.ParseFloat(m[1], 64)
	}
	if runtime.GOOS == "windows" && strings.Contains(out, "TTL=") {
		alive = true
	}
	if !alive {
		if strings.Contains(strings.ToLower(out), "reply from") ||
			strings.Contains(strings.ToLower(out), "bytes from") {
			alive = true
		}
	}
	return alive, ttl, rtt
}

func osFromTTL(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl <= 64:
		return "Linux/macOS/Unix"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Cisco/network device"
	}
	return ""
}
