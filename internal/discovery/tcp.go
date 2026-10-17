package discovery

import (
	"net"
	"strconv"
	"time"

	"github.com/5evenTeam/mapip/internal/model"
)

func TCPPing(ip string, ports []int, timeout time.Duration) (model.Host, bool) {
	start := time.Now()
	for _, p := range ports {
		d := net.Dialer{Timeout: timeout}
		if c, err := d.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(p))); err == nil {
			c.Close()
			rtt := time.Since(start).Seconds() * 1000
			h := model.Host{IP: ip, Alive: true, RTTMs: rtt}
			h.Ports = append(h.Ports, model.Port{Port: p, Proto: "tcp", State: "open"})
			return h, true
		}
	}
	rtt := time.Since(start).Seconds() * 1000
	return model.Host{IP: ip, Alive: false, RTTMs: rtt}, false
}

func ServiceGuess(port int, proto string, banner string) string {
	if proto != "tcp" {
		return ""
	}
	switch port {
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25, 587:
		return "smtp"
	case 53:
		return "dns"
	case 80, 8080, 8000, 8443:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 3389:
		return "rdp"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	}
	return ""
}
