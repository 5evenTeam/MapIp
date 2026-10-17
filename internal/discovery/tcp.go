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
