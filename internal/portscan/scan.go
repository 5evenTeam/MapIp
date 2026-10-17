package portscan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/5evenTeam/mapip/internal/model"
)

type Options struct {
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	Banners     bool
}

func DefaultPorts() []int {
	return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
		995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017}
}

func Scan(ctx context.Context, ip string, opts Options) []model.Port {
	if len(opts.Ports) == 0 {
		opts.Ports = DefaultPorts()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 800 * time.Millisecond
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 128
	}

	results := make([]model.Port, 0, 8)
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, port := range opts.Ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p, ok := probe(ctx, ip, port, opts)
			if !ok {
				return
			}
			mu.Lock()
			results = append(results, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sortPorts(results)
	return results
}

func probe(ctx context.Context, ip string, port int, opts Options) (model.Port, bool) {
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return model.Port{}, false
	}
	defer conn.Close()

	p := model.Port{Port: port, Proto: "tcp", State: "open", Service: GuessService(port)}
	if opts.Banners {
		banner := grabBanner(conn, opts.Timeout)
		p.Banner = banner
		if detected := detectProtocol(banner); detected != "" {
			p.Service = detected
		}
	}
	return p, true
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)

	if _, err := conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n")); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if n <= 0 || err != nil {
		return ""
	}
	return cleanBanner(string(buf[:n]))
}

func cleanBanner(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.TrimSpace(s)
}

func GuessService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 27017:
		return "mongodb"
	}
	return ""
}

func detectProtocol(banner string) string {
	if banner == "" {
		return ""
	}
	low := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(low, "ssh-"):
		return "ssh"
	case strings.HasPrefix(low, "-err") || strings.HasPrefix(low, "$") || strings.Contains(low, "-err unknown command"):
		return "redis"
	case strings.Contains(low, "esmtp") || strings.Contains(low, "smtp"):
		return "smtp"
	case strings.Contains(low, "ftp"):
		return "ftp"
	case strings.HasPrefix(low, "+ok"):
		return "pop3"
	case strings.HasPrefix(low, "* ok"):
		return "imap"
	}
	return ""
}

func sortPorts(p []model.Port) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Port < p[j-1].Port; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}
