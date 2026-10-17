package enrich

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

func ReverseDNS(ip string, timeout time.Duration) string {
	type result struct{ name string }
	ch := make(chan result, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			ch <- result{}
			return
		}
		ch <- result{name: strings.TrimSuffix(names[0], ".")}
	}()
	select {
	case r := <-ch:
		return r.name
	case <-time.After(timeout):
		return ""
	}
}

func HTTPTitle(ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	var conn net.Conn
	var err error

	if port == 443 || port == 8443 {
		d := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: mapip/0.1\r\n\r\n", addr)

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	body := false
	for sc.Scan() {
		line := sc.Text()
		if !body {
			if strings.TrimSpace(line) == "" {
				body = true
			}
			continue
		}
		if title := extractTitle(line); title != "" {
			return title
		}
	}
	return ""
}

func extractTitle(line string) string {
	low := strings.ToLower(line)
	i := strings.Index(low, "<title>")
	if i < 0 {
		return ""
	}
	rest := line[i+len("<title>"):]
	j := strings.Index(strings.ToLower(rest), "</title>")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}
