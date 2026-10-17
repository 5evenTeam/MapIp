package portscan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestGuessService(t *testing.T) {
	cases := map[int]string{
		22:    "ssh",
		80:    "http",
		443:   "https",
		445:   "microsoft-ds",
		3389:  "rdp",
		8080:  "http-proxy",
		27017: "mongodb",
		12345: "",
	}
	for port, want := range cases {
		if got := GuessService(port); got != want {
			t.Errorf("GuessService(%d) = %q, want %q", port, got, want)
		}
	}
}

func TestDetectProtocolDoesNotDowngradeHTTP(t *testing.T) {
	httpBanner := "HTTP/1.1 400 Bad Request  Server: nginx"
	if got := detectProtocol(httpBanner); got != "" {
		t.Fatalf("http banners must not override the port-derived service, got %q", got)
	}
	if got := detectProtocol("SSH-2.0-OpenSSH_9.0"); got != "ssh" {
		t.Fatalf("expected ssh, got %q", got)
	}
	if got := detectProtocol("220 mail.example.com ESMTP Postfix"); got != "smtp" {
		t.Fatalf("expected smtp, got %q", got)
	}
	if got := detectProtocol("-ERR unknown command"); got != "redis" {
		t.Fatalf("expected redis, got %q", got)
	}
}

func TestScanFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	results := Scan(context.Background(), "127.0.0.1", Options{
		Ports:   []int{port},
		Timeout: 2 * time.Second,
		Banners: false,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(results))
	}
	if results[0].Port != port || results[0].State != "open" {
		t.Fatalf("unexpected result: %+v", results[0])
	}
}

func TestScanIgnoresClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	results := Scan(context.Background(), "127.0.0.1", Options{
		Ports:   []int{port},
		Timeout: 500 * time.Millisecond,
	})
	if len(results) != 0 {
		t.Fatalf("expected no open ports, got %+v", results)
	}
}

func TestDefaultPortsSane(t *testing.T) {
	ports := DefaultPorts()
	if len(ports) < 10 {
		t.Fatalf("expected a reasonable default port set, got %d", len(ports))
	}
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			t.Fatalf("invalid default port %s", strconv.Itoa(p))
		}
	}
}
