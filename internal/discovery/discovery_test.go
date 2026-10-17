package discovery

import (
	"net"
	"testing"
	"time"
)

func TestTCPPingFindsOpenPort(t *testing.T) {
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
	h, ok := TCPPing("127.0.0.1", []int{port}, 2*time.Second)
	if !ok {
		t.Fatal("expected the loopback listener to answer")
	}
	if !h.Alive || h.IP != "127.0.0.1" {
		t.Fatalf("unexpected host: %+v", h)
	}
}

func TestTCPPingClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	if _, ok := TCPPing("127.0.0.1", []int{port}, 300*time.Millisecond); ok {
		t.Fatal("expected no answer from a closed port")
	}
}

func TestIPLessSortsNumerically(t *testing.T) {
	if !ipLess("192.168.1.2", "192.168.1.10") {
		t.Fatal("10 should sort after 2 in dotted-quad order")
	}
	if ipLess("192.168.1.10", "192.168.1.2") {
		t.Fatal("comparison must be numeric, not lexical")
	}
	if !ipLess("10.0.0.1", "10.0.0.2") {
		t.Fatal("expected ascending order")
	}
}

func TestOSFromTTL(t *testing.T) {
	if got := osFromTTL(64); got == "" {
		t.Fatal("expected an OS family for ttl 64")
	}
	if got := osFromTTL(128); got == "" {
		t.Fatal("expected an OS family for ttl 128")
	}
}

func TestARPTableIsUsable(t *testing.T) {
	table := ARPTable()
	if table == nil {
		t.Fatal("ARPTable must never return nil")
	}
	for ip, mac := range table {
		if net.ParseIP(ip) == nil {
			t.Errorf("ARP table contains a malformed ip: %q", ip)
		}
		if len(mac) != 17 {
			t.Errorf("ARP table contains a malformed mac %q for %s", mac, ip)
		}
	}
}
