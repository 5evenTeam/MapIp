package netutil

import (
	"net"
	"reflect"
	"testing"
)

func TestParseTargetsCIDR(t *testing.T) {
	got, err := ParseTargets("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseTargetsRange(t *testing.T) {
	got, err := ParseTargets("10.0.0.1-10.0.0.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 addresses, got %d (%v)", len(got), got)
	}
	if got[0] != "10.0.0.1" || got[3] != "10.0.0.4" {
		t.Fatalf("unexpected bounds: %v", got)
	}
}

func TestParseTargetsShortRange(t *testing.T) {
	got, err := ParseTargets("10.0.0.10-13")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseTargetsSingle(t *testing.T) {
	got, _ := ParseTargets("127.0.0.1")
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestNormalizeTargetsDedupes(t *testing.T) {
	got := NormalizeTargets([]string{"127.0.0.1", "127.0.0.1", "  ", "10.0.0.1"})
	want := []string{"127.0.0.1", "10.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestIsPrivate(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":      true,
		"172.16.5.4":    true,
		"172.32.5.4":    false,
		"192.168.1.1":   true,
		"169.254.10.10": true,
		"8.8.8.8":       false,
	}
	for ip, want := range cases {
		if got := isPrivate(net.ParseIP(ip)); got != want {
			t.Errorf("isPrivate(%s) = %v, want %v", ip, got, want)
		}
	}
}
