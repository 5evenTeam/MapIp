package enrich

import (
	"encoding/binary"
	"testing"
)

func buildNodeStatusResponse(name string, suffix byte, group bool) []byte {
	msg := []byte{0x13, 0x37, 0x85, 0x00}
	msg = append(msg, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)

	msg = append(msg, 0x20, 'C', 'K')
	for i := 0; i < 15; i++ {
		msg = append(msg, 'A', 'A')
	}
	msg = append(msg, 0x00, 0x00, 0x21, 0x00, 0x01)

	msg = append(msg, 0xC0, 0x0C)
	msg = append(msg, 0x00, 0x21, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)

	entry := make([]byte, 15)
	copy(entry, name)
	rdata := []byte{0x01}
	rdata = append(rdata, entry...)
	rdata = append(rdata, suffix)
	flags := uint16(0)
	if group {
		flags = 0x8000
	}
	var fb [2]byte
	binary.BigEndian.PutUint16(fb[:], flags)
	rdata = append(rdata, fb[:]...)

	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(rdata)))
	msg = append(msg, lb[:]...)
	msg = append(msg, rdata...)
	return msg
}

func TestParseNodeStatus(t *testing.T) {
	msg := buildNodeStatusResponse("TESTPC", 0x00, false)
	if got := parseNodeStatus(msg); got != "TESTPC" {
		t.Fatalf("got %q want TESTPC", got)
	}
}

func TestParseNodeStatusSkipsGroupEntries(t *testing.T) {
	msg := buildNodeStatusResponse("WORKGROUP", 0x00, true)
	if got := parseNodeStatus(msg); got != "" {
		t.Fatalf("group entries must be skipped, got %q", got)
	}
}

func TestParseNodeStatusTruncated(t *testing.T) {
	msg := buildNodeStatusResponse("TESTPC", 0x00, false)
	for _, n := range []int{0, 11, 20, len(msg) - 1} {
		if got := parseNodeStatus(msg[:n]); got != "" {
			t.Fatalf("truncated at %d returned %q, want empty", n, got)
		}
	}
}

func buildPTRResponse(ptrName string) []byte {
	msg := []byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}

	msg = append(msg, 0x01, '5', 0x01, '1', 0x03, '1', '6', '8', 0x03, '1', '9', '2')
	msg = append(msg, 0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r', 0x04, 'a', 'r', 'p', 'a', 0x00)
	msg = append(msg, 0x00, 0x0C, 0x00, 0x01)

	msg = append(msg, 0xC0, 0x0C)
	msg = append(msg, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78)

	var data []byte
	for _, label := range []string{"myhost", "local"} {
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}
	data = append(data, 0x00)

	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(data)))
	msg = append(msg, lb[:]...)
	msg = append(msg, data...)
	return msg
}

func TestFirstPTR(t *testing.T) {
	msg := buildPTRResponse("myhost.local")
	if got := firstPTR(msg); got != "myhost.local" {
		t.Fatalf("got %q want myhost.local", got)
	}
}

func TestFirstPTRGarbage(t *testing.T) {
	for _, msg := range [][]byte{nil, {1, 2, 3}, make([]byte, 12)} {
		if got := firstPTR(msg); got != "" {
			t.Fatalf("expected empty for garbage input, got %q", got)
		}
	}
}

func TestReverseName(t *testing.T) {
	got := reverseName("192.168.1.5")
	if got != "5.1.168.192.in-addr.arpa" {
		t.Fatalf("got %q", got)
	}
	if reverseName("not-an-ip") != "" {
		t.Fatal("expected empty for invalid ip")
	}
	if reverseName("::1") != "" {
		t.Fatal("expected empty for ipv6")
	}
}

func TestBuildPTRQueryShape(t *testing.T) {
	q := buildPTRQuery("5.1.168.192.in-addr.arpa")
	if len(q) < 12 {
		t.Fatalf("query too short: %d", len(q))
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Fatal("expected qdcount of 1")
	}
	if q[len(q)-4] != 0x00 || q[len(q)-3] != 0x0C {
		t.Fatalf("expected PTR qtype at the end, got %v", q[len(q)-4:])
	}
}
