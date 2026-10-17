package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/5evenTeam/mapip/internal/model"
)

func sampleReport() model.ScanReport {
	return model.ScanReport{
		Targets: []string{"192.168.1.0/30"},
		Hosts: []model.Host{
			{
				IP:       "192.168.1.1",
				MAC:      "00:00:0c:11:22:33",
				Vendor:   "Cisco",
				OS:       "Linux/macOS/Unix",
				TTL:      64,
				RTTMs:    1.25,
				Hostname: "gateway",
				Ports: []model.Port{
					{Port: 80, Proto: "tcp", State: "open", Service: "http"},
					{Port: 443, Proto: "tcp", State: "open", Service: "https"},
				},
			},
		},
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleReport()); err != nil {
		t.Fatalf("csv write failed: %v", err)
	}
	text := buf.String()
	for _, want := range []string{"ip,hostname,mac,vendor,os,ttl,rtt_ms,ports", "00:00:0c:11:22:33", "80 443"} {
		if !strings.Contains(text, want) {
			t.Fatalf("csv missing %q:\n%s", want, text)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatalf("json write failed: %v", err)
	}
	if !strings.Contains(buf.String(), `"ip": "192.168.1.1"`) {
		t.Fatalf("unexpected json:\n%s", buf.String())
	}
}

func TestWriteNmapXML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNmapXML(&buf, sampleReport()); err != nil {
		t.Fatalf("xml write failed: %v", err)
	}
	text := buf.String()
	for _, want := range []string{
		"<nmaprun",
		`scanner="mapip"`,
		`addrtype="mac"`,
		`vendor="Cisco"`,
		`portid="443"`,
		`state="open"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("xml missing %q:\n%s", want, text)
		}
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, sampleReport()); err != nil {
		t.Fatalf("table write failed: %v", err)
	}
	text := buf.String()
	for _, want := range []string{"IP", "OPEN PORTS", "192.168.1.1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("table missing %q:\n%s", want, text)
		}
	}
}

func TestWriteHTMLCarriesDisclaimer(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatalf("html write failed: %v", err)
	}
	text := buf.String()
	if !strings.Contains(text, "<!doctype html>") {
		t.Fatalf("missing doctype:\n%s", text)
	}
	if !strings.Contains(text, "does not geolocate") {
		t.Fatal("html report must carry the no-geolocation statement")
	}
}
