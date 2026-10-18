package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/5evenTeam/mapip/internal/store"
)

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	return New("test-token", store.New(t.TempDir())).Handler()
}

func TestHealthIsPublic(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	newHandler(t).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health status = %d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("health body: %v", err)
	}
	if body["name"] != "mapip" {
		t.Fatalf("unexpected name: %v", body["name"])
	}
	if _, ok := body["capabilities"]; !ok {
		t.Fatal("health missing capabilities")
	}
}

func TestAuthRequired(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/interfaces", nil)
	newHandler(t).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthAcceptsBearer(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/interfaces", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	newHandler(t).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestStartScanAcceptsDeepAndUDP(t *testing.T) {
	body := `{"targets":["127.0.0.1"],"port_scan":false,"deep":true,"udp_ports":[53,123],"ports":[0,80,80,70000]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	newHandler(t).ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("scan body: %v", err)
	}
	if resp["id"] == nil || resp["id"] == "" {
		t.Fatal("scan response missing id")
	}
}

func TestSanitizePorts(t *testing.T) {
	got := sanitizePorts([]int{0, 80, 80, 70000, -1, 443})
	want := []int{80, 443}
	if len(got) != len(want) {
		t.Fatalf("sanitizePorts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sanitizePorts = %v, want %v", got, want)
		}
	}
	if sanitizePorts(nil) != nil {
		t.Fatal("sanitizePorts(nil) should be nil")
	}
}
