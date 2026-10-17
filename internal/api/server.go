package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/5evenTeam/mapip/internal/discovery"
	"github.com/5evenTeam/mapip/internal/model"
	"github.com/5evenTeam/mapip/internal/netutil"
	"github.com/5evenTeam/mapip/internal/output"
	"github.com/5evenTeam/mapip/internal/portscan"
	"github.com/5evenTeam/mapip/internal/store"
	"github.com/5evenTeam/mapip/internal/wol"
)

const Version = "0.1.0"

const Disclaimer = "MapIp maps the hosts on your own network. It does not geolocate IP addresses."

type Server struct {
	token   string
	store   *store.Store
	mu      sync.Mutex
	scans   map[string]*Scan
	counter int
}

type Scan struct {
	ID      string
	Hosts   []model.Host
	Targets []string
	Done    int
	Total   int
	State   string
	Started time.Time
	cancel  context.CancelFunc
	subs    map[chan Event]struct{}
	mu      sync.Mutex
}

type Event struct {
	Type  string      `json:"type"`
	Host  *model.Host `json:"host,omitempty"`
	Done  int         `json:"done,omitempty"`
	Total int         `json:"total,omitempty"`
	Text  string      `json:"text,omitempty"`
}

func New(token string, st *store.Store) *Server {
	if token == "" {
		token = randomToken()
	}
	return &Server{token: token, store: st, scans: map[string]*Scan{}}
}

func (s *Server) Token() string { return s.token }

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/interfaces", s.auth(s.interfaces))
	mux.HandleFunc("/api/scan", s.auth(s.startScan))
	mux.HandleFunc("/api/scan/", s.auth(s.scanRoute))
	mux.HandleFunc("/api/snapshots", s.auth(s.snapshots))
	mux.HandleFunc("/api/snapshots/latest", s.auth(s.latest))
	mux.HandleFunc("/api/diff", s.auth(s.diff))
	mux.HandleFunc("/api/export", s.auth(s.export))
	mux.HandleFunc("/api/wol", s.auth(s.wake))
	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if got != s.token {
			writeErr(w, http.StatusUnauthorized, "invalid or missing token")
			return
		}
		next(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":        "mapip",
		"version":     Version,
		"disclaimer":  Disclaimer,
		"geolocation": false,
	})
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	list, err := netutil.LocalInterfaces()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cidr, _ := netutil.PrimaryLocalCIDR()
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": list, "primary_cidr": cidr})
}

type scanRequest struct {
	Targets   []string `json:"targets"`
	CIDR      string   `json:"cidr"`
	Ports     []int    `json:"ports"`
	PortScan  bool     `json:"port_scan"`
	TimeoutMs int      `json:"timeout_ms"`
	Enrich    bool     `json:"enrich"`
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	targetText := strings.Join(req.Targets, ",")
	if req.CIDR != "" {
		targetText = req.CIDR
	}
	ips, err := netutil.ParseTargets(targetText)
	if err != nil || len(ips) == 0 {
		writeErr(w, http.StatusBadRequest, "no usable targets")
		return
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = portscan.DefaultPorts()
	}

	ctx, cancel := context.WithCancel(context.Background())
	scan := &Scan{
		ID:      s.nextID(),
		Targets: netutil.NormalizeTargets(ips),
		Total:   len(ips),
		State:   "running",
		Started: time.Now(),
		cancel:  cancel,
		subs:    map[chan Event]struct{}{},
	}

	s.mu.Lock()
	s.scans[scan.ID] = scan
	s.mu.Unlock()

	opts := discovery.Options{
		Targets:     ips,
		Timeout:     timeout,
		Concurrency: 64,
		Ports:       ports,
		PortScan:    req.PortScan,
		Enrich:      req.Enrich,
	}

	go func() {
		res := discovery.ScanAll(ctx, opts, func(p discovery.Progress) {
			scan.mu.Lock()
			scan.Done = p.Done
			if p.Found {
				scan.Hosts = append(scan.Hosts, p.Host)
			}
			scan.mu.Unlock()
			ev := Event{Type: "progress", Done: p.Done, Total: p.Total}
			if p.Found {
				ev.Type = "host"
				h := p.Host
				ev.Host = &h
			}
			scan.broadcast(ev)
		})

		report := model.ScanReport{
			Targets:  scan.Targets,
			Hosts:    res.Hosts,
			Started:  scan.Started,
			Finished: time.Now(),
		}
		path, _ := s.store.Save(store.Snapshot{TakenAt: report.Finished, Targets: scan.Targets, Hosts: res.Hosts})

		scan.mu.Lock()
		scan.State = "done"
		scan.Hosts = res.Hosts
		scan.mu.Unlock()

		scan.broadcast(Event{Type: "done", Total: len(res.Hosts), Text: path})
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":      scan.ID,
		"total":   scan.Total,
		"targets": scan.Targets,
	})
}

func (s *Server) scanRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	parts := strings.Split(rest, "/")
	id := parts[0]

	s.mu.Lock()
	scan, ok := s.scans[id]
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown scan id")
		return
	}

	if len(parts) > 1 && parts[1] == "events" {
		s.streamEvents(w, r, scan)
		return
	}
	if len(parts) > 1 && parts[1] == "cancel" {
		scan.cancel()
		scan.mu.Lock()
		scan.State = "cancelled"
		scan.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "state": "cancelled"})
		return
	}

	scan.mu.Lock()
	defer scan.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      scan.ID,
		"state":   scan.State,
		"done":    scan.Done,
		"total":   scan.Total,
		"targets": scan.Targets,
		"hosts":   scan.Hosts,
	})
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request, scan *Scan) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan Event, 64)
	scan.subscribe(ch)
	defer scan.unsubscribe(ch)

	snapshot := Event{Type: "snapshot", Done: scan.Done, Total: scan.Total}
	writeEvent(w, snapshot)
	flusher.Flush()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			writeEvent(w, ev)
			flusher.Flush()
			if ev.Type == "done" {
				return
			}
		case <-keepAlive.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func (s *Server) snapshots(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": list})
}

func (s *Server) latest(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.store.Latest()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"snapshot": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshot": snap})
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.List()
	if err != nil || len(list) < 2 {
		writeJSON(w, http.StatusOK, map[string]any{"changes": []store.Change{}})
		return
	}
	before := list[len(list)-2]
	after := list[len(list)-1]
	writeJSON(w, http.StatusOK, map[string]any{
		"before":  before.TakenAt,
		"after":   after.TakenAt,
		"changes": store.Diff(before, after),
	})
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	snap, ok := s.store.Latest()
	if !ok {
		writeErr(w, http.StatusNotFound, "no snapshots to export")
		return
	}
	report := model.ScanReport{Targets: snap.Targets, Hosts: snap.Hosts, Started: snap.TakenAt, Finished: snap.TakenAt}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=mapip.csv")
		_ = output.WriteCSV(w, report)
	case "xml":
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", "attachment; filename=mapip.xml")
		_ = output.WriteNmapXML(w, report)
	case "html":
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", "attachment; filename=mapip.html")
		_ = output.WriteHTML(w, report)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=mapip.json")
		_ = output.WriteJSON(w, report)
	}
}

type wolRequest struct {
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast"`
}

func (s *Server) wake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req wolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := wol.Wake(req.MAC, req.Broadcast); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true, "mac": req.MAC})
}

func (s *Server) nextID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	return "scan-" + strconv.Itoa(s.counter)
}

func (sc *Scan) subscribe(ch chan Event) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.subs[ch] = struct{}{}
}

func (sc *Scan) unsubscribe(ch chan Event) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	delete(sc.subs, ch)
	close(ch)
}

func (sc *Scan) broadcast(ev Event) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for ch := range sc.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func Listen(addr string, handler http.Handler) (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return srv, ln, nil
}
