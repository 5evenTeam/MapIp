package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/5evenTeam/mapip/internal/model"
)

type Snapshot struct {
	TakenAt time.Time    `json:"taken_at"`
	Targets []string     `json:"targets"`
	Hosts   []model.Host `json:"hosts"`
}

type Change struct {
	IP     string `json:"ip"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type Store struct {
	dir string
}

func New(dir string) *Store {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dir = filepath.Join(home, ".mapip")
		} else {
			dir = ".mapip"
		}
	}
	_ = os.MkdirAll(filepath.Join(dir, "snapshots"), 0o755)
	return &Store{dir: dir}
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Save(snap Snapshot) (string, error) {
	name := snap.TakenAt.Format("20060102-150405") + ".json"
	path := filepath.Join(s.dir, "snapshots", name)
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Store) List() ([]Snapshot, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "snapshots"))
	if err != nil {
		return nil, err
	}
	var out []Snapshot
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, "snapshots", e.Name()))
		if err != nil {
			continue
		}
		var snap Snapshot
		if json.Unmarshal(data, &snap) != nil {
			continue
		}
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TakenAt.Before(out[j].TakenAt) })
	return out, nil
}

func (s *Store) Latest() (Snapshot, bool) {
	list, err := s.List()
	if err != nil || len(list) == 0 {
		return Snapshot{}, false
	}
	return list[len(list)-1], true
}

func Diff(before, after Snapshot) []Change {
	prev := map[string]model.Host{}
	for _, h := range before.Hosts {
		prev[h.IP] = h
	}
	curr := map[string]model.Host{}
	for _, h := range after.Hosts {
		curr[h.IP] = h
	}

	var changes []Change
	for ip, h := range curr {
		old, existed := prev[ip]
		if !existed {
			changes = append(changes, Change{IP: ip, Kind: "new", Detail: describe(h)})
			continue
		}
		if old.MAC != "" && h.MAC != "" && old.MAC != h.MAC {
			changes = append(changes, Change{IP: ip, Kind: "mac-changed", Detail: old.MAC + " -> " + h.MAC})
		}
		if old.Hostname != h.Hostname && h.Hostname != "" {
			changes = append(changes, Change{IP: ip, Kind: "hostname-changed", Detail: old.Hostname + " -> " + h.Hostname})
		}
		for _, p := range h.Ports {
			if !hasPort(old.Ports, p.Port) {
				changes = append(changes, Change{IP: ip, Kind: "port-opened", Detail: describePort(p)})
			}
		}
		for _, p := range old.Ports {
			if !hasPort(h.Ports, p.Port) {
				changes = append(changes, Change{IP: ip, Kind: "port-closed", Detail: describePort(p)})
			}
		}
	}
	for ip, h := range prev {
		if _, ok := curr[ip]; !ok {
			changes = append(changes, Change{IP: ip, Kind: "missing", Detail: describe(h)})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].IP != changes[j].IP {
			return changes[i].IP < changes[j].IP
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes
}

func hasPort(ports []model.Port, port int) bool {
	for _, p := range ports {
		if p.Port == port {
			return true
		}
	}
	return false
}

func describe(h model.Host) string {
	if h.Hostname != "" {
		return h.Hostname
	}
	if h.MAC != "" {
		return h.MAC
	}
	return h.IP
}

func describePort(p model.Port) string {
	if p.Service != "" {
		return p.Proto + "/" + p.Service
	}
	return p.Proto + "/" + itoa(p.Port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
