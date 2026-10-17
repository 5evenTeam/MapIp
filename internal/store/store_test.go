package store

import (
	"testing"
	"time"

	"github.com/5evenTeam/mapip/internal/model"
)

func host(ip string, ports ...int) model.Host {
	h := model.Host{IP: ip, Alive: true}
	for _, p := range ports {
		h.Ports = append(h.Ports, model.Port{Port: p, Proto: "tcp", State: "open"})
	}
	return h
}

func TestSaveAndLatest(t *testing.T) {
	s := New(t.TempDir())

	first := Snapshot{TakenAt: time.Now().Add(-time.Minute), Targets: []string{"a"}, Hosts: []model.Host{host("10.0.0.1")}}
	if _, err := s.Save(first); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	second := Snapshot{TakenAt: time.Now(), Targets: []string{"a"}, Hosts: []model.Host{host("10.0.0.1", 80)}}
	if _, err := s.Save(second); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	latest, ok := s.Latest()
	if !ok {
		t.Fatal("expected a snapshot")
	}
	if latest.Hosts[0].IP != "10.0.0.1" || len(latest.Hosts[0].Ports) != 1 {
		t.Fatalf("unexpected latest snapshot: %+v", latest)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(list))
	}
	if !list[0].TakenAt.Before(list[1].TakenAt) {
		t.Fatal("snapshots should be sorted oldest first")
	}
}

func TestLatestEmpty(t *testing.T) {
	s := New(t.TempDir())
	if _, ok := s.Latest(); ok {
		t.Fatal("expected no snapshot in an empty store")
	}
}

func TestDiffDetectsChanges(t *testing.T) {
	before := Snapshot{TakenAt: time.Now(), Hosts: []model.Host{
		host("10.0.0.1", 80),
		host("10.0.0.2"),
	}}
	after := Snapshot{TakenAt: time.Now(), Hosts: []model.Host{
		host("10.0.0.1", 80, 443),
		host("10.0.0.3"),
	}}

	changes := Diff(before, after)
	kinds := map[string]string{}
	for _, c := range changes {
		kinds[c.IP] = c.Kind
	}

	if kinds["10.0.0.1"] != "port-opened" {
		t.Errorf("expected port-opened for 10.0.0.1, got %q", kinds["10.0.0.1"])
	}
	if kinds["10.0.0.2"] != "missing" {
		t.Errorf("expected missing for 10.0.0.2, got %q", kinds["10.0.0.2"])
	}
	if kinds["10.0.0.3"] != "new" {
		t.Errorf("expected new for 10.0.0.3, got %q", kinds["10.0.0.3"])
	}
}

func TestDiffNoChanges(t *testing.T) {
	snap := Snapshot{TakenAt: time.Now(), Hosts: []model.Host{host("10.0.0.1", 80)}}
	if changes := Diff(snap, snap); len(changes) != 0 {
		t.Fatalf("expected no changes, got %+v", changes)
	}
}

func TestDiffDetectsMACChange(t *testing.T) {
	a := model.Host{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"}
	b := model.Host{IP: "10.0.0.1", MAC: "11:22:33:44:55:66"}
	changes := Diff(Snapshot{Hosts: []model.Host{a}}, Snapshot{Hosts: []model.Host{b}})
	found := false
	for _, c := range changes {
		if c.Kind == "mac-changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mac-changed, got %+v", changes)
	}
}
