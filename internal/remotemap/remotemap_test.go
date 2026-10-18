package remotemap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startHost(t *testing.T, cfg HostConfig) (*Host, string) {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	if cfg.Version == "" {
		cfg.Version = "test"
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	h, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if err := h.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = h.Close()
		<-done
	})
	return h, h.Addr().String()
}

func dial(t *testing.T, addr, key string) *Client {
	t.Helper()
	c, err := Dial(addr, key, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestInfoRoundTrip(t *testing.T) {
	root := t.TempDir()
	_, addr := startHost(t, HostConfig{Key: "correct horse battery", Root: root})
	c := dial(t, addr, "correct horse battery")

	info, err := c.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Version != "test" {
		t.Errorf("version = %q, want test", info.Version)
	}
	if filepath.Clean(info.Root) != filepath.Clean(root) {
		if !strings.HasSuffix(info.Root, filepath.Base(root)) {
			t.Errorf("root = %q, want under %q", info.Root, root)
		}
	}
	if info.Hostname == "" {
		t.Error("hostname is empty")
	}
	if info.AllowShell {
		t.Error("allow_shell should be false")
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	_, addr := startHost(t, HostConfig{Key: "the-right-key", Root: t.TempDir()})

	c, err := Dial(addr, "the-wrong-key", 5*time.Second)
	if err == nil {
		_ = c.Close()
		t.Fatal("expected authentication to fail")
	}
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
}

func TestNonRemoteMapPeerRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	if _, err := Dial(ln.Addr().String(), "k", 3*time.Second); err == nil {
		t.Fatal("expected an error dialing a non-RemoteMap endpoint")
	}
}

func TestWrongKeyFails(t *testing.T) {
	_, addr := startHost(t, HostConfig{Key: "right", Root: t.TempDir()})
	if _, err := Dial(addr, "wrong", 3*time.Second); !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
}

func TestListAndGet(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("netbreak-mapip-remotemap\n"), 4000)
	if err := os.WriteFile(filepath.Join(root, "sub", "data.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	_, addr := startHost(t, HostConfig{Key: "k1234567890", Root: root})
	c := dial(t, addr, "k1234567890")

	res, err := c.List("sub")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if res.Path != "sub" {
		t.Errorf("path = %q, want sub", res.Path)
	}
	if len(res.Entries) != 1 || res.Entries[0].Name != "data.bin" || res.Entries[0].Dir {
		t.Fatalf("unexpected entries: %+v", res.Entries)
	}
	if res.Entries[0].Size != int64(len(payload)) {
		t.Errorf("size = %d, want %d", res.Entries[0].Size, len(payload))
	}

	var got bytes.Buffer
	header, err := c.Get("sub/data.bin", &got)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if header.Name != "data.bin" || header.Size != int64(len(payload)) {
		t.Errorf("header = %+v", header)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("downloaded %d bytes, want %d", got.Len(), len(payload))
	}

	if _, err := c.List("/sub"); err != nil {
		t.Fatalf("List(/sub): %v", err)
	}
}

func TestPathEscapeRefused(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "shared")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, addr := startHost(t, HostConfig{Key: "k1234567890", Root: root})
	c := dial(t, addr, "k1234567890")

	for _, p := range []string{"../secret.txt", "..", "../"} {
		if _, err := c.Get(p, io.Discard); err == nil {
			t.Errorf("Get(%q) succeeded, want refusal", p)
		}
	}
	if _, err := c.List("../"); err == nil {
		t.Error("List(../) succeeded, want refusal")
	}
}

func TestExecRequiresOptIn(t *testing.T) {
	_, addr := startHost(t, HostConfig{Key: "k1234567890", Root: t.TempDir()})
	c := dial(t, addr, "k1234567890")

	_, err := c.Exec("echo hello", 5*time.Second)
	if err == nil {
		t.Fatal("Exec succeeded without --allow-shell")
	}
	if !strings.Contains(err.Error(), "allow-shell") {
		t.Errorf("error = %q, want a hint about --allow-shell", err)
	}
}

func TestExecWhenAllowed(t *testing.T) {
	_, addr := startHost(t, HostConfig{Key: "k1234567890", Root: t.TempDir(), AllowShell: true})
	c := dial(t, addr, "k1234567890")

	res, err := c.Exec("echo remotemap-ok", 10*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0 (stderr=%q)", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "remotemap-ok") {
		t.Errorf("stdout = %q, want it to contain remotemap-ok", res.Stdout)
	}
}

func TestAllowListRejectsOthers(t *testing.T) {
	_, addr := startHost(t, HostConfig{
		Key:   "k1234567890",
		Root:  t.TempDir(),
		Allow: []string{"10.99.0.0/16"},
	})
	if _, err := Dial(addr, "k1234567890", 3*time.Second); err == nil {
		t.Fatal("expected the allow-list to reject 127.0.0.1")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "key.txt")
	key, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !created || len(key) != 64 {
		t.Fatalf("created=%v key=%q", created, key)
	}
	again, created2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if created2 || again != key {
		t.Fatalf("second call returned created=%v key=%q, want the stored key", created2, again)
	}
}

func TestFingerprintIsStable(t *testing.T) {
	a := Fingerprint("some passphrase")
	if a != Fingerprint("some passphrase") {
		t.Error("fingerprint is not stable")
	}
	if a == Fingerprint("some passphrasf") {
		t.Error("fingerprint did not change with the key")
	}
}

func TestHKDFMatchesRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	prk := hkdfExtract(salt, ikm)
	okm := hkdfExpand(prk, info, 42)
	want := []byte{
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
		0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
		0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	}
	if !bytes.Equal(okm, want) {
		t.Errorf("hkdf okm = %x, want %x", okm, want)
	}
}
