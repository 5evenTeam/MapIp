package remotemap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type HostConfig struct {
	Addr       string
	Key        string
	Root       string
	AllowShell bool
	Allow      []string
	Timeout    time.Duration
	Version    string
	Logger     *log.Logger
}

type Host struct {
	cfg   HostConfig
	root  string
	nets  []*net.IPNet
	log   *log.Logger
	ln    net.Listener
	start time.Time

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

func NewHost(cfg HostConfig) (*Host, error) {
	if strings.TrimSpace(cfg.Key) == "" {
		return nil, errors.New("remotemap: a pre-shared key is required")
	}
	if cfg.Addr == "" {
		cfg.Addr = fmt.Sprintf("0.0.0.0:%d", DefaultPort)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	root := cfg.Root
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		root = wd
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	if fi, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("remotemap: root %s: %w", abs, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("remotemap: root %s is not a directory", abs)
	}

	nets, err := parseAllow(cfg.Allow)
	if err != nil {
		return nil, err
	}

	return &Host{
		cfg:   cfg,
		root:  abs,
		nets:  nets,
		log:   cfg.Logger,
		conns: make(map[net.Conn]struct{}),
		start: time.Now(),
	}, nil
}

func parseAllow(allow []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range allow {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("remotemap: bad allow entry %q", entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("remotemap: bad allow entry %q", entry)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func (h *Host) Root() string { return h.root }

func (h *Host) Addr() net.Addr {
	if h.ln == nil {
		return nil
	}
	return h.ln.Addr()
}

func (h *Host) Listen() error {
	ln, err := net.Listen("tcp", h.cfg.Addr)
	if err != nil {
		return err
	}
	h.ln = ln
	return nil
}

func (h *Host) ListenAndServe(ctx context.Context) error {
	if err := h.Listen(); err != nil {
		return err
	}
	return h.Serve(ctx)
}

func (h *Host) Serve(ctx context.Context) error {
	if h.ln == nil {
		return errors.New("remotemap: Listen must be called before Serve")
	}
	go func() {
		<-ctx.Done()
		_ = h.ln.Close()
	}()

	for {
		conn, err := h.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				h.wg.Wait()
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		if !h.allowed(conn.RemoteAddr()) {
			h.logf("rejected %s: not in the allow-list", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		h.track(conn, true)
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer h.track(conn, false)
			h.handle(ctx, conn)
		}()
	}
}

func (h *Host) Close() error {
	if h.ln != nil {
		_ = h.ln.Close()
	}
	h.mu.Lock()
	for c := range h.conns {
		_ = c.Close()
	}
	h.mu.Unlock()
	h.wg.Wait()
	return nil
}

func (h *Host) track(c net.Conn, add bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if add {
		h.conns[c] = struct{}{}
	} else {
		delete(h.conns, c)
	}
}

func (h *Host) allowed(addr net.Addr) bool {
	if len(h.nets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range h.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *Host) logf(format string, args ...any) {
	h.log.Printf("[remotemap] "+format, args...)
}

func isDisconnect(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"forcibly closed",
		"connection reset",
		"connection aborted",
		"broken pipe",
		"use of closed network connection",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func requestDetail(req request) string {
	switch {
	case req.Path != "":
		return " " + req.Path
	case req.Command != "":
		return " " + req.Command
	default:
		return ""
	}
}

func (h *Host) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	h.logf("connection from %s", remote)

	_ = conn.SetDeadline(time.Now().Add(h.cfg.Timeout))
	sess, err := serverHandshake(conn, h.cfg.Key)
	if err != nil {
		h.logf("authentication failed for %s: %v", remote, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	h.logf("%s authenticated (key fingerprint %s)", remote, Fingerprint(h.cfg.Key))

	for {
		_ = conn.SetReadDeadline(time.Now().Add(h.cfg.Timeout))
		kind, payload, err := sess.readFrame()
		if err != nil {
			if isDisconnect(err) {
				h.logf("%s disconnected", remote)
			} else {
				h.logf("%s disconnected: %v", remote, err)
			}
			return
		}
		if kind != kindJSON {
			continue
		}
		var req request
		if err := json.Unmarshal(payload, &req); err != nil {
			_ = sess.sendError(errors.New("malformed request"))
			continue
		}
		h.logf("%s -> %s%s", remote, req.Op, requestDetail(req))
		if err := h.dispatch(sess, req); err != nil {
			h.logf("%s error: %v", remote, err)
			return
		}
		if req.Op == "bye" {
			h.logf("%s closed the session", remote)
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (h *Host) dispatch(sess *session, req request) error {
	switch req.Op {
	case "ping":
		return sess.sendJSON(response{OK: true, Data: raw(map[string]any{
			"pong": true,
			"time": time.Now().UTC().Format(time.RFC3339),
		})})
	case "info":
		return sess.sendJSON(response{OK: true, Data: raw(h.info())})
	case "list":
		return h.opList(sess, req)
	case "get":
		return h.opGet(sess, req)
	case "exec":
		return h.opExec(sess, req)
	case "bye":
		return sess.sendJSON(response{OK: true})
	default:
		return sess.sendError(fmt.Errorf("unknown operation %q", req.Op))
	}
}

func (h *Host) info() Info {
	hostname, _ := os.Hostname()
	username := ""
	if cu, err := user.Current(); err == nil {
		username = cu.Username
	}
	return Info{
		Version:    h.cfg.Version,
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		User:       username,
		UptimeSec:  int64(time.Since(h.start).Seconds()),
		Root:       h.root,
		AllowShell: h.cfg.AllowShell,
		Interfaces: localInterfaces(),
	}
}

func localInterfaces() []Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Interface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		var list []string
		for _, a := range addrs {
			list = append(list, a.String())
		}
		if len(list) == 0 {
			continue
		}
		out = append(out, Interface{Name: ifc.Name, Addresses: list})
	}
	return out
}

func (h *Host) opList(sess *session, req request) error {
	abs, err := h.safePath(req.Path)
	if err != nil {
		return sess.sendError(err)
	}
	dirents, err := os.ReadDir(abs)
	if err != nil {
		return sess.sendError(err)
	}
	entries := make([]Entry, 0, len(dirents))
	for _, de := range dirents {
		fi, err := de.Info()
		if err != nil {
			continue
		}
		entries = append(entries, Entry{
			Name:    de.Name(),
			Dir:     de.IsDir(),
			Size:    fi.Size(),
			Mode:    fi.Mode().String(),
			ModTime: fi.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	rel, err := filepath.Rel(h.root, abs)
	if err != nil {
		rel = "."
	}
	return sess.sendJSON(response{OK: true, Data: raw(map[string]any{
		"path":    filepath.ToSlash(rel),
		"entries": entries,
	})})
}

func (h *Host) opGet(sess *session, req request) error {
	abs, err := h.safePath(req.Path)
	if err != nil {
		return sess.sendError(err)
	}
	f, err := os.Open(abs)
	if err != nil {
		return sess.sendError(err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return sess.sendError(err)
	}
	if fi.IsDir() {
		return sess.sendError(errors.New("path is a directory"))
	}

	if err := sess.sendJSON(response{OK: true, Data: raw(TransferHeader{
		Name: filepath.Base(abs),
		Size: fi.Size(),
		Mode: fi.Mode().String(),
	})}); err != nil {
		return err
	}

	buf := make([]byte, 32<<10)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if werr := sess.writeFrame(kindBinary, buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return sess.writeFrame(kindEnd, nil)
}

func (h *Host) opExec(sess *session, req request) error {
	if !h.cfg.AllowShell {
		return sess.sendError(errors.New("this host was not started with --allow-shell"))
	}
	if strings.TrimSpace(req.Command) == "" {
		return sess.sendError(errors.New("empty command"))
	}
	timeout := time.Duration(req.TimeoutS) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return sess.sendJSON(response{OK: true, Data: raw(runCommand(req.Command, timeout))})
}

func runCommand(command string, timeout time.Duration) ExecResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	res := ExecResult{Command: command}
	err := cmd.Run()
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
			if res.Stderr == "" {
				res.Stderr = err.Error()
			}
		}
	}
	return res
}

func (h *Host) safePath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return h.root, nil
	}
	p = strings.TrimPrefix(filepath.ToSlash(p), "/")
	abs := filepath.Clean(filepath.Join(h.root, filepath.FromSlash(p)))

	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	} else {
		parent := filepath.Dir(abs)
		if pr, perr := filepath.EvalSymlinks(parent); perr == nil {
			abs = filepath.Join(pr, filepath.Base(abs))
		}
	}
	if !withinRoot(h.root, abs) {
		return "", fmt.Errorf("path %q is outside the shared directory", p)
	}
	return abs, nil
}

func withinRoot(root, p string) bool {
	root = filepath.Clean(root)
	p = filepath.Clean(p)
	if p == root {
		return true
	}
	sep := string(os.PathSeparator)
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(strings.ToLower(p), strings.ToLower(root)+sep)
	}
	return strings.HasPrefix(p, root+sep)
}

func serverHandshake(conn net.Conn, passphrase string) (*session, error) {
	serverNonce := randomBytes(nonceLen)
	hello := make([]byte, 0, 1+nonceLen)
	hello = append(hello, ProtocolVersion)
	hello = append(hello, serverNonce...)
	if err := writePlainFrame(conn, kindHello, hello); err != nil {
		return nil, err
	}

	kind, payload, err := readPlainFrame(conn)
	if err != nil {
		return nil, err
	}
	if kind != kindAuth {
		return nil, errors.New("remotemap: unexpected handshake frame")
	}
	if len(payload) != 1+nonceLen+sha256.Size || payload[0] != ProtocolVersion {
		_ = writePlainFrame(conn, kindAuthFail, nil)
		return nil, ErrAuth
	}
	clientNonce := payload[1 : 1+nonceLen]
	gotMAC := payload[1+nonceLen:]

	mac := hmac.New(sha256.New, psk(passphrase))
	mac.Write([]byte("remotemap-client-v1"))
	mac.Write(serverNonce)
	mac.Write(clientNonce)
	if !hmac.Equal(gotMAC, mac.Sum(nil)) {
		_ = writePlainFrame(conn, kindAuthFail, nil)
		return nil, ErrAuth
	}

	mac = hmac.New(sha256.New, psk(passphrase))
	mac.Write([]byte("remotemap-server-v1"))
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	if err := writePlainFrame(conn, kindAuthOK, mac.Sum(nil)); err != nil {
		return nil, err
	}

	clientKey, serverKey := deriveKeys(passphrase, serverNonce, clientNonce)
	return newSession(conn, clientKey, serverKey, 0, 1)
}

func LoadOrCreateKey(path string) (string, bool, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(b))
		if key == "" {
			return "", false, fmt.Errorf("remotemap: key file %s is empty", path)
		}
		return key, false, nil
	}
	if !os.IsNotExist(err) {
		return "", false, err
	}
	key := GenerateKey()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", false, err
		}
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", false, err
	}
	return key, true, nil
}

func DefaultKeyFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "MapIp", "remotemap", "key.txt")
}

func DefaultRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}
