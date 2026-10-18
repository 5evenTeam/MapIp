package remotemap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const ProtocolVersion byte = 1

const DefaultPort = 8530

const MaxFrame = 64 << 20

const (
	nonceLen = 32
	keyLen   = 32
)

const (
	kindHello    = 'H'
	kindAuth     = 'A'
	kindAuthOK   = 'K'
	kindAuthFail = 'F'
)

const (
	kindJSON   = 'J'
	kindBinary = 'B'
	kindEnd    = 'E'
)

var ErrAuth = errors.New("remotemap: authentication failed")

func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("remotemap: no system entropy: " + err.Error())
	}
	return b
}

func psk(passphrase string) []byte {
	sum := sha256.Sum256([]byte("remotemap-psk-v1\x00" + passphrase))
	return sum[:]
}

func Fingerprint(passphrase string) string {
	sum := sha256.Sum256(append([]byte("remotemap-fingerprint-v1\x00"), psk(passphrase)...))
	return hex.EncodeToString(sum[:4])
}

func GenerateKey() string { return hex.EncodeToString(randomBytes(keyLen)) }

func deriveKeys(passphrase string, serverNonce, clientNonce []byte) (clientKey, serverKey []byte) {
	salt := make([]byte, 0, nonceLen*2)
	salt = append(salt, serverNonce...)
	salt = append(salt, clientNonce...)
	prk := hkdfExtract(salt, psk(passphrase))
	clientKey = hkdfExpand(prk, []byte("remotemap-client-key-v1"), keyLen)
	serverKey = hkdfExpand(prk, []byte("remotemap-server-key-v1"), keyLen)
	return clientKey, serverKey
}

func writeU32(w io.Writer, n uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	_, err := w.Write(b[:])
	return err
}

func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func readPlainFrame(r io.Reader) (byte, []byte, error) {
	n, err := readU32(r)
	if err != nil {
		return 0, nil, err
	}
	if n == 0 || n > MaxFrame {
		return 0, nil, fmt.Errorf("remotemap: bad frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

func writePlainFrame(w io.Writer, kind byte, payload []byte) error {
	if err := writeU32(w, uint32(len(payload)+1)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{kind}); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

type session struct {
	conn net.Conn

	readAEAD, writeAEAD cipher.AEAD
	readDir, writeDir   byte

	readMu, writeMu   sync.Mutex
	readSeq, writeSeq uint64
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newSession(conn net.Conn, readKey, writeKey []byte, readDir, writeDir byte) (*session, error) {
	readAEAD, err := newAEAD(readKey)
	if err != nil {
		return nil, err
	}
	writeAEAD, err := newAEAD(writeKey)
	if err != nil {
		return nil, err
	}
	return &session{
		conn:      conn,
		readAEAD:  readAEAD,
		writeAEAD: writeAEAD,
		readDir:   readDir,
		writeDir:  writeDir,
	}, nil
}

func nonce(aead cipher.AEAD, dir byte, seq uint64) []byte {
	n := make([]byte, aead.NonceSize())
	n[0] = dir
	binary.BigEndian.PutUint64(n[len(n)-8:], seq)
	return n
}

func (s *session) writeFrame(kind byte, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	plaintext := make([]byte, 1+len(payload))
	plaintext[0] = kind
	copy(plaintext[1:], payload)

	sealed := s.writeAEAD.Seal(nil, nonce(s.writeAEAD, s.writeDir, s.writeSeq), plaintext, nil)
	s.writeSeq++

	if err := writeU32(s.conn, uint32(len(sealed))); err != nil {
		return err
	}
	_, err := s.conn.Write(sealed)
	return err
}

func (s *session) readFrame() (byte, []byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	n, err := readU32(s.conn)
	if err != nil {
		return 0, nil, err
	}
	if n == 0 || n > MaxFrame {
		return 0, nil, fmt.Errorf("remotemap: bad frame length %d", n)
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(s.conn, sealed); err != nil {
		return 0, nil, err
	}
	plaintext, err := s.readAEAD.Open(nil, nonce(s.readAEAD, s.readDir, s.readSeq), sealed, nil)
	if err != nil {
		return 0, nil, ErrAuth
	}
	s.readSeq++
	if len(plaintext) == 0 {
		return 0, nil, errors.New("remotemap: empty frame")
	}
	return plaintext[0], plaintext[1:], nil
}

type request struct {
	Op       string `json:"op"`
	Path     string `json:"path,omitempty"`
	Command  string `json:"command,omitempty"`
	TimeoutS int    `json:"timeout_seconds,omitempty"`
}

type response struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

func (s *session) sendJSON(resp response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return s.writeFrame(kindJSON, b)
}

func (s *session) sendError(err error) error {
	return s.sendJSON(response{OK: false, Error: err.Error()})
}

func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

type Info struct {
	Version    string      `json:"version"`
	Hostname   string      `json:"hostname"`
	OS         string      `json:"os"`
	Arch       string      `json:"arch"`
	User       string      `json:"user"`
	UptimeSec  int64       `json:"uptime_seconds"`
	Root       string      `json:"root"`
	AllowShell bool        `json:"allow_shell"`
	Interfaces []Interface `json:"interfaces"`
}

type Interface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

type Entry struct {
	Name    string `json:"name"`
	Dir     bool   `json:"dir"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
}

type ExecResult struct {
	Command  string `json:"command"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

type TransferHeader struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mode string `json:"mode"`
}
