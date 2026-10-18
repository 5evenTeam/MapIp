package remotemap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type Client struct {
	conn net.Conn
	sess *session
}

func Dial(addr, passphrase string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sess, err := clientHandshake(conn, passphrase)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &Client{conn: conn, sess: sess}, nil
}

func (c *Client) RemoteAddr() string {
	if c.conn == nil {
		return ""
	}
	return c.conn.RemoteAddr().String()
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	_ = c.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if req, err := json.Marshal(request{Op: "bye"}); err == nil {
		if err := c.sess.writeFrame(kindJSON, req); err == nil {
			_, _, _ = c.sess.readFrame()
		}
	}
	return c.conn.Close()
}

func (c *Client) call(req request, dst any) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := c.sess.writeFrame(kindJSON, payload); err != nil {
		return err
	}
	kind, reply, err := c.sess.readFrame()
	if err != nil {
		return err
	}
	if kind != kindJSON {
		return errors.New("remotemap: host sent an unexpected frame")
	}
	var resp response
	if err := json.Unmarshal(reply, &resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "host reported an error"
		}
		return errors.New(resp.Error)
	}
	if dst != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, dst)
	}
	return nil
}

func (c *Client) Ping() error {
	var out struct {
		Pong bool   `json:"pong"`
		Time string `json:"time"`
	}
	return c.call(request{Op: "ping"}, &out)
}

func (c *Client) Info() (Info, error) {
	var info Info
	err := c.call(request{Op: "info"}, &info)
	return info, err
}

type ListResult struct {
	Path    string  `json:"path"`
	Entries []Entry `json:"entries"`
}

func (c *Client) List(path string) (ListResult, error) {
	var res ListResult
	err := c.call(request{Op: "list", Path: path}, &res)
	return res, err
}

func (c *Client) Exec(command string, timeout time.Duration) (ExecResult, error) {
	secs := int(timeout / time.Second)
	if secs <= 0 {
		secs = 60
	}
	var res ExecResult
	err := c.call(request{Op: "exec", Command: command, TimeoutS: secs}, &res)
	return res, err
}

func (c *Client) Get(path string, w io.Writer) (TransferHeader, error) {
	payload, err := json.Marshal(request{Op: "get", Path: path})
	if err != nil {
		return TransferHeader{}, err
	}
	if err := c.sess.writeFrame(kindJSON, payload); err != nil {
		return TransferHeader{}, err
	}
	kind, reply, err := c.sess.readFrame()
	if err != nil {
		return TransferHeader{}, err
	}
	if kind != kindJSON {
		return TransferHeader{}, errors.New("remotemap: host sent an unexpected frame")
	}
	var resp response
	if err := json.Unmarshal(reply, &resp); err != nil {
		return TransferHeader{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "host reported an error"
		}
		return TransferHeader{}, errors.New(resp.Error)
	}
	var header TransferHeader
	if err := json.Unmarshal(resp.Data, &header); err != nil {
		return TransferHeader{}, err
	}
	for {
		kind, chunk, err := c.sess.readFrame()
		if err != nil {
			return header, err
		}
		if kind == kindEnd {
			break
		}
		if kind == kindBinary {
			if _, err := w.Write(chunk); err != nil {
				return header, err
			}
		}
	}
	return header, nil
}

func clientHandshake(conn net.Conn, passphrase string) (*session, error) {
	kind, payload, err := readPlainFrame(conn)
	if err != nil {
		return nil, err
	}
	if kind != kindHello || len(payload) != 1+nonceLen || payload[0] != ProtocolVersion {
		return nil, errors.New("remotemap: the remote endpoint is not a RemoteMap host")
	}
	serverNonce := payload[1:]

	clientNonce := randomBytes(nonceLen)
	mac := hmac.New(sha256.New, psk(passphrase))
	mac.Write([]byte("remotemap-client-v1"))
	mac.Write(serverNonce)
	mac.Write(clientNonce)

	auth := make([]byte, 0, 1+nonceLen+sha256.Size)
	auth = append(auth, ProtocolVersion)
	auth = append(auth, clientNonce...)
	auth = append(auth, mac.Sum(nil)...)
	if err := writePlainFrame(conn, kindAuth, auth); err != nil {
		return nil, err
	}

	kind, payload, err = readPlainFrame(conn)
	if err != nil {
		return nil, err
	}
	switch kind {
	case kindAuthFail:
		return nil, ErrAuth
	case kindAuthOK:
	default:
		return nil, errors.New("remotemap: unexpected handshake frame")
	}

	mac = hmac.New(sha256.New, psk(passphrase))
	mac.Write([]byte("remotemap-server-v1"))
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	if !hmac.Equal(payload, mac.Sum(nil)) {
		return nil, fmt.Errorf("%w: the host could not prove the shared key", ErrAuth)
	}

	clientKey, serverKey := deriveKeys(passphrase, serverNonce, clientNonce)
	return newSession(conn, serverKey, clientKey, 1, 0)
}
