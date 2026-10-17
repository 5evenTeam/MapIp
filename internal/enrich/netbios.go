package enrich

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

func NetBIOSName(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(nodeStatusQuery()); err != nil {
		return ""
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	return parseNodeStatus(buf[:n])
}

func nodeStatusQuery() []byte {
	packet := make([]byte, 0, 50)
	txid := []byte{0x13, 0x37}
	packet = append(packet, txid...)
	packet = append(packet, 0x00, 0x00)
	packet = append(packet, 0x00, 0x01)
	packet = append(packet, 0x00, 0x00)
	packet = append(packet, 0x00, 0x00)
	packet = append(packet, 0x00, 0x00)

	packet = append(packet, 0x20)
	packet = append(packet, 'C', 'K')
	for i := 0; i < 15; i++ {
		packet = append(packet, 'A', 'A')
	}
	packet = append(packet, 0x00)
	packet = append(packet, 0x00, 0x21)
	packet = append(packet, 0x00, 0x01)
	return packet
}

func parseNodeStatus(msg []byte) string {
	pos := 12
	if pos >= len(msg) {
		return ""
	}

	pos = skipName(msg, pos)
	if pos < 0 || pos+4 > len(msg) {
		return ""
	}
	pos += 4

	pos = skipName(msg, pos)
	if pos < 0 || pos+10 > len(msg) {
		return ""
	}
	rdlength := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
	pos += 10
	if pos+rdlength > len(msg) || rdlength < 1 {
		return ""
	}

	rdata := msg[pos : pos+rdlength]
	count := int(rdata[0])
	entries := rdata[1:]

	best := ""
	for i := 0; i < count; i++ {
		off := i * 18
		if off+18 > len(entries) {
			break
		}
		raw := entries[off : off+15]
		suffix := entries[off+15]
		flags := binary.BigEndian.Uint16(entries[off+16 : off+18])
		group := flags&0x8000 != 0
		if group {
			continue
		}
		name := decodeNetBIOSName(raw)
		if name == "" {
			continue
		}
		if suffix == 0x00 {
			return name
		}
		if best == "" && suffix == 0x20 {
			best = name
		}
	}
	return best
}

func skipName(msg []byte, pos int) int {
	for pos < len(msg) {
		length := int(msg[pos])
		if length == 0 {
			return pos + 1
		}
		if length&0xC0 == 0xC0 {
			return pos + 2
		}
		pos += length + 1
	}
	return -1
}

func decodeNetBIOSName(raw []byte) string {
	var b strings.Builder
	for _, c := range raw {
		if c == 0x20 || c == 0x00 {
			break
		}
		if c >= 0x21 && c <= 0x7E {
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}
