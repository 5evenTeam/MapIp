package enrich

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

const (
	mdnsAddr  = "224.0.0.251:5353"
	llmnrAddr = "224.0.0.252:5355"

	dnsTypePTR = 12
)

func MDNSName(ip string, timeout time.Duration) string {
	return reverseLookup(ip, mdnsAddr, timeout)
}

func LLMNRName(ip string, timeout time.Duration) string {
	return reverseLookup(ip, llmnrAddr, timeout)
}

func reverseLookup(ip, server string, timeout time.Duration) string {
	name := reverseName(ip)
	if name == "" {
		return ""
	}
	query := buildPTRQuery(name)

	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	return firstPTR(buf[:n])
}

func reverseName(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	var b strings.Builder
	for i := 3; i >= 0; i-- {
		b.WriteString(itoaByte(v4[i]))
		b.WriteByte('.')
	}
	b.WriteString("in-addr.arpa")
	return b.String()
}

func itoaByte(v byte) string {
	if v == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = '0' + v%10
		v /= 10
	}
	return string(buf[i:])
}

func buildPTRQuery(name string) []byte {
	packet := make([]byte, 0, 12+len(name)+6)
	packet = append(packet, 0x00, 0x00)
	packet = append(packet, 0x00, 0x00)
	packet = append(packet, 0x00, 0x01)
	packet = append(packet, 0x00, 0x00)
	packet = append(packet, 0x00, 0x00)
	packet = append(packet, 0x00, 0x00)

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0x00)
	packet = append(packet, 0x00, byte(dnsTypePTR))
	packet = append(packet, 0x00, 0x01)
	return packet
}

func firstPTR(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))

	pos := 12
	for i := 0; i < qd; i++ {
		pos = dnsSkipName(msg, pos)
		if pos < 0 || pos+4 > len(msg) {
			return ""
		}
		pos += 4
	}

	for i := 0; i < an; i++ {
		pos = dnsSkipName(msg, pos)
		if pos < 0 || pos+10 > len(msg) {
			return ""
		}
		rrType := binary.BigEndian.Uint16(msg[pos : pos+2])
		rdlength := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10
		if pos+rdlength > len(msg) {
			return ""
		}
		if rrType == dnsTypePTR {
			name, _ := dnsReadName(msg, pos)
			name = strings.TrimSuffix(name, ".")
			if name != "" {
				return name
			}
		}
		pos += rdlength
	}
	return ""
}

func dnsSkipName(msg []byte, pos int) int {
	for pos >= 0 && pos < len(msg) {
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

func dnsReadName(msg []byte, pos int) (string, int) {
	var b strings.Builder
	jumped := false
	next := pos
	hops := 0

	for pos >= 0 && pos < len(msg) && hops < 32 {
		hops++
		length := int(msg[pos])
		if length == 0 {
			pos++
			if !jumped {
				next = pos
			}
			break
		}
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				break
			}
			offset := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3FFF)
			if !jumped {
				next = pos + 2
			}
			jumped = true
			pos = offset
			continue
		}
		pos++
		if pos+length > len(msg) {
			break
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(msg[pos : pos+length])
		pos += length
	}

	return b.String(), next
}
