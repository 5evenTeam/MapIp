package wol

import (
	"errors"
	"net"
	"strings"
)

func Wake(mac string, broadcast string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	if len(hw) != 6 {
		return errors.New("wake-on-lan needs a 6-byte MAC address")
	}
	packet := make([]byte, 0, 102)
	packet = append(packet, make([]byte, 6)...)
	for i := 0; i < 16; i++ {
		packet = append(packet, hw...)
	}
	if broadcast == "" {
		broadcast = "255.255.255.255"
	}
	addr := broadcast
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(broadcast, "9")
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(packet)
	return err
}
