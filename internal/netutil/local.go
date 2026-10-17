package netutil

import (
	"errors"
	"net"
	"strings"
)

type Interface struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	CIDR    string `json:"cidr"`
	Private bool   `json:"private"`
}

func LocalInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			out = append(out, Interface{
				Name:    iface.Name,
				Address: ip4.String(),
				CIDR:    ipnet.String(),
				Private: isPrivate(ip4),
			})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no usable IPv4 interface found")
	}
	return out, nil
}

func PrimaryLocalCIDR() (string, error) {
	list, err := LocalInterfaces()
	if err != nil {
		return "", err
	}
	for _, i := range list {
		if i.Private {
			return i.CIDR, nil
		}
	}
	return list[0].CIDR, nil
}

func isPrivate(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 169 && v4[1] == 254:
			return true
		}
	}
	return false
}

func NormalizeTargets(list []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(list))
	for _, t := range list {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}
