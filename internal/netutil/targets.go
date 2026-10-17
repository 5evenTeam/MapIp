package netutil

import (
	"net"
	"strconv"
	"strings"
)

func ParseTargets(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	parts := strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err == nil {
			for _, ip := range expandCIDR(p) {
				out = append(out, ip)
			}
			continue
		}
		if strings.Contains(p, "-") && !strings.Contains(p, ":") {
			for _, ip := range expandRange(p) {
				out = append(out, ip)
			}
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			out = append(out, ip.String())
			continue
		}
		if host, err := net.LookupHost(p); err == nil && len(host) > 0 {
			out = append(out, host[0])
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func expandCIDR(cidr string) []string {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
		if len(ips) > 4096 {
			break
		}
	}
	if len(ips) > 0 {
		ips = ips[1 : len(ips)-1]
	}
	if len(ips) > 2048 {
		ips = ips[:2048]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func expandRange(r string) []string {
	parts := strings.Split(r, "-")
	if len(parts) != 2 {
		return []string{r}
	}
	base, end := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	b := net.ParseIP(base)
	if b == nil {
		return []string{r}
	}
	eip := net.ParseIP(end)
	if eip == nil {
		oct := strings.Split(base, ".")
		if len(oct) == 4 {
			if v, err := strconv.Atoi(end); err == nil && v >= 0 && v <= 255 {
				oct[3] = end
				eip = net.ParseIP(strings.Join(oct, "."))
			}
		}
	}
	if eip == nil {
		return []string{r}
	}
	var ips []string
	for ip := b; !ip.Equal(eip); inc(ip) {
		ips = append(ips, ip.String())
		if len(ips) > 2048 {
			break
		}
	}
	ips = append(ips, eip.String())
	return ips
}
