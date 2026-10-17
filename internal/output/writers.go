package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"strconv"
	"strings"

	"github.com/5evenTeam/mapip/internal/model"
)

func WriteJSON(w io.Writer, report model.ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteCSV(w io.Writer, report model.ScanReport) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ip", "hostname", "mac", "vendor", "os", "ttl", "rtt_ms", "ports"})
	for _, h := range report.Hosts {
		ports := make([]string, 0, len(h.Ports))
		for _, p := range h.Ports {
			ports = append(ports, strconv.Itoa(p.Port))
		}
		_ = cw.Write([]string{
			h.IP, h.Hostname, h.MAC, h.Vendor, h.OS,
			strconv.Itoa(h.TTL),
			fmt.Sprintf("%.2f", h.RTTMs),
			strings.Join(ports, " "),
		})
	}
	cw.Flush()
	return cw.Error()
}

func WriteTable(w io.Writer, report model.ScanReport) error {
	fmt.Fprintf(w, "%-16s %-24s %-18s %-18s %s\n", "IP", "HOSTNAME", "MAC", "VENDOR", "OPEN PORTS")
	for _, h := range report.Hosts {
		ports := make([]string, 0, len(h.Ports))
		for _, p := range h.Ports {
			label := strconv.Itoa(p.Port)
			if p.Service != "" {
				label += "/" + p.Service
			}
			ports = append(ports, label)
		}
		fmt.Fprintf(w, "%-16s %-24s %-18s %-18s %s\n",
			h.IP, dash(h.Hostname), dash(h.MAC), dash(h.Vendor), strings.Join(ports, " "))
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Scanner string     `xml:"scanner,attr"`
	Args    string     `xml:"args,attr"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr,omitempty"`
}

type nmapHostnames struct {
	Names []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr,omitempty"`
}

func WriteNmapXML(w io.Writer, report model.ScanReport) error {
	run := nmapRun{Scanner: "mapip", Args: "mapip " + strings.Join(report.Targets, " ")}
	for _, h := range report.Hosts {
		nh := nmapHost{Status: nmapStatus{State: "up"}}
		nh.Addresses = append(nh.Addresses, nmapAddress{Addr: h.IP, AddrType: "ipv4"})
		if h.MAC != "" {
			nh.Addresses = append(nh.Addresses, nmapAddress{Addr: h.MAC, AddrType: "mac", Vendor: h.Vendor})
		}
		if h.Hostname != "" {
			nh.Hostnames.Names = append(nh.Hostnames.Names, nmapHostname{Name: h.Hostname, Type: "PTR"})
		}
		for _, p := range h.Ports {
			nh.Ports.Ports = append(nh.Ports.Ports, nmapPort{
				Protocol: p.Proto,
				PortID:   p.Port,
				State:    nmapState{State: p.State, Reason: "syn-ack"},
				Service:  nmapService{Name: p.Service, Product: p.Banner},
			})
		}
		run.Hosts = append(run.Hosts, nh)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func WriteHTML(w io.Writer, report model.ScanReport) error {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<title>MapIp report</title>\n<style>\n")
	b.WriteString("body{background:#0b0f14;color:#c9d1d9;font:14px ui-monospace,Menlo,Consolas,monospace;padding:24px}\n")
	b.WriteString("h1{color:#58a6ff;font-size:18px}\n")
	b.WriteString("p.note{color:#8b949e}\n")
	b.WriteString("table{border-collapse:collapse;width:100%;margin-top:16px}\n")
	b.WriteString("th,td{border-bottom:1px solid #21262d;padding:6px 10px;text-align:left}\n")
	b.WriteString("th{color:#f0883e}\n")
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString("<h1>MapIp &mdash; network host map</h1>\n")
	b.WriteString("<p class=\"note\">Hosts on the scanned network. MapIp does not geolocate IP addresses.</p>\n")
	b.WriteString("<p class=\"note\">Targets: " + html.EscapeString(strings.Join(report.Targets, ", ")) + "</p>\n")
	b.WriteString("<table>\n<thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>OS</th><th>Ports</th></tr></thead>\n<tbody>\n")
	for _, h := range report.Hosts {
		ports := make([]string, 0, len(h.Ports))
		for _, p := range h.Ports {
			label := strconv.Itoa(p.Port)
			if p.Service != "" {
				label += "/" + p.Service
			}
			ports = append(ports, label)
		}
		b.WriteString("<tr>")
		b.WriteString("<td>" + html.EscapeString(h.IP) + "</td>")
		b.WriteString("<td>" + html.EscapeString(dash(h.Hostname)) + "</td>")
		b.WriteString("<td>" + html.EscapeString(dash(h.MAC)) + "</td>")
		b.WriteString("<td>" + html.EscapeString(dash(h.Vendor)) + "</td>")
		b.WriteString("<td>" + html.EscapeString(dash(h.OS)) + "</td>")
		b.WriteString("<td>" + html.EscapeString(strings.Join(ports, " ")) + "</td>")
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody>\n</table>\n</body>\n</html>\n")
	_, err := io.WriteString(w, b.String())
	return err
}
