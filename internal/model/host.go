package model

import "time"

type Host struct {
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	MAC       string    `json:"mac"`
	Vendor    string    `json:"vendor"`
	TTL       int       `json:"ttl"`
	OS        string    `json:"os"`
	Alive     bool      `json:"alive"`
	RTTMs     float64   `json:"rtt_ms"`
	Ports     []Port    `json:"ports"`
	Names     Names     `json:"names"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner"`
}

type Names struct {
	MDNS    string `json:"mdns"`
	LLMNR   string `json:"llmnr"`
	NetBIOS string `json:"netbios"`
	SSDP    string `json:"ssdp"`
	SNMP    string `json:"snmp"`
	DHCP    string `json:"dhcp"`
}

type ScanReport struct {
	Targets  []string  `json:"targets"`
	Hosts    []Host    `json:"hosts"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}
