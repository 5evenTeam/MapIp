package oui

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed data/oui.tsv
var ouiData string

var (
	once sync.Once
	maL  map[string]string
	maM  map[string]string
)

func load() {
	maL = make(map[string]string, 48000)
	maM = make(map[string]string, 8000)
	for len(ouiData) > 0 {
		line := ouiData
		if i := strings.IndexByte(ouiData, '\n'); i >= 0 {
			line, ouiData = ouiData[:i], ouiData[i+1:]
		} else {
			ouiData = ""
		}
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		prefix := line[:tab]
		vendor := line[tab+1:]
		switch len(prefix) {
		case 6:
			maL[prefix] = vendor
		case 7:
			maM[prefix] = vendor
		}
	}
}

func hexMAC(mac string) string {
	var b strings.Builder
	b.Grow(12)
	for i := 0; i < len(mac); i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c >= 'a' && c <= 'f':
			b.WriteByte(c - 32)
		case c >= 'A' && c <= 'F':
			b.WriteByte(c)
		}
	}
	return b.String()
}

func Lookup(mac string) string {
	hex := hexMAC(mac)
	if len(hex) < 6 {
		return ""
	}
	once.Do(load)
	if v, ok := maL[hex[:6]]; ok {
		return v
	}
	if len(hex) >= 7 {
		if v, ok := maM[hex[:7]]; ok {
			return v
		}
	}
	return ""
}

func Count() int {
	once.Do(load)
	return len(maL) + len(maM)
}
