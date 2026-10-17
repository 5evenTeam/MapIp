package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	var out string
	var inputs multiFlag
	flag.StringVar(&out, "o", "internal/oui/data/oui.tsv", "output tsv")
	flag.Var(&inputs, "in", "input ieee csv (repeatable)")
	flag.Parse()

	rows := map[string]string{}

	for _, path := range inputs {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(1)
		}
		r := csv.NewReader(f)
		r.FieldsPerRecord = -1
		records, err := r.ReadAll()
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		for i, rec := range records {
			if i == 0 || len(rec) < 3 {
				continue
			}
			prefix := strings.ToUpper(strings.TrimSpace(rec[1]))
			vendor := strings.TrimSpace(rec[2])
			if prefix == "" || vendor == "" {
				continue
			}
			if !isHex(prefix) {
				continue
			}
			if len(prefix) != 6 && len(prefix) != 7 {
				continue
			}
			if _, exists := rows[prefix]; exists {
				continue
			}
			rows[prefix] = sanitize(vendor)
		}
	}

	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no rows parsed")
		os.Exit(1)
	}

	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('\t')
		b.WriteString(rows[k])
		b.WriteByte('\n')
	}

	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d prefixes to %s (%d bytes)\n", len(keys), out, b.Len())
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'F':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
