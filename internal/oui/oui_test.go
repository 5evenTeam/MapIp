package oui

import "testing"

func TestLookupKnownPrefixes(t *testing.T) {
	if got := Lookup("3c:1b:f8:aa:bb:cc"); got == "" {
		t.Fatal("expected a vendor for 3c:1b:f8")
	}
	if got := Lookup("00:00:0c:11:22:33"); got == "" {
		t.Fatal("expected a vendor for 00:00:0c (Cisco)")
	}
}

func TestLookupAcceptsFormats(t *testing.T) {
	dashed := Lookup("00-00-0C-11-22-33")
	colon := Lookup("00:00:0c:11:22:33")
	plain := Lookup("00000C112233")
	if dashed == "" || dashed != colon || dashed != plain {
		t.Fatalf("formats disagree: dashed=%q colon=%q plain=%q", dashed, colon, plain)
	}
}

func TestLookupUnknown(t *testing.T) {
	if got := Lookup("ff:ff:ff:ff:ff:ff"); got != "" {
		t.Fatalf("expected empty for 02:00:00 style unknown prefix, got %q", got)
	}
	if got := Lookup("garbage"); got != "" {
		t.Fatalf("expected empty for garbage, got %q", got)
	}
	if got := Lookup(""); got != "" {
		t.Fatalf("expected empty for empty input, got %q", got)
	}
}

func TestDatabaseLoaded(t *testing.T) {
	if n := Count(); n < 40000 {
		t.Fatalf("expected the embedded IEEE registry to hold 40k+ prefixes, got %d", n)
	}
}
