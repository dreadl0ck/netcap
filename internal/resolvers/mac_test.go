package resolvers

import "testing"

func TestMACCompleteAddress(t *testing.T) {
	for _, address := range []string{"00:00:0c", "00x00x0cx00x00x01", "02:00:0c:00:00:01", "01:00:0c:00:00:01", "00:00:0c:00:00:zz"} {
		if got := LookupManufacturer(address); got != "" {
			t.Fatalf("%q: %q", address, got)
		}
	}
	want := LookupManufacturer("00:00:0c:00:00:01")
	if want == "" || LookupManufacturer("00000c000001") != want || LookupManufacturer("00-00-0C-00-00-01") != want {
		t.Fatal("normalization mismatch")
	}
}

func TestMACExplicitRefresh(t *testing.T) {
	old := macCatalogue.Load()
	t.Cleanup(func() { macCatalogue.Store(old) })
	if err := LoadMACCatalogue("../devicecatalog/data/mac-catalogue-v1.json"); err != nil {
		t.Fatal(err)
	}
	before := LookupManufacturer("00:00:0c:00:00:01")
	if before == "" {
		t.Fatal("empty refresh")
	}
	if err := LoadMACCatalogue("missing"); err == nil {
		t.Fatal("accepted missing")
	}
	if LookupManufacturer("00:00:0c:00:00:01") != before {
		t.Fatal("failed refresh erased table")
	}
}
