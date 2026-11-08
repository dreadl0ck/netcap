package devicecatalog

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSharedVectors(t *testing.T) {
	b, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		MACCatalogue json.RawMessage `json:"mac_catalogue"`
		MAC          []struct{ Input, Want string }
		DHCP         []struct {
			Options     []Option
			File, Sname []byte
			Want        string
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	c, err := ParseMAC(v.MACCatalogue)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range v.MAC {
		t.Run(fmt.Sprintf("mac/%d", i), func(t *testing.T) {
			if got := c.Lookup(v.Input); got != v.Want {
				t.Fatalf("%q: %q != %q", v.Input, got, v.Want)
			}
		})
	}
	for i, v := range v.DHCP {
		t.Run(fmt.Sprintf("dhcp/%d", i), func(t *testing.T) {
			if got := ParameterKey(v.Options, v.File, v.Sname); got != v.Want {
				t.Fatalf("%q != %q", got, v.Want)
			}
		})
	}
}

func TestSourceOutputs(t *testing.T) {
	b, err := os.ReadFile("data/dhcp-catalogue-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseDHCP(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 535 {
		t.Fatal(len(c.Entries))
	}
	ambiguous, occurrences := 0, 0
	for _, e := range c.Entries {
		occurrences += len(e.Candidates)
		if len(e.Candidates) > 1 {
			ambiguous++
			if c.Lookup(e.Key) != "" {
				t.Fatal("collision became identity")
			}
		}
	}
	if ambiguous != 1 || occurrences != 536 {
		t.Fatalf("%d %d", ambiguous, occurrences)
	}
	if c.Lookup("1,3,6") != "Xbox 360" || c.Lookup("6,3,1") == "Xbox 360" {
		t.Fatal("ordered list mismatch")
	}
	b, err = os.ReadFile("sources/dhcp_fingerprints.conf")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != c.SourceSHA256 {
		t.Fatal("source hash")
	}
	b, err = os.ReadFile("data/mac-catalogue-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMAC(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 58971 || m.Lookup("00:00:0c:12:34:56") == "" {
		t.Fatal("missing IEEE assignments")
	}
}

func TestRejectCatalogueMutations(t *testing.T) {
	b, _ := os.ReadFile("data/dhcp-catalogue-v1.json")
	for _, bad := range []string{`{}`, `{"1,3,6":{"device_name":"legacy"}}`, string(b) + "{}", strings.Replace(string(b), `"schema": 1`, `"schema": 2`, 1), strings.Replace(string(b), `"key":`, `"unknown":`, 1), strings.Replace(string(b), `"key": "1,`, `"key": "01,`, 1)} {
		if _, err := ParseDHCP([]byte(bad)); err == nil {
			t.Fatal("accepted malformed DHCP catalogue")
		}
	}
	for _, key := range []string{"", "01,3", "256", "-1", "+1", "1, 3", "1,", strings.Repeat("1,", 257) + "1"} {
		if ValidKey(key) {
			t.Fatal(key)
		}
	}
	b, _ = os.ReadFile("data/mac-catalogue-v1.json")
	for _, bad := range []string{`{}`, string(b) + "{}", strings.Replace(string(b), `"bits": 24`, `"bits": 25`, 1), strings.Replace(string(b), `"prefix": "`, `"prefix": "z`, 1), strings.Replace(string(b), `"organization":`, `"address":`, 1)} {
		if _, err := ParseMAC([]byte(bad)); err == nil {
			t.Fatal("accepted malformed MAC catalogue")
		}
	}
}

func TestRandomMACsAndLimits(t *testing.T) {
	var x uint64 = 0x66
	for range 4096 {
		x = x*6364136223846793005 + 1
		raw := fmt.Sprintf("%012x", x&0xffffffffffff)
		got := NormalizeMAC(raw)
		if (x>>40)&3 != 0 {
			if got != "" {
				t.Fatal(raw)
			}
		} else if got != strings.ToUpper(raw) {
			t.Fatal(raw, got)
		}
		if NormalizeMAC(raw+"z") != "" {
			t.Fatal("suffix accepted")
		}
	}
	if ParameterKey([]Option{{55, 255, make([]byte, 255)}, {55, 2, []byte{1, 2}}}, nil, nil) != "" {
		t.Fatal("unbounded PRL")
	}
	if _, err := ParseDHCP(make([]byte, MaxBytes+1)); err == nil {
		t.Fatal("unbounded file")
	}
}
