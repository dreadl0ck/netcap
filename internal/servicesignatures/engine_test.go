package servicesignatures

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic fixtures authored from the cited wire grammars, not vendor corpora.
func TestProtocolFixturesAndSegmentation(t *testing.T) {
	e := Builtin()
	for _, tc := range []struct{ banner, id string }{
		{"SSH-2.0-NetcapFixture_1.0 comment\r\n", "netcap.ssh.ident.v1"},
		{"HTTP/1.1 200 OK\r\n", "netcap.http.response.v1"},
		{"HTTP/1.0 503 Unavailable\r\n", "netcap.http.response.v1"},
		{"220 mail.example ESMTP ready\r\n", "netcap.smtp.greeting.v1"},
		{"220 FTP ready\r\n", "netcap.ftp.greeting.v1"},
	} {
		t.Run(tc.id+tc.banner[:3], func(t *testing.T) {
			for split := 0; split < len(tc.banner); split++ {
				if r, ok := e.Identify([]byte(tc.banner[:split]), "tcp", "server-to-client"); ok {
					t.Fatalf("premature match at %d: %+v", split, r)
				}
				prefix := append([]byte(tc.banner[:split]), []byte(tc.banner[split:])...)
				r, ok := e.Identify(prefix, "tcp", "server-to-client")
				if !ok || r.ID != tc.id {
					t.Fatalf("split %d: %+v %v", split, r, ok)
				}
			}
			for _, scope := range [][2]string{{"udp", "server-to-client"}, {"tcp", "client-to-server"}, {"tcp", "unknown"}} {
				if _, ok := e.Identify([]byte(tc.banner), scope[0], scope[1]); ok {
					t.Fatal("wrong transport/direction matched")
				}
			}
		})
	}
}

func TestNegativeCollisionAndGapFixtures(t *testing.T) {
	e := Builtin()
	for _, s := range []string{
		"220 ready\r\n", "220 FTP SMTP ready\r\n", "220 notsmtp ready\r\n", "220 ESMTPish ready\r\n",
		"220-mail.example ESMTP ready\r\n", "SSH-2.0-\r\n", "SSH-2.0-bad-name\r\n", "SSH-2.0-name\x00\r\n",
		"HTTP/2.0 200 OK\r\n", "HTTP/1.1 999 Nope\r\n", "HTTP/1.1 20x Nope\r\n", "HTTP/1.1 200\r\n",
		"noise HTTP/1.1 200 OK\r\n", "HTTP/1.1 200 OK\n", "2.0-Fixture\r\n", // missing prefix/gap
		"SSH-2.0-" + strings.Repeat("a", 246) + "\r\n",
		strings.Repeat("a", MaxBannerBytes) + "\r\n",
	} {
		if r, ok := e.Identify([]byte(s), "tcp", "server-to-client"); ok {
			t.Errorf("false match %q: %+v", s, r)
		}
	}
}

func TestCatalogueValidation(t *testing.T) {
	for _, mutate := range []func(*Catalogue){
		func(c *Catalogue) { c.SchemaVersion = 2 }, func(c *Catalogue) { c.Format = "other" },
		func(c *Catalogue) { c.Rules = nil }, func(c *Catalogue) { c.Rules[0].ID = "ssh-1" },
		func(c *Catalogue) { c.Rules[0].Kind = "regex" }, func(c *Catalogue) { c.Rules[0].Provenance = nil },
		func(c *Catalogue) { c.Rules[0].Provenance[0].URL = "file:///tmp/x" },
		func(c *Catalogue) { c.Rules[0].Transport = "udp" }, func(c *Catalogue) { c.Rules[0].Protocol = "smtp" },
		func(c *Catalogue) { c.Rules[1].ID = c.Rules[0].ID }, func(c *Catalogue) { c.Rules = append(c.Rules, c.Rules[0]) },
	} {
		c := Builtin().Catalogue()
		mutate(&c)
		b, _ := json.Marshal(c)
		if _, err := Parse(bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted malformed catalogue %s", b)
		}
	}
	for _, b := range [][]byte{
		append(append([]byte{}, builtin...), []byte(` {}`)...),
		[]byte(`{"format":"netcap-service-signatures","schema_version":1,"rules":[],"unknown":true}`),
		bytes.Replace(builtin, []byte(`"schema_version": 1`), []byte(`"schema_version": 2, "schema_version": 1`), 1),
		bytes.Replace(builtin, []byte(`"id":"netcap.ssh.ident.v1"`), []byte(`"id":"netcap.other", "id":"netcap.ssh.ident.v1"`), 1),
		bytes.Repeat([]byte{' '}, MaxCatalogueBytes+1),
		[]byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)),
	} {
		if _, err := Parse(bytes.NewReader(b)); err == nil {
			t.Fatal("accepted malformed/oversized input")
		}
	}
}

func TestLoadFallbackAndReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	for _, content := range []string{"", "not-json"} {
		if content != "" {
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		e, err := Load(path)
		if e == nil || err == nil || !strings.Contains(err.Error(), "degraded") {
			t.Fatalf("missing visible fallback: %v", err)
		}
	}
	if err := os.WriteFile(path, builtin, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := Load(path)
	if err != nil || len(e.Catalogue().Rules) != 4 {
		t.Fatalf("%v", err)
	}
	c := e.Catalogue()
	c.Rules[0].ID = "netcap.changed"
	if e.Catalogue().Rules[0].ID == c.Rules[0].ID {
		t.Fatal("catalogue was mutable")
	}
}

func BenchmarkIdentify(b *testing.B) {
	e := Builtin()
	data := []byte("SSH-2.0-NetcapFixture_1.0\r\n")
	for b.Loop() {
		e.Identify(data, "tcp", "server-to-client")
	}
}
