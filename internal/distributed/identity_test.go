/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package distributed

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testIdentity struct {
	cert tls.Certificate
	fp   string
}

func newIdentity(t testing.TB, name string) testIdentity {
	t.Helper()

	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")

	fp, err := GenerateIdentity(certPath, keyPath, name)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := LoadIdentity(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if got, _ := IdentityFingerprint(cert); got != fp {
		t.Fatalf("fingerprint of loaded identity %s != generated %s", got, fp)
	}

	return testIdentity{cert: cert, fp: fp}
}

func TestGenerateIdentityPermsAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key")

	if _, err := GenerateIdentity(c, k, "a"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{c, k} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o, want 600", p, st.Mode().Perm())
		}
	}

	if _, err := GenerateIdentity(c, k, "a"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second generate: %v, want ErrExist", err)
	}
}

func TestParseAllowlist(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	fp2 := strings.Repeat("cd", 32)

	allow, err := ParseAllowlist(strings.NewReader("# comment\n\n" + strings.ToUpper(fp) + " sensor-1\n" + fp2 + " sensor_2.dmz\n"))
	if err != nil {
		t.Fatal(err)
	}
	if allow[fp] != "sensor-1" || allow[fp2] != "sensor_2.dmz" {
		t.Fatalf("got %v", allow)
	}

	bad := map[string]string{
		"traversal":    fp + " ../x",
		"absolute":     fp + " /etc",
		"dotdot":       fp + " ..",
		"dot":          fp + " .",
		"slash":        fp + " a/b",
		"backslash":    fp + " a\\b",
		"long name":    fp + " " + strings.Repeat("a", 65),
		"missing name": fp,
		"extra field":  fp + " a b",
		"short fp":     "abcd a",
		"non-hex fp":   strings.Repeat("zz", 32) + " a",
		"dup fp":       fp + " a\n" + fp + " b",
		"dup name":     fp + " a\n" + fp2 + " a",
		"empty":        "# nothing\n",
	}
	for name, in := range bad {
		if _, err := ParseAllowlist(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// handshake runs a TLS handshake between the two configs over a pipe.
func handshake(t *testing.T, server, client *tls.Config) (serverErr, clientErr error) {
	t.Helper()

	// Loopback TCP, not net.Pipe: an unbuffered pipe blocks the side that
	// sends the rejecting alert until its deadline.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	b, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	a, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))

	errc := make(chan error, 1)
	go func() {
		s := tls.Server(a, server)
		err := s.Handshake()
		if err != nil {
			_ = a.Close()
		}
		errc <- err
	}()

	c := tls.Client(b, client)
	clientErr = c.Handshake()
	if clientErr != nil {
		_ = b.Close()
	}

	return <-errc, clientErr
}

func TestTLSPinning(t *testing.T) {
	var (
		srv      = newIdentity(t, "srv")
		agent    = newIdentity(t, "agent")
		stranger = newIdentity(t, "stranger")
		allow    = Allowlist{agent.fp: "agent"}
	)

	clientConf := func(id testIdentity, pin string) *tls.Config {
		c, err := ClientTLSConfig(id.cert, pin)
		if err != nil {
			t.Fatal(err)
		}

		return c
	}

	if se, ce := handshake(t, ServerTLSConfig(srv.cert, allow), clientConf(agent, srv.fp)); se != nil || ce != nil {
		t.Fatalf("allowed client failed: server %v, client %v", se, ce)
	}

	if se, _ := handshake(t, ServerTLSConfig(srv.cert, allow), clientConf(stranger, srv.fp)); se == nil {
		t.Fatal("server accepted a client key that is not in the allowlist")
	}

	// The agent must refuse a collector whose key it has not pinned, even one
	// that would accept it.
	if _, ce := handshake(t, ServerTLSConfig(stranger.cert, allow), clientConf(agent, srv.fp)); ce == nil {
		t.Fatal("client accepted a server key that does not match the pin")
	}

	noCert := clientConf(agent, srv.fp)
	noCert.Certificates = nil
	if se, _ := handshake(t, ServerTLSConfig(srv.cert, allow), noCert); se == nil {
		t.Fatal("server accepted a client without a certificate")
	}

	if _, err := ClientTLSConfig(agent.cert, "nothex"); err == nil {
		t.Fatal("invalid pin accepted")
	}
}
