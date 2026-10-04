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
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"
)

// validName is the only shape a client name may take. It is a single path
// segment, so it is safe to use as a directory name.
var validName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidName reports whether name may be used as a client name.
func ValidName(name string) bool {
	return validName.MatchString(name) && name != "." && name != ".."
}

// GenerateIdentity creates a self-signed Ed25519 certificate and key and writes
// them as PEM to certPath and keyPath with mode 0600. Existing files are never
// overwritten. It returns the SPKI fingerprint to pin on the other side.
func GenerateIdentity(certPath, keyPath, commonName string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		// Trust is the pinned key, not the validity window, which is ignored.
		NotAfter:    now.AddDate(100, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return "", err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}

	// Write the key first: a cert without its key is useless, the reverse is harmless.
	if err = writePEMExclusive(keyPath, "PRIVATE KEY", keyDER); err != nil {
		return "", err
	}
	if err = writePEMExclusive(certPath, "CERTIFICATE", der); err != nil {
		return "", err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}

	return Fingerprint(cert), nil
}

func writePEMExclusive(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	if err = pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		_ = f.Close()

		return err
	}

	return f.Close()
}

// LoadIdentity loads a certificate and key written by GenerateIdentity.
func LoadIdentity(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return cert, err
	}

	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}

	return cert, err
}

// Fingerprint returns the lowercase hex SHA-256 of the certificate's public key.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	return hex.EncodeToString(sum[:])
}

// IdentityFingerprint returns the fingerprint of a loaded identity.
func IdentityFingerprint(id tls.Certificate) (string, error) {
	leaf := id.Leaf
	if leaf == nil {
		if len(id.Certificate) == 0 {
			return "", errors.New("identity has no certificate")
		}

		var err error
		if leaf, err = x509.ParseCertificate(id.Certificate[0]); err != nil {
			return "", err
		}
	}

	return Fingerprint(leaf), nil
}

// NormalizeFingerprint lowercases a fingerprint, strips ':' separators and
// checks that it is 32 bytes of hex.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))

	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("invalid fingerprint %q: want 64 hex characters", s)
	}

	return s, nil
}

// Allowlist maps a client key fingerprint to the client's name.
type Allowlist map[string]string

// ParseAllowlist reads lines of "<fingerprint> <name>". Blank lines and lines
// starting with '#' are ignored. Any malformed line, invalid name, or
// duplicate fingerprint or name is an error, so a typo stops the collector
// rather than silently locking a client out or merging two clients.
func ParseAllowlist(r io.Reader) (Allowlist, error) {
	var (
		allow = Allowlist{}
		names = map[string]bool{}
		sc    = bufio.NewScanner(r)
		line  int
	)

	for sc.Scan() {
		line++

		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: want \"<fingerprint> <name>\"", line)
		}

		fp, err := NormalizeFingerprint(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}

		name := fields[1]
		if !ValidName(name) {
			return nil, fmt.Errorf("line %d: invalid client name %q: want 1-64 of [A-Za-z0-9._-]", line, name)
		}
		if _, dup := allow[fp]; dup {
			return nil, fmt.Errorf("line %d: duplicate fingerprint", line)
		}
		if names[name] {
			return nil, fmt.Errorf("line %d: duplicate client name %q", line, name)
		}

		allow[fp] = name
		names[name] = true
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(allow) == 0 {
		return nil, errors.New("allowlist is empty: no client could connect")
	}

	return allow, nil
}

// LoadAllowlist parses the allowlist file at path.
func LoadAllowlist(path string) (Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ParseAllowlist(f)
}

func peerLeaf(certs []*x509.Certificate) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("peer presented no certificate")
	}

	return certs[0], nil
}

// ServerTLSConfig returns a TLS 1.3 config that requires a client certificate
// whose key is in allow.
func ServerTLSConfig(id tls.Certificate, allow Allowlist) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id},
		// Chain verification is replaced by key pinning below.
		ClientAuth: tls.RequireAnyClientCert,
		// VerifyConnection, unlike VerifyPeerCertificate, also runs on
		// resumed sessions; tickets are off regardless.
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			leaf, err := peerLeaf(cs.PeerCertificates)
			if err != nil {
				return err
			}
			if _, ok := allow[Fingerprint(leaf)]; !ok {
				return fmt.Errorf("client key %s is not in the allowlist", Fingerprint(leaf))
			}

			return nil
		},
	}
}

// ClientTLSConfig returns a TLS 1.3 config that presents id and accepts only
// a server whose key has the pinned fingerprint.
func ClientTLSConfig(id tls.Certificate, serverFingerprint string) (*tls.Config, error) {
	want, err := NormalizeFingerprint(serverFingerprint)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id},
		// The server cert is self-signed; VerifyConnection pins its key instead.
		InsecureSkipVerify: true, //nolint:gosec // replaced by key pinning
		VerifyConnection: func(cs tls.ConnectionState) error {
			leaf, err := peerLeaf(cs.PeerCertificates)
			if err != nil {
				return err
			}
			if got := Fingerprint(leaf); got != want {
				return fmt.Errorf("server key %s does not match pinned %s", got, want)
			}

			return nil
		},
	}, nil
}

// PeerName returns the allowlist name of the client on an established
// server-side connection.
func PeerName(cs tls.ConnectionState, allow Allowlist) (string, error) {
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}

	name, ok := allow[Fingerprint(cs.PeerCertificates[0])]
	if !ok {
		return "", errors.New("client key not in allowlist")
	}

	return name, nil
}
