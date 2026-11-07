//go:build coraza && http3

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func fixtureTLS() (*tls.Config, string, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}
	cert := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(8 * 24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		return nil, "", err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(der)
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, hex.EncodeToString(hash[:]), nil
}

// The lifecycle lock makes old requests drain before replacing the local proxy,
// policy and TLS identity. Origins retain their independent cumulative ledger.
func (p *profile) restart(ctx context.Context) (string, string, error) {
	old := p.CertificateSHA256
	replacement, err := newProfile(ctx, p.Rules, p.CRS, p.Protocol)
	if err != nil {
		return old, "", err
	}
	replacement.Ledger = p.Ledger
	p.Close()
	p.Client, p.URL, p.FW, p.Policy, p.Close, p.Down = replacement.Client, replacement.URL, replacement.FW, replacement.Policy, replacement.Close, replacement.Down
	p.CertificateSHA256 = replacement.CertificateSHA256
	p.OriginURL = replacement.OriginURL
	return old, p.CertificateSHA256, nil
}

func (p *profile) exerciseFault(ctx context.Context, generation int) (map[string]any, error) {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	started := time.Now()
	p.Down.Store(true)
	status, _, err := p.requestUnlocked(training[0])
	p.Down.Store(false)
	if err != nil || status != 503 {
		return nil, fmt.Errorf("owned outage not observed: %d %v", status, err)
	}
	compiled, err := compileState(p.Rules, generation, p.Stateful)
	if err != nil {
		return nil, err
	}
	p.FW.SetPolicy(compiled)
	if p.FW.BodyCapabilities().BufferedBytes != 0 {
		return nil, fmt.Errorf("buffer not released after outage")
	}
	oldCert, newCert, err := p.restart(ctx)
	if err != nil {
		return nil, err
	}
	p.FW.SetPolicy(compiled)
	status, actual, err := p.requestUnlocked(training[0])
	if err != nil || status != 200 || actual != p.Protocol {
		return nil, fmt.Errorf("restart recovery: %d h%d %v", status, actual, err)
	}
	status, _, err = p.requestUnlocked(workflow{"post-restart-denial", "/api/invoices", "application/json", `{"value":"` + forbidden + `"}`})
	if err != nil || status != 403 || oldCert == newCert {
		return nil, fmt.Errorf("restart certificate/denial invariant failed: %d %v", status, err)
	}
	if err = checkLedger(p.Ledger); err != nil {
		return nil, err
	}
	return map[string]any{"profile": p.Name, "kind": "owned origin 503, policy reload, in-process proxy/listener restart with new TLS identity", "recovery_ms": float64(time.Since(started)) / float64(time.Millisecond), "revision": compiled.Revision(), "old_certificate_sha256": oldCert, "new_certificate_sha256": newCert, "buffered_bytes_after_recovery": p.FW.BodyCapabilities().BufferedBytes}, nil
}

func diskBytes(directory string) int64 {
	var total int64
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return -1
	}
	return total
}
