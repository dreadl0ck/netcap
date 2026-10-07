package protocoltest

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

type ServerTLS struct {
	CertificateFile       string `json:"certificateFile"`
	KeyFile               string `json:"keyFile"`
	ClientCAFile          string `json:"clientCAFile,omitempty"`
	PeerCertificateSHA256 string `json:"peerCertificateSHA256,omitempty"`
}

func loadIdentity(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := boundedFile(certFile, 1<<20)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := boundedFile(keyFile, 1<<20)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(cert, key)
}
func loadTrust(file string) (*x509.CertPool, error) {
	data, err := boundedFile(file, 1<<20)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file contains no valid PEM certificates")
	}
	return roots, nil
}

// Pins supplement normal chain/hostname verification, never replace it.
func setPeerPin(config *tls.Config, pin string) error {
	if pin == "" {
		return nil
	}
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("peer certificate pin must be SHA-256 hex of leaf DER")
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return fmt.Errorf("pin requires verified peer chain")
		}
		got := sha256.Sum256(state.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return fmt.Errorf("peer certificate pin mismatch")
		}
		return nil
	}
	return nil
}
func serverTLSConfig(spec ServerTLS) (*tls.Config, error) {
	identity, err := loadIdentity(spec.CertificateFile, spec.KeyFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity}}
	if spec.ClientCAFile != "" {
		config.ClientCAs, err = loadTrust(spec.ClientCAFile)
		if err != nil {
			return nil, err
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if spec.PeerCertificateSHA256 != "" && spec.ClientCAFile == "" {
		return nil, fmt.Errorf("server peer pin requires explicit client CA")
	}
	if err = setPeerPin(config, spec.PeerCertificateSHA256); err != nil {
		return nil, err
	}
	return config, nil
}
