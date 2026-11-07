package waf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// ReloadTLS reads complete pairs before publication. A failed reload preserves live TLS and policy.
func (f *Firewall) ReloadTLS() error {
	c := f.cfg
	next := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSCert != "" {
		pair, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return err
		}
		next.Certificates = []tls.Certificate{pair}
	}
	if c.ClientCA != "" {
		b, err := os.ReadFile(c.ClientCA)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return errors.New("clientCA contains no certificates")
		}
		next.ClientCAs = roots
		next.ClientAuth = tls.RequireAndVerifyClientCert
	}
	var pair *tls.Certificate
	if c.UpstreamCert != "" {
		p, err := tls.LoadX509KeyPair(c.UpstreamCert, c.UpstreamKey)
		if err != nil {
			return err
		}
		pair = &p
	}
	if pair != nil {
		f.clientPair.Store(pair)
	}
	f.listenerTLS.Store(next)
	if pair != nil && f.transport != nil {
		f.transport.CloseIdleConnections()
	}
	return nil
}

// TLSConfig snapshots listener identity and client trust together at each handshake.
func (f *Firewall) TLSConfig() *tls.Config {
	return f.TLSConfigForProtocols("h2", "http/1.1")
}

// TLSConfigForProtocols preserves the listener's ALPN contract across identity reloads.
func (f *Firewall) TLSConfigForProtocols(protocols ...string) *tls.Config {
	protocols = append([]string(nil), protocols...)
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: append([]string(nil), protocols...), GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := f.listenerTLS.Load().Clone()
		c.NextProtos = protocols
		return c, nil
	}}
}
