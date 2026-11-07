package waf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// ReloadTLS reads complete pairs before publication. A failed reload preserves live TLS and policy.
func (f *Firewall) ReloadTLS() error {
	f.routeMu.Lock()
	defer f.routeMu.Unlock()
	bindings := []*Firewall{f}
	if f.router != nil {
		for _, b := range f.router.current.Load().bindings {
			bindings = append(bindings, b.firewall)
		}
		for _, table := range f.retired {
			for _, b := range table.bindings {
				bindings = append(bindings, b.firewall)
			}
		}
	}
	type material struct {
		listener *tls.Config
		client   *tls.Certificate
	}
	staged := make([]material, len(bindings))
	for i, bound := range bindings {
		listener, pair, err := loadTLS(bound.cfg)
		if err != nil {
			return err
		}
		staged[i] = material{listener, pair}
	}
	for i, bound := range bindings {
		if staged[i].client != nil {
			bound.clientPair.Store(staged[i].client)
		}
		bound.listenerTLS.Store(staged[i].listener)
		if staged[i].client != nil && bound.transport != nil {
			bound.transport.CloseIdleConnections()
		}
	}
	return nil
}

func loadTLS(c Config) (*tls.Config, *tls.Certificate, error) {
	next := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSCert != "" {
		pair, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, nil, err
		}
		next.Certificates = []tls.Certificate{pair}
	}
	if c.ClientCA != "" {
		b, err := os.ReadFile(c.ClientCA)
		if err != nil {
			return nil, nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, nil, errors.New("clientCA contains no certificates")
		}
		next.ClientCAs = roots
		next.ClientAuth = tls.RequireAndVerifyClientCert
	}
	var pair *tls.Certificate
	if c.UpstreamCert != "" {
		p, err := tls.LoadX509KeyPair(c.UpstreamCert, c.UpstreamKey)
		if err != nil {
			return nil, nil, err
		}
		pair = &p
	}
	return next, pair, nil
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
