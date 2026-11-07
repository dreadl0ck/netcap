package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

var errFrame = errors.New("gateway: invalid, oversized or unsupported message")

func caPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("gateway: empty CA pool")
	}
	return p, nil
}
func (g *Gateway) listenerTLS() (*tls.Config, error) {
	if g.cfg.TLSCert == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(g.cfg.TLSCert, g.cfg.TLSKey)
	if err != nil {
		return nil, err
	}
	t := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if g.cfg.ClientCA != "" {
		t.ClientCAs, err = caPool(g.cfg.ClientCA)
		t.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return t, err
}
func (g *Gateway) upstreamTLS() (*tls.Config, error) {
	if !g.cfg.UpstreamTLS {
		return nil, nil
	}
	t := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: g.cfg.UpstreamServerName}
	var err error
	if g.cfg.UpstreamCA != "" {
		t.RootCAs, err = caPool(g.cfg.UpstreamCA)
	}
	if err == nil && g.cfg.UpstreamCert != "" {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(g.cfg.UpstreamCert, g.cfg.UpstreamKey)
		t.Certificates = []tls.Certificate{cert}
	}
	return t, err
}
func (g *Gateway) dial(ctx context.Context) (result net.Conn, resultErr error) {
	start := time.Now()
	defer func() {
		outcome := "ok"
		if resultErr != nil {
			outcome = "error"
		}
		g.Operations.Observe("connect", start, outcome)
	}()
	c, err := (&net.Dialer{Timeout: g.cfg.IOTimeout}).DialContext(ctx, "tcp", g.upstream)
	if err != nil {
		return nil, err
	}
	raw := c
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if g.cfg.UpstreamTLS && g.cfg.Protocol != "mysql" {
		if g.cfg.Protocol == "postgres" {
			if g.writeFrame(ctx, c, []byte{0, 0, 0, 8, 4, 210, 22, 47}) != nil {
				c.Close()
				return nil, errFrame
			}
			c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
			var b [1]byte
			if _, err = io.ReadFull(c, b[:]); err != nil || b[0] != 'S' {
				c.Close()
				return nil, errFrame
			}
		}
		tc := tls.Client(c, g.originTLS)
		tc.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
		if err = tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		c = tc
	}
	return c, nil
}
func (g *Gateway) serveClient(parent context.Context, c net.Conn, ip string) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(parent, g.cfg.SessionTimeout)
	defer cancel()
	raw := c
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if g.cfg.TLSCert != "" && g.cfg.Protocol != "postgres" && g.cfg.Protocol != "mysql" {
		tc := tls.Server(c, g.serverTLS)
		tc.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
		if tc.HandshakeContext(ctx) != nil {
			return
		}
		c = tc
	}
	switch g.cfg.Protocol {
	case "modbus":
		g.modbusClient(ctx, c, ip)
	case "dns-tcp", "dns-tls":
		g.dnsStream(ctx, c, ip)
	case "redis":
		g.redisClient(ctx, c, ip)
	case "postgres":
		g.postgresClient(ctx, c, ip)
	case "smtp":
		g.smtpClient(ctx, c, ip)
	case "mysql":
		g.mysqlClient(ctx, c, ip)
	case "dnp3":
		g.dnp3Client(ctx, c, ip)
	}
}

func event(protocol, command, ip string, attrs map[string]string) policy.Event {
	return policy.Event{Protocol: protocol, RecordType: protocol, Method: command, ClientIP: ip, Phase: "request", Attributes: attrs}
}

// ReadSlice has a fixed backing buffer: no unbounded ReadString allocation.
func boundedLine(r *bufio.Reader, limit int) ([]byte, error) {
	b, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	if len(b) > limit || len(b) < 2 || b[len(b)-2] != '\r' {
		return nil, errFrame
	}
	return append([]byte(nil), b...), nil
}
func cleanToken(s string) bool { return !strings.ContainsAny(s, "\x00\r\n") }
