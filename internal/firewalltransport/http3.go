//go:build http3

package firewalltransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// HTTP3Config requires explicit resource and time bounds. Early data is disabled.
type HTTP3Config struct {
	TLS             *tls.Config
	MaxConnections  int
	MaxStreams      int64
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

const HTTP3Available = true

// ServeHTTP3 terminates QUIC/TLS and dispatches real HTTP requests to handler.
// The caller owns conn; cancellation drains, then forcibly closes remaining streams.
func ServeHTTP3(ctx context.Context, conn net.PacketConn, c HTTP3Config, handler http.Handler) error {
	if ctx == nil || conn == nil || handler == nil || c.TLS == nil || (len(c.TLS.Certificates) == 0 && c.TLS.GetCertificate == nil && c.TLS.GetConfigForClient == nil) {
		return errors.New("HTTP/3 requires context, UDP connection, TLS certificate and handler")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 4096 || c.MaxStreams < 1 || c.MaxStreams > 4096 || c.IdleTimeout <= 0 || c.IdleTimeout > 5*time.Minute || c.ShutdownTimeout <= 0 || c.ShutdownTimeout > time.Minute {
		return errors.New("HTTP/3 requires bounded connections, streams, idle and shutdown timeouts")
	}
	tlsConfig := c.TLS.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	slots := make(chan struct{}, c.MaxConnections)
	s := &http3.Server{TLSConfig: tlsConfig, Handler: handler, MaxHeaderBytes: 32 << 10, IdleTimeout: c.IdleTimeout, QUICConfig: &quic.Config{
		Allow0RTT: false, MaxIncomingStreams: c.MaxStreams, MaxIncomingUniStreams: 8,
		HandshakeIdleTimeout: c.IdleTimeout, MaxIdleTimeout: c.IdleTimeout,
		InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 1 << 20,
		InitialConnectionReceiveWindow: 128 << 10, MaxConnectionReceiveWindow: 4 << 20,
	}}
	transport := &quic.Transport{Conn: conn, ConnContext: func(parent context.Context, _ *quic.ClientInfo) (context.Context, error) {
		select {
		case slots <- struct{}{}:
		default:
			return nil, errors.New("HTTP/3 connection capacity exhausted")
		}
		context.AfterFunc(parent, func() { <-slots })
		return parent, nil
	}}
	defer transport.Close()
	listener, err := transport.Listen(http3.ConfigureTLSConfig(tlsConfig), s.QUICConfig)
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		drain, cancel := context.WithTimeout(context.Background(), c.ShutdownTimeout)
		defer cancel()
		_ = s.Shutdown(drain)
		_ = s.Close()
	})
	err = s.ServeListener(listener)
	if !stop() {
		<-done
	}
	if ctx.Err() != nil && (errors.Is(err, http.ErrServerClosed) || err == nil) {
		return nil
	}
	return err
}
