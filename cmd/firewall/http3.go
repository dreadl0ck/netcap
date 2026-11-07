//go:build http3

package firewall

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewalltransport"
)

func serveHTTP3(ctx context.Context, conn net.PacketConn, tc *tls.Config, h http.Handler) error {
	return firewalltransport.ServeHTTP3(ctx, conn, firewalltransport.HTTP3Config{TLS: tc, MaxConnections: 64, MaxStreams: 128, IdleTimeout: 30 * time.Second, ShutdownTimeout: 5 * time.Second}, h)
}
