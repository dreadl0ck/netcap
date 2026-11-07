//go:build !http3

package firewall

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
)

func serveHTTP3(context.Context, net.PacketConn, *tls.Config, http.Handler) error {
	return errors.New("HTTP/3 unavailable: rebuild with -tags http3")
}
