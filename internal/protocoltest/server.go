package protocoltest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// ServeOne emulates one ordered TCP session. Receive and send steps are separate
// when a response depends on a request. A new invocation resets all variables.
func ServeOne(ctx context.Context, listener net.Listener, spec Exchange) (result Result, runErr error) {
	result = Result{Version: 1, Status: "error", Address: listener.Addr().String(), Observations: []Observation{}, Limitations: []string{"one ordered TCP session; variables reset per invocation"}}
	defer func() {
		if runErr != nil {
			result.Error = runErr.Error()
		}
	}()
	if err := spec.Validate(); err != nil {
		return result, err
	}
	if spec.Network != "tcp" {
		return result, fmt.Errorf("TCP listener requires tcp; use ServeUDP for datagrams")
	}
	var config *tls.Config
	if spec.TLS {
		if spec.ServerTLS == nil {
			return result, fmt.Errorf("TLS server requires explicit serverTLS identity")
		}
		var err error
		config, err = serverTLSConfig(*spec.ServerTLS)
		if err != nil {
			return result, err
		}
	}
	if spec.RootCAFile != "" || spec.ClientCertificateFile != "" || spec.ClientKeyFile != "" || spec.ServerName != "" || spec.PeerCertificateSHA256 != "" {
		return result, fmt.Errorf("client TLS fields are unsupported by server; use serverTLS")
	}
	data, _ := json.Marshal(spec)
	sum := sha256.Sum256(data)
	result.ConfigurationSHA256 = hex.EncodeToString(sum[:])
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutMilliseconds)*time.Millisecond)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	conn, err := listener.Accept()
	if err != nil {
		return result, err
	}
	defer conn.Close()
	if config != nil {
		secure := tls.Server(conn, config)
		if err := secure.HandshakeContext(ctx); err != nil {
			return result, err
		}
		conn = secure
		defer secure.Close()
	}
	return runConnection(ctx, conn, spec, result)
}

// ServeUDP pins one peer on the first datagram and refuses cross-peer session
// mixing. UDP has no half-close, retransmission or reliable ordering semantics.
func ServeUDP(ctx context.Context, packet net.PacketConn, spec Exchange) (result Result, runErr error) {
	result = Result{Version: 1, Status: "error", Address: packet.LocalAddr().String(), Observations: []Observation{}, Limitations: []string{"single UDP peer; foreign datagram terminates session; no retransmission/reordering"}}
	defer func() {
		if runErr != nil {
			result.Error = runErr.Error()
		}
	}()
	if err := spec.Validate(); err != nil {
		return result, err
	}
	if spec.Network != "udp" || !spec.Steps[0].Receive || spec.Steps[0].SendPresent || len(spec.Steps[0].Send) > 0 || spec.Steps[0].SendVariable != "" {
		return result, fmt.Errorf("UDP server must start with receive-only step")
	}
	data, _ := json.Marshal(spec)
	sum := sha256.Sum256(data)
	result.ConfigurationSHA256 = hex.EncodeToString(sum[:])
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutMilliseconds)*time.Millisecond)
	defer cancel()
	conn := &udpSession{PacketConn: packet}
	defer conn.Close()
	result, runErr = runConnection(ctx, conn, spec, result)
	if conn.peer != nil {
		result.RemoteAddress = conn.peer.String()
	}
	return result, runErr
}

type udpSession struct {
	net.PacketConn
	peer net.Addr
}

func (c *udpSession) Read(b []byte) (int, error) {
	n, peer, err := c.ReadFrom(b)
	if err != nil {
		return n, err
	}
	if c.peer == nil {
		c.peer = peer
	} else if peer.String() != c.peer.String() {
		return n, fmt.Errorf("foreign UDP peer %s; pinned peer %s", peer, c.peer)
	}
	return n, nil
}
func (c *udpSession) Write(b []byte) (int, error) {
	if c.peer == nil {
		return 0, fmt.Errorf("UDP peer unknown until first datagram")
	}
	return c.WriteTo(b, c.peer)
}
func (c *udpSession) RemoteAddr() net.Addr {
	if c.peer != nil {
		return c.peer
	}
	return &net.UDPAddr{}
}
