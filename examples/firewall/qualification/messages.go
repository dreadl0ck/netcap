//go:build coraza && http3

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/waf"
)

func grpcPacket(body string) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint32(b[1:], uint32(len(body)))
	return append(b, []byte(body)...)
}

func newMessageProfile(ctx context.Context, protocol string) (*profile, error) {
	p := &profile{Name: protocol + "-scripted-v1", Ledger: &ledger{}, Fixture: map[string]string{"websocket": "RFC6455 uncompressed masked text request and echo", "grpc": "gRPC identity framing over TLS H2, scripted unary service"}[protocol]}
	directory, err := os.MkdirTemp("", "netcap-owned-message-")
	if err != nil {
		return nil, err
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if protocol == "grpc" {
			b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			p.Ledger.recordWire(b, bytes.Contains(b, []byte(forbidden)))
			if err != nil || len(b) > 65536 || r.ProtoMajor != 2 {
				http.Error(w, "fixture", 400)
				return
			}
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			_, _ = w.Write(grpcPacket("safe"))
			w.Header().Set("Grpc-Status", "0")
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		if rw.Flush() != nil {
			return
		}
		b, err := wsRead(rw.Reader, true)
		if err != nil {
			return
		}
		p.Ledger.recordWire(b, bytes.Contains(b, []byte(forbidden)))
		_, _ = c.Write(append([]byte{129, byte(len(b))}, b...))
	}))
	if protocol == "grpc" {
		origin.EnableHTTP2 = true
		origin.StartTLS()
	} else {
		origin.Start()
	}
	cfg := waf.Config{Version: "netcap-firewall/v1", Listen: "127.0.0.1:8080", AdminListen: "127.0.0.1:9090", Upstream: origin.URL, MaxBodyBytes: 65536, MaxResponseBytes: 65536, MaxBufferedBytes: 8 << 20, MaxConcurrent: 32, BodyTimeout: "2s"}
	if protocol == "grpc" {
		cfg.UpstreamCA = filepath.Join(directory, "origin-ca.pem")
		if err = os.WriteFile(cfg.UpstreamCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
			origin.Close()
			_ = os.RemoveAll(directory)
			return nil, err
		}
	}
	compiled, err := compile(0, 0)
	if err != nil {
		origin.Close()
		_ = os.RemoveAll(directory)
		return nil, err
	}
	p.FW, err = waf.New(cfg, compiled)
	if err != nil {
		origin.Close()
		_ = os.RemoveAll(directory)
		return nil, err
	}
	h, err := p.FW.MessageHandler(protocol == "websocket", protocol == "grpc")
	if err != nil {
		_ = p.FW.Close()
		origin.Close()
		_ = os.RemoveAll(directory)
		return nil, err
	}
	proxy := httptest.NewUnstartedServer(h)
	if protocol == "grpc" {
		proxy.EnableHTTP2 = true
		proxy.StartTLS()
	} else {
		proxy.Start()
	}
	p.Close = func() { proxy.Close(); _ = p.FW.Close(); origin.Close(); _ = os.RemoveAll(directory) }
	client := proxy.Client()
	client.Timeout = 3 * time.Second
	p.CustomRequest = func(w workflow) (int, int, error) {
		attack := strings.Contains(w.Body, forbidden)
		body := "safe"
		if attack {
			body = forbidden
		}
		if protocol == "grpc" {
			req, err := http.NewRequestWithContext(ctx, "POST", proxy.URL+"/qualification.Invoice/Submit", bytes.NewReader(grpcPacket(body)))
			if err != nil {
				return 0, 0, err
			}
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("TE", "trailers")
			resp, err := client.Do(req)
			if err != nil {
				return 0, 0, err
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
			if err != nil {
				return 0, 0, err
			}
			if resp.ProtoMajor != 2 {
				return 0, 0, errors.New("gRPC did not negotiate H2")
			}
			if attack {
				if resp.StatusCode != 200 || !bytes.Equal(b, grpcPacket("safe")) {
					return 403, 2, nil
				}
				return 0, 2, errors.New("gRPC attack returned allowed response")
			}
			if resp.StatusCode != 200 || !bytes.Equal(b, grpcPacket("safe")) || resp.Trailer.Get("Grpc-Status") != "0" {
				return 0, 2, fmt.Errorf("gRPC response/trailer mismatch: %d %x %v", resp.StatusCode, b, resp.Trailer)
			}
			return 200, 2, nil
		}
		c, err := net.DialTimeout("tcp", strings.TrimPrefix(proxy.URL, "http://"), time.Second)
		if err != nil {
			return 0, 0, wireStage("ws-dial", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = io.WriteString(c, "GET /chat HTTP/1.1\r\nHost: fixture.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
		if err != nil {
			return 0, 0, wireStage("ws-handshake-write", err)
		}
		r := bufio.NewReader(c)
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			return 0, 0, wireStage("ws-handshake-read", err)
		}
		if resp.StatusCode != 101 {
			_ = resp.Body.Close()
			return resp.StatusCode, 0, &wireError{Stage: "ws-upgrade", Category: "unexpected-status"}
		}
		frame := append([]byte{129, 128 | byte(len(body)), 0, 0, 0, 0}, []byte(body)...)
		if _, err = c.Write(frame); err != nil {
			return 0, 0, wireStage("ws-frame-write", err)
		}
		b, err := wsRead(r, false)
		if attack {
			if wsDeniedCleanly(err) {
				return 403, 1, nil
			}
			if err != nil {
				return 0, 1, err
			}
			return 0, 1, &wireError{Stage: "ws-denial", Category: "unexpected-frame", Read: len(b)}
		}
		if err != nil {
			return 0, 1, err
		}
		if string(b) != body {
			return 0, 1, &wireError{Stage: "ws-echo", Category: "payload-mismatch", Read: len(b), Want: len(body)}
		}
		return 200, 1, nil
	}
	return p, nil
}

func wsDeniedCleanly(err error) bool {
	var wire *wireError
	return errors.As(err, &wire) && wire.Stage == "ws-frame-header" && wire.Read == 0 && errors.Is(err, io.EOF)
}

func wsRead(r *bufio.Reader, masked bool) ([]byte, error) {
	h := make([]byte, 2)
	if n, err := io.ReadFull(r, h); err != nil {
		return nil, &wireError{Stage: "ws-frame-header", Category: errorCategory(err), Header: fmt.Sprintf("%x", h[:n]), Read: n, Want: 2, Cause: err}
	}
	if h[0] != 129 || h[1]&127 > 125 || (h[1]&128 != 0) != masked {
		return nil, &wireError{Stage: "ws-frame-header", Category: "invalid-frame", Header: fmt.Sprintf("%x", h), Read: 2, Want: 2}
	}
	var mask [4]byte
	if masked {
		if n, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, &wireError{Stage: "ws-frame-mask", Category: errorCategory(err), Read: n, Want: 4, Cause: err}
		}
	}
	b := make([]byte, int(h[1]&127))
	if n, err := io.ReadFull(r, b); err != nil {
		return nil, &wireError{Stage: "ws-frame-body", Category: errorCategory(err), Read: n, Want: len(b), Cause: err}
	}
	if masked {
		for i := range b {
			b[i] ^= mask[i%4]
		}
	}
	return b, nil
}
