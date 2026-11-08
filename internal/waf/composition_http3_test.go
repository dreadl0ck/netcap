//go:build http3

package waf

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/apipolicy"
	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/quic-go/quic-go/http3"
)

func TestRoutedHTTP3CompressedProtobufHooks(t *testing.T) {
	artifact, _ := grpcArtifact(t)
	var messages atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("origin is not HTTP/2")
		}
		wire, _ := io.ReadAll(r.Body)
		if len(wire) == 0 {
			return
		}
		messages.Add(1)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Encoding", "gzip")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(wire)
		w.Header().Set("Grpc-Status", "0")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	fields := map[string]apipolicy.FieldPolicy{"nested.amount": {Required: true, Schema: map[string]any{"type": "integer", "minimum": 1, "maximum": 10}}}
	c := apiConfig(t, config(origin.URL), map[string][]byte{"api.pb": artifact}, apipolicy.Declaration{Descriptors: "api.pb", GRPC: map[string]apipolicy.MethodPolicy{"/api.Service/Exchange": {Request: fields, Response: fields}}})
	c.APIValidateResponse = true
	c.UpstreamCA = filepath.Join(t.TempDir(), "origin.pem")
	if err := os.WriteFile(c.UpstreamCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	f, _, handler := composedFirewall(t, c, compiled(t, "enforce", "request", ""), true)
	if _, err := f.MessageHandler(true, true); err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- firewalltransport.ServeHTTP3(ctx, udp, firewalltransport.HTTP3Config{TLS: origin.TLS, MaxConnections: 4, MaxStreams: 8, IdleTimeout: time.Second, ShutdownTimeout: time.Second}, handler)
	}()
	defer func() { cancel(); <-done; udp.Close() }()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS13}}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, amount := range []byte{5, 99, 7} {
		if amount == 99 {
			if err := f.ReloadRoutePolicies(); err != nil {
				t.Fatal(err)
			}
		}
		var compressed bytes.Buffer
		z := gzip.NewWriter(&compressed)
		_, _ = z.Write([]byte{10, 2, 8, amount})
		_ = z.Close()
		wire := make([]byte, 5)
		wire[0] = 1
		binary.BigEndian.PutUint32(wire[1:], uint32(compressed.Len()))
		wire = append(wire, compressed.Bytes()...)
		before := messages.Load()
		req, _ := http.NewRequest("POST", "https://"+udp.LocalAddr().String()+"/api.Service/Exchange", bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("Grpc-Encoding", "gzip")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if amount == 99 {
			if bytes.Contains(body, compressed.Bytes()) || messages.Load() != before || (resp.StatusCode < 400 && resp.Trailer.Get("Grpc-Status") == "0") {
				t.Fatalf("invalid nested protobuf escaped compressed H3 gate: %x", body)
			}
		} else if !bytes.Equal(body, wire) || resp.ProtoMajor != 3 || resp.Trailer.Get("Grpc-Status") != "0" || messages.Load() != before+1 {
			t.Fatalf("valid compressed protobuf failed: body=%x status=%d trailers=%v", body, resp.StatusCode, resp.Trailer)
		}
	}
}
