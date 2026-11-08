package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func amendRuntime(t *testing.T, path string, fields map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		cfg[k] = v
	}
	jsonFile(t, path, cfg)
}

func grpcFrame(body string) []byte {
	b := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(b[1:], uint32(len(body)))
	copy(b[5:], body)
	return b
}

func TestShippingGRPCMessageGate(t *testing.T) {
	var received atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		received.Add(int64(len(data)))
		w.Header().Set("Content-Type", "application/grpc")
		w.Write(grpcFrame("ok"))
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	admin := freeAddress(t, "tcp")
	cfg, url := runtimeConfig(t, origin.URL, admin)
	cert, key := testCertificate(t)
	ca := filepath.Join(filepath.Dir(cfg), "upstream.pem")
	writeFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})))
	amendRuntime(t, cfg, map[string]any{"tlsCert": cert, "tlsKey": key, "upstreamCA": ca})
	writeFile(t, filepath.Join(filepath.Dir(cfg), "policy.json"), bundle("grpc-cli", `Protocol == 'grpc' && Attributes["inspection.kind"] == 'message' && Body contains 'secret'`))
	p := startCLI(t, "", "serve", "--config", cfg, "--grpc")
	waitReady(t, p, httpClient(t), "http://"+admin+"/readyz")
	pool := x509.NewCertPool()
	raw, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(raw)
	tr := &http2.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	url = strings.Replace(url, "http://", "https://", 1)
	for _, body := range []string{"safe", "secret"} {
		r, err := http.NewRequest("POST", url+"/service/chat", bytes.NewReader(grpcFrame(body)))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/grpc")
		res, err := c.Do(r)
		if err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
		if body == "safe" && (err != nil || res.StatusCode != 200) {
			t.Fatalf("safe gRPC failed: %v", err)
		}
	}
	if got := received.Load(); got != int64(len(grpcFrame("safe"))) {
		t.Fatalf("gRPC denied body reached origin: %d", got)
	}
	p.stop(t)
}

func maskedFrame(body string) []byte {
	b := []byte{0x81, 0x80 | byte(len(body)), 1, 2, 3, 4}
	for i, v := range []byte(body) {
		b = append(b, v^byte(1+i%4))
	}
	return b
}

func readWSFrame(r *bufio.Reader) (byte, string, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, "", err
	}
	n := int(header[1] & 127)
	if n > 125 {
		return 0, "", fmt.Errorf("unexpected long test frame")
	}
	var mask [4]byte
	if header[1]&128 != 0 {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, "", err
		}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, "", err
	}
	if header[1]&128 != 0 {
		for i := range body {
			body[i] ^= mask[i%4]
		}
	}
	return header[0] & 15, string(body), nil
}

func TestShippingWebSocketMessageGate(t *testing.T) {
	messages := make(chan string, 8)
	originDone := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		defer close(originDone)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		hash := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(hash[:]))
		rw.Flush()
		for {
			op, body, err := readWSFrame(rw.Reader)
			if err != nil || op == 8 {
				return
			}
			messages <- body
		}
	}))
	defer origin.Close()
	admin := freeAddress(t, "tcp")
	cfg, url := runtimeConfig(t, origin.URL, admin)
	writeFile(t, filepath.Join(filepath.Dir(cfg), "policy.json"), bundle("ws-cli", `Protocol == 'websocket' && Body contains 'secret'`))
	p := startCLI(t, "", "serve", "--config", cfg, "--websocket")
	waitReady(t, p, httpClient(t), "http://"+admin+"/readyz")
	c, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n")
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, &http.Request{Method: "GET"})
	if err != nil || response.StatusCode != 101 {
		t.Fatalf("WebSocket handshake: %v %+v", err, response)
	}
	c.Write(maskedFrame("safe"))
	select {
	case body := <-messages:
		if body != "safe" {
			t.Fatalf("origin message %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("safe WebSocket message not forwarded")
	}
	c.Write(maskedFrame("secret"))
	for {
		op, _, err := readWSFrame(r)
		if err != nil || op == 8 {
			break
		}
	}
	c.Close()
	p.stop(t)
	select {
	case <-originDone:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket origin did not close")
	}
	select {
	case body := <-messages:
		t.Fatalf("denied WebSocket message reached origin: %q", body)
	default:
	}
}
