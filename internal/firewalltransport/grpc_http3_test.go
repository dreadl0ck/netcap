//go:build http3

package firewalltransport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3MessageProfileRealQUICDuplexTrailersAndDenial(t *testing.T) {
	for _, mode := range []string{"duplex", "gzip", "stream-limit", "request-denied", "response-denied", "trailer-denied", "response-trailer-denied", "partial-cancel"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var originWire []byte
			var originCalls atomic.Int32
			originTrailers := make(chan http.Header, 1)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originCalls.Add(1)
				if r.ProtoMajor != 2 {
					t.Error("origin must use HTTP/2")
				}
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status, X-Final")
				w.WriteHeader(200)
				http.NewResponseController(w).Flush()
				for i := 0; ; i++ {
					var head [5]byte
					n, e := io.ReadFull(r.Body, head[:])
					mu.Lock()
					originWire = append(originWire, head[:n]...)
					mu.Unlock()
					if e != nil {
						originTrailers <- r.Trailer.Clone()
						break
					}
					body := make([]byte, int(binary.BigEndian.Uint32(head[1:])))
					if _, e = io.ReadFull(r.Body, body); e != nil {
						return
					}
					mu.Lock()
					originWire = append(originWire, body...)
					mu.Unlock()
					out := string(body)
					if head[0] == 1 {
						z, err := gzip.NewReader(bytes.NewReader(body))
						if err != nil {
							t.Error(err)
							return
						}
						decoded, err := io.ReadAll(z)
						z.Close()
						if err != nil {
							t.Error(err)
							return
						}
						out = string(decoded)
					}
					if mode == "response-denied" && i == 1 {
						out = "forbidden-response"
					}
					w.Write(grpcFrame(out, false))
					http.NewResponseController(w).Flush()
				}
				w.Header().Set("Grpc-Status", "0")
				w.Header().Set("X-Final", "complete")
				if mode == "response-trailer-denied" {
					w.Header().Set("X-Final", "forbidden-trailer")
				}
			}))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			defer origin.Close()
			h := newHandler(t, origin.URL, false, true, func(_ context.Context, e Event) error {
				if strings.Contains(e.Body, "forbidden") || e.Headers.Get("X-Client") == "forbidden-trailer" || e.Headers.Get("X-Final") == "forbidden-trailer" {
					return ErrDenied
				}
				return nil
			})
			h.cfg.Transport = origin.Client().Transport
			h.cfg.HTTP3MessageProfile = true
			udp, e := net.ListenPacket("udp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				streams := int64(8)
				if mode == "stream-limit" {
					streams = 1
				}
				done <- ServeHTTP3(ctx, udp, HTTP3Config{TLS: origin.TLS, MaxConnections: 4, MaxStreams: streams, IdleTimeout: 3 * time.Second, ShutdownTimeout: time.Second}, h)
			}()
			t.Cleanup(func() {
				defer udp.Close()
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(3 * time.Second):
					t.Error("HTTP/3 did not cancel/drain")
				}
			})
			pool := x509.NewCertPool()
			pool.AddCert(origin.Certificate())
			tr := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}
			defer tr.Close()
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			req, e := http.NewRequestWithContext(ctx, "POST", "https://"+udp.LocalAddr().String()+"/service/stream", pr)
			if e != nil {
				t.Fatal(e)
			}
			req.Header.Set("Content-Type", "application/grpc")
			if mode == "gzip" {
				req.Header.Set("Grpc-Encoding", "gzip")
			}
			req.Trailer = http.Header{"X-Client": []string{"final-client"}}
			if mode == "trailer-denied" {
				req.Trailer.Set("X-Client", "forbidden-trailer")
			}
			result := make(chan *http.Response, 1)
			errch := make(chan error, 1)
			go func() {
				resp, err := client.Do(req)
				if err != nil {
					errch <- err
					return
				}
				result <- resp
			}()
			if _, e = pw.Write(grpcFrame("safe-first", mode == "gzip")); e != nil {
				t.Fatal(e)
			}
			var resp *http.Response
			select {
			case resp = <-result:
			case e := <-errch:
				t.Fatal(e)
			case <-time.After(4 * time.Second):
				t.Fatal("duplex response waited for request EOF")
			}
			defer resp.Body.Close()
			if resp.ProtoMajor != 3 || resp.StatusCode != 200 {
				t.Fatalf("not HTTP/3: %+v", resp)
			}
			first := make([]byte, len(grpcFrame("safe-first", false)))
			if _, e = io.ReadFull(resp.Body, first); e != nil || !bytes.Equal(first, grpcFrame("safe-first", false)) {
				t.Fatalf("first duplex message %x %v", first, e)
			}
			if mode == "stream-limit" {
				limited, stop := context.WithTimeout(ctx, 200*time.Millisecond)
				probe, err := http.NewRequestWithContext(limited, "POST", req.URL.String(), bytes.NewReader(grpcFrame("must-not-arrive", false)))
				if err != nil {
					t.Fatal(err)
				}
				probe.Header.Set("Content-Type", "application/grpc")
				second, err := client.Do(probe)
				stop()
				if err == nil {
					second.Body.Close()
					t.Fatal("QUIC stream limit did not block concurrent request")
				}
				if originCalls.Load() != 1 {
					t.Fatal("over-limit stream reached origin")
				}
			}
			second := "safe-second"
			if mode == "request-denied" {
				second = "forbidden-request"
			}
			wire := grpcFrame(second, mode == "gzip")
			if mode == "partial-cancel" {
				wire = wire[:3]
			}
			if _, e = pw.Write(wire); e != nil {
				t.Fatal(e)
			}
			if mode == "partial-cancel" {
				cancel()
			}
			pw.Close()
			rest, e := io.ReadAll(resp.Body)
			if mode == "duplex" || mode == "gzip" || mode == "stream-limit" {
				if e != nil || !bytes.Equal(rest, grpcFrame(second, false)) || resp.Trailer.Get("Grpc-Status") != "0" || resp.Trailer.Get("X-Final") != "complete" {
					t.Fatalf("duplex trailers/body: %x %v %v", rest, e, resp.Trailer)
				}
			} else if bytes.Contains(rest, []byte("forbidden")) || resp.Trailer.Get("Grpc-Status") == "0" {
				t.Fatalf("denied stream released payload/success: %x %v %v", rest, e, resp.Trailer)
			}
			select {
			case trailers := <-originTrailers:
				if (mode == "duplex" || mode == "gzip" || mode == "stream-limit") && trailers.Get("X-Client") != "final-client" {
					t.Fatalf("request trailers lost: %v", trailers)
				}
				if mode == "trailer-denied" && trailers.Get("X-Client") == "forbidden-trailer" {
					t.Fatal("denied request trailer forwarded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("origin request did not end")
			}
			if mode == "stream-limit" {
				recovered, err := client.Post(req.URL.String(), "application/grpc", bytes.NewReader(grpcFrame("safe-recovery", false)))
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(recovered.Body)
				recovered.Body.Close()
				if err != nil || !bytes.Equal(b, grpcFrame("safe-recovery", false)) || recovered.Trailer.Get("Grpc-Status") != "0" || originCalls.Load() != 2 {
					t.Fatalf("stream capacity failed recovery: %x %v trailers=%v calls=%d", b, err, recovered.Trailer, originCalls.Load())
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if (mode == "request-denied" || mode == "partial-cancel") && !bytes.Equal(originWire, grpcFrame("safe-first", false)) {
				t.Fatalf("denied frame/header leaked to origin: %x", originWire)
			}
		})
	}
}
