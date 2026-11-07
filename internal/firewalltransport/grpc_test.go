package firewalltransport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func grpcFrame(body string, compress bool) []byte {
	data := []byte(body)
	if compress {
		var buf bytes.Buffer
		z := gzip.NewWriter(&buf)
		_, _ = z.Write(data)
		_ = z.Close()
		data = buf.Bytes()
	}
	wire := make([]byte, 5+len(data))
	if compress {
		wire[0] = 1
	}
	binary.BigEndian.PutUint32(wire[1:], uint32(len(data)))
	copy(wire[5:], data)
	return wire
}

func TestGRPCGateRejectsBeforeHeaderAndBoundsExpansion(t *testing.T) {
	truncated := grpcFrame("safe", true)
	truncated = truncated[:len(truncated)-4]
	binary.BigEndian.PutUint32(truncated[1:], uint32(len(truncated)-5))
	badChecksum := grpcFrame("safe", true)
	badChecksum[len(badChecksum)-8] ^= 1
	for name, wire := range map[string][]byte{
		"gzip-truncated": truncated,
		"gzip-checksum":  badChecksum,
		"denied":         grpcFrame("secret", false),
		"gzip-denied":    grpcFrame("secret", true),
		"gzip-bomb":      grpcFrame(strings.Repeat("a", MaxMessageBytes+1), true),
		"bad-flag":       {2, 0, 0, 0, 0},
		"oversized":      {0, 0, 16, 0, 1},
		"short":          {0, 0, 0, 0, 2, 'x'},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g := &grpcReader{ReadCloser: io.NopCloser(bytes.NewReader(wire)), ctx: ctx, cancel: cancel, timeout: time.Second, encoding: "gzip", inspect: func(data []byte, _ bool, _ uint64) error {
				if string(data) == "secret" {
					return ErrDenied
				}
				return nil
			}}
			data, err := io.ReadAll(g)
			if err == nil || len(data) != 0 {
				t.Fatalf("invalid message released header/body: %x %v", data, err)
			}
		})
	}
}

func TestGRPCMessageTimeoutUnblocksPartialFrame(t *testing.T) {
	for _, wire := range [][]byte{{0}, {0, 0, 0, 0, 5, 'x'}} {
		ctx, cancel := context.WithCancel(context.Background())
		r, w := io.Pipe()
		g := &grpcReader{ReadCloser: r, ctx: ctx, cancel: cancel, timeout: 20 * time.Millisecond, inspect: func([]byte, bool, uint64) error { return nil }}
		done := make(chan error, 1)
		go func() { _, err := io.Copy(io.Discard, g); done <- err }()
		_, _ = w.Write(wire)
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("timeout allowed partial message")
			}
		case <-time.After(time.Second):
			t.Fatal("message reader leaked")
		}
		cancel()
		_ = w.Close()
		_ = r.Close()
	}
}

func TestGRPCRealHTTP2DuplexAndTrailers(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("upstream not HTTP/2")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, X-Finish")
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		for {
			var head [5]byte
			_, err := io.ReadFull(r.Body, head[:])
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			data := make([]byte, binary.BigEndian.Uint32(head[1:]))
			if _, err := io.ReadFull(r.Body, data); err != nil {
				return
			}
			_, _ = w.Write(grpcFrame("echo:"+string(data), false))
			_ = http.NewResponseController(w).Flush()
		}
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("X-Finish", "complete")
		if r.Trailer.Get("X-Request-Finish") != "done" {
			t.Errorf("request trailers lost: %+v", r.Trailer)
		}
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	var mu sync.Mutex
	var seen []Event
	h := newHandler(t, origin.URL, false, true, func(_ context.Context, e Event) error { mu.Lock(); seen = append(seen, e); mu.Unlock(); return nil })
	h.cfg.Transport = origin.Client().Transport
	proxy := httptest.NewUnstartedServer(h)
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	reader, writer := io.Pipe()
	req, _ := http.NewRequest("POST", proxy.URL+"/demo.Service/Chat?q=x", reader)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("X-Metadata", "preserved")
	req.Trailer = http.Header{"X-Request-Finish": nil}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	responses := make(chan *http.Response, 1)
	errs := make(chan error, 1)
	go func() {
		resp, err := proxy.Client().Do(req)
		if err != nil {
			errs <- err
			return
		}
		responses <- resp
	}()
	if _, err := writer.Write(grpcFrame("first", false)); err != nil {
		t.Fatal(err)
	}
	var resp *http.Response
	select {
	case resp = <-responses:
	case err := <-errs:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("full request buffering stalled duplex")
	}
	defer resp.Body.Close()
	want := grpcFrame("echo:first", false)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(resp.Body, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("first response before EOF: %x %v status=%d", got, err, resp.StatusCode)
	}
	if _, err := writer.Write(grpcFrame("second", false)); err != nil {
		t.Fatal(err)
	}
	req.Trailer.Set("X-Request-Finish", "done")
	_ = writer.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(data, grpcFrame("echo:second", false)) {
		t.Fatalf("second message: %x %v", data, err)
	}
	if resp.Trailer.Get("Grpc-Status") != "0" || resp.Trailer.Get("X-Finish") != "complete" {
		t.Fatalf("trailers lost: %+v", resp.Trailer)
	}
	mu.Lock()
	defer mu.Unlock()
	requests, responsesCount := 0, 0
	for _, e := range seen {
		if e.Method != "POST" || e.Path != "/demo.Service/Chat" || e.Protocol != "grpc" {
			t.Errorf("event identity lost: %+v", e)
		}
		if e.Attributes["message.index"] != "" {
			if e.Phase == "request" {
				requests++
				if e.Headers.Get("X-Metadata") != "preserved" {
					t.Error("request metadata lost")
				}
			} else {
				responsesCount++
			}
		}
	}
	if requests != 2 || responsesCount != 2 {
		t.Fatalf("messages were coalesced or missed: req=%d resp=%d", requests, responsesCount)
	}
}

func TestGRPCRealHTTP2DeniedResponseAndStreamIsolation(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Encoding", "gzip")
		_, _ = w.Write(grpcFrame("safe", false))
		_ = http.NewResponseController(w).Flush()
		if r.URL.Path == "/deny" {
			_, _ = w.Write(grpcFrame("secret", true))
		}
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	h := newHandler(t, origin.URL, false, true, func(_ context.Context, e Event) error {
		if e.Body == "secret" {
			return ErrDenied
		}
		return nil
	})
	h.cfg.Transport = origin.Client().Transport
	proxy := httptest.NewUnstartedServer(h)
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/allow"
			if i%2 == 0 {
				path = "/deny"
			}
			req, _ := http.NewRequest("POST", proxy.URL+path, bytes.NewReader(grpcFrame("request", false)))
			req.Header.Set("Content-Type", "application/grpc")
			resp, err := proxy.Client().Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(data, grpcFrame("safe", false)) {
				t.Errorf("stream %s: leaked/changed frames: %x %v", path, data, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestModesDefaultDisabled(t *testing.T) {
	h, err := New(Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) }), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://example/rpc", nil)
	r.Header.Set("Content-Type", "application/grpc")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 418 {
		t.Fatalf("implicit stream mode: %d", w.Code)
	}
}

func TestGRPCRealHTTP2DeniedRequestDoesNotReleaseHeader(t *testing.T) {
	afterFirst := make(chan []byte, 1)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first := make([]byte, len(grpcFrame("safe", false)))
		if _, err := io.ReadFull(r.Body, first); err != nil {
			t.Error(err)
			afterFirst <- nil
			return
		}
		if !bytes.Equal(first, grpcFrame("safe", false)) {
			t.Errorf("first message changed: %x", first)
		}
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = w.Write(grpcFrame("ack", false))
		_ = http.NewResponseController(w).Flush()
		rest, _ := io.ReadAll(r.Body)
		afterFirst <- rest
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	h := newHandler(t, origin.URL, false, true, func(_ context.Context, e Event) error {
		if e.Phase == "request" && e.Body == "secret" {
			return ErrDenied
		}
		return nil
	})
	h.cfg.Transport = origin.Client().Transport
	proxy := httptest.NewUnstartedServer(h)
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", proxy.URL+"/chat", reader)
	req.Header.Set("Content-Type", "application/grpc")
	response := make(chan *http.Response, 1)
	errs := make(chan error, 1)
	go func() {
		resp, err := proxy.Client().Do(req)
		if err != nil {
			errs <- err
			return
		}
		response <- resp
	}()
	_, _ = writer.Write(grpcFrame("safe", false))
	var resp *http.Response
	select {
	case resp = <-response:
	case err := <-errs:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer resp.Body.Close()
	ack := make([]byte, len(grpcFrame("ack", false)))
	if _, err := io.ReadFull(resp.Body, ack); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(grpcFrame("secret", false))
	select {
	case rest := <-afterFirst:
		if len(rest) != 0 {
			t.Fatalf("denied frame/header reached origin: %x", rest)
		}
	case <-ctx.Done():
		t.Fatal("denied RPC did not cancel origin")
	}
}
