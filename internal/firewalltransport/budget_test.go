package firewalltransport

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestBufferBudgetConcurrentReservations(t *testing.T) {
	b, _ := NewBufferBudget(64 << 10)
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if b.Acquire(1024) {
					if used := b.Used(); used > b.Limit() {
						t.Errorf("quota exceeded: %d", used)
					}
					b.Release(1024)
				}
			}
		}()
	}
	wg.Wait()
	if b.Used() != 0 {
		t.Fatalf("reservation leaked: %d", b.Used())
	}
}

func TestMessageBudgetRejectsBeforeFrameHeaderAndReleases(t *testing.T) {
	for _, protocol := range []string{"grpc", "websocket"} {
		t.Run(protocol, func(t *testing.T) {
			b, _ := NewBufferBudget(64)
			var got bytes.Buffer
			if protocol == "grpc" {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				g := &grpcReader{ReadCloser: io.NopCloser(bytes.NewReader(grpcFrame(string(bytes.Repeat([]byte{'a'}, 100)), false))), ctx: ctx, cancel: cancel, timeout: time.Second, budget: b, inspect: func([]byte, bool, uint64) error { return nil }}
				_, err := io.Copy(&got, g)
				_ = g.Close()
				if err == nil {
					t.Fatal("message exceeded quota")
				}
			} else {
				var wire bytes.Buffer
				_ = writeWSFrame(&wire, 1, bytes.Repeat([]byte{'a'}, 100), true)
				err := gateWebSocketBudget(context.Background(), &wire, &got, true, time.Second, func() {}, func([]byte, byte, uint64) error { return nil }, b)
				if err == nil {
					t.Fatal("message exceeded quota")
				}
			}
			if got.Len() != 0 || b.Used() != 0 {
				t.Fatalf("quota reject leaked frame/resources: output=%x used=%d", got.Bytes(), b.Used())
			}
		})
	}
}

func TestGRPCPendingMessageQuotaReleasedOnConcurrentClose(t *testing.T) {
	b, _ := NewBufferBudget(128)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := &grpcReader{ReadCloser: io.NopCloser(bytes.NewReader(grpcFrame("safe", false))), ctx: ctx, cancel: cancel, timeout: time.Second, budget: b, inspect: func([]byte, bool, uint64) error { return nil }}
	var one [1]byte
	if _, err := g.Read(one[:]); err != nil {
		t.Fatal(err)
	}
	if b.Used() != 9 {
		t.Fatalf("pending frame uncharged: %d", b.Used())
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = g.Close() }()
	}
	wg.Wait()
	if b.Used() != 0 {
		t.Fatalf("closed frame retained quota: %d", b.Used())
	}
}

func TestByteEventsBorrowPayloadWithoutBodyString(t *testing.T) {
	h := &Handler{cfg: Config{ByteEvents: true}}
	data := bytes.Repeat([]byte{'a'}, MaxMessageBytes)
	e := h.messageEvent(httptest.NewRequest("POST", "https://example/service/method", nil), "grpc", "request", data, 0)
	if e.Body != "" || len(e.Payload) != len(data) || &e.Payload[0] != &data[0] {
		t.Fatal("byte event copied or discarded payload")
	}
}

func TestGRPCTrailerHookRunsOnceAtEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	g := &grpcReader{ReadCloser: io.NopCloser(bytes.NewReader(nil)), ctx: ctx, cancel: cancel, timeout: time.Second, onEOF: func() error { calls++; return nil }}
	var buf [1]byte
	for i := 0; i < 4; i++ {
		if _, err := g.Read(buf[:]); err != io.EOF {
			t.Fatalf("repeated EOF: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("trailer quota counted more than once: %d", calls)
	}
}
