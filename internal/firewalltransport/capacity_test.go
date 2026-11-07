package firewalltransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestWebSocketGrowthChargesOldAndNewBackingArrays(t *testing.T) {
	for _, limit := range []int64{24, 25} {
		budget, _ := NewBufferBudget(limit)
		old := bytes.Repeat([]byte{'x'}, 8)
		if !budget.Acquire(int64(cap(old)) + 1) {
			t.Fatal("fixture quota")
		}
		grown, err := appendWSMessage(old, []byte{'y'}, budget)
		if limit == 24 {
			if !errors.Is(err, ErrBufferCapacity) || &grown[0] != &old[0] || budget.Used() != 9 {
				t.Fatalf("growth did not retain old reservation on refusal: cap=%d used=%d error=%v", cap(grown), budget.Used(), err)
			}
		} else {
			if err != nil || cap(grown) != 16 || &grown[0] == &old[0] || string(grown) != "xxxxxxxxy" || budget.Used() != 17 {
				t.Fatalf("growth capacity/copy accounting: cap=%d data=%q used=%d error=%v", cap(grown), grown, budget.Used(), err)
			}
		}
		budget.Release(int64(cap(grown)) + 1)
		if budget.Used() != 0 {
			t.Fatalf("growth quota leaked: %d", budget.Used())
		}
	}
}

func fragmentWire(count, payloadSize int) []byte {
	var wire bytes.Buffer
	for i := 0; i < count; i++ {
		op := byte(0)
		if i == 0 {
			op = 2
		}
		if i == count-1 {
			op |= 128
		}
		wire.Write([]byte{op, byte(payloadSize)})
		if payloadSize > 0 {
			wire.WriteByte('x')
		}
	}
	return wire.Bytes()
}

func TestWebSocketFragmentBackingCapacityBudget(t *testing.T) {
	for _, limit := range []int64{1024, 2048} {
		budget, _ := NewBufferBudget(limit)
		var forwarded bytes.Buffer
		inspections := 0
		err := gateWebSocketBudget(context.Background(), bytes.NewReader(fragmentWire(1000, 1)), &forwarded, false, time.Second, func() {}, func(data []byte, _ byte, _ uint64) error {
			inspections++
			if len(data) != 1000 || cap(data) != 1024 || budget.Used() != int64(cap(data))+1 || budget.Used() > limit {
				t.Errorf("retained capacity undercharged: len=%d cap=%d used=%d limit=%d", len(data), cap(data), budget.Used(), limit)
			}
			return nil
		}, budget)
		if limit == 1024 {
			if !errors.Is(err, ErrBufferCapacity) || inspections != 0 || forwarded.Len() != 0 {
				t.Fatalf("insufficient copy-peak quota leaked a frame: error=%v inspections=%d bytes=%d", err, inspections, forwarded.Len())
			}
		} else {
			if err != io.EOF || inspections != 1 {
				t.Fatalf("bounded fragmented message rejected: error=%v inspections=%d", err, inspections)
			}
			frame, readErr := readWSFrame(&forwarded, false)
			if readErr != nil || frame.opcode != 2 || len(frame.payload) != 1000 {
				t.Fatalf("reassembled frame: %+v %v", frame, readErr)
			}
		}
		if budget.Used() != 0 {
			t.Fatalf("fragment quota leaked: %d", budget.Used())
		}
	}
}

func TestWebSocketFragmentCountLimitReleasesResources(t *testing.T) {
	for _, payloadSize := range []int{0, 1} {
		for _, count := range []int{1024, 1025} {
			budget, _ := NewBufferBudget(4096)
			var forwarded bytes.Buffer
			inspections := 0
			err := gateWebSocketBudget(context.Background(), bytes.NewReader(fragmentWire(count, payloadSize)), &forwarded, false, time.Second, func() {}, func([]byte, byte, uint64) error { inspections++; return nil }, budget)
			if count == 1024 {
				if err != io.EOF || inspections != 1 || forwarded.Len() == 0 {
					t.Fatalf("valid fragment boundary rejected: payload=%d error=%v inspections=%d", payloadSize, err, inspections)
				}
			} else if !errors.Is(err, ErrFraming) || forwarded.Len() != 0 || inspections != 0 {
				t.Fatalf("fragment-count bound: payload=%d error=%v bytes=%d inspections=%d", payloadSize, err, forwarded.Len(), inspections)
			}
			if budget.Used() != 0 {
				t.Fatalf("fragment-count quota leaked: %d", budget.Used())
			}
		}
	}
}

type capacityWriter struct {
	calls  int
	budget *BufferBudget
	t      *testing.T
}

func (w *capacityWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 2 && (cap(p) != 1000 || w.budget.Used() != 1000) {
		w.t.Errorf("mask copy backing array undercharged: len=%d cap=%d used=%d", len(p), cap(p), w.budget.Used())
	}
	return len(p), nil
}

func TestWebSocketMaskCopyHasChargedExactCapacity(t *testing.T) {
	budget, _ := NewBufferBudget(1000)
	w := &capacityWriter{budget: budget, t: t}
	if err := writeWSFrameBudget(w, 2, bytes.Repeat([]byte{'x'}, 1000), true, budget); err != nil {
		t.Fatal(err)
	}
	if w.calls != 2 || budget.Used() != 0 {
		t.Fatalf("mask copy quota leaked: calls=%d used=%d", w.calls, budget.Used())
	}
}

func TestGRPCGzipBackingCapacityBudget(t *testing.T) {
	wire := grpcFrame(string(bytes.Repeat([]byte{'x'}, MaxMessageBytes)), true)
	budget, _ := NewBufferBudget(int64(len(wire) + MaxMessageBytes + 1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inspections := 0
	g := &grpcReader{ReadCloser: io.NopCloser(bytes.NewReader(wire)), ctx: ctx, cancel: cancel, timeout: time.Second, encoding: "gzip", budget: budget, inspect: func(data []byte, _ bool, _ uint64) error {
		inspections++
		if len(data) != MaxMessageBytes || cap(data) != MaxMessageBytes+1 || budget.Used() != int64(cap(data)+len(wire)) {
			t.Errorf("expanded backing array undercharged: len=%d cap=%d used=%d wire=%d", len(data), cap(data), budget.Used(), len(wire))
		}
		return nil
	}}
	_, err := io.Copy(io.Discard, g)
	_ = g.Close()
	if err != nil || inspections != 1 || budget.Used() != 0 {
		t.Fatalf("expanded quota lifetime: error=%v inspections=%d used=%d", err, inspections, budget.Used())
	}
}
