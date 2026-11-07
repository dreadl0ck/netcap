package networkfirewall

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

type evaluatorFunc func(PacketEvent) (Decision, error)

func (e evaluatorFunc) EvaluatePacket(p PacketEvent) (Decision, error) { return e(p) }

func packet(v6 bool, port uint16) []byte {
	off := 20
	if v6 {
		off = 40
	}
	b := make([]byte, off+20)
	if v6 {
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:6], 20)
		b[6] = 6
		b[7] = 64
		b[8] = 0xfd
		b[23] = 2
		b[24] = 0xfd
		b[39] = 3
	} else {
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], 40)
		b[8] = 64
		b[9] = 6
		copy(b[12:16], []byte{10, 80, 0, 2})
		copy(b[16:20], []byte{10, 81, 0, 2})
	}
	binary.BigEndian.PutUint16(b[off:off+2], 12345)
	binary.BigEndian.PutUint16(b[off+2:off+4], port)
	b[off+12] = 0x50
	b[off+13] = 2
	return b
}

func TestParseBounds(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		b := packet(v6, 443)
		for n := 0; n < len(b); n++ {
			if _, err := ParsePacket(b[:n]); err == nil {
				t.Fatalf("accepted truncated packet %v/%d", v6, n)
			}
		}
		e, err := ParsePacket(b)
		if err != nil || e.DstPort != 443 || e.TCPFlags != 2 || e.Transport != "tcp" {
			t.Fatalf("%+v %v", e, err)
		}
	}
	b := packet(false, 443)
	b[6] = 0x20
	if _, err := ParsePacket(b); !errors.Is(err, ErrFragment) {
		t.Fatal(err)
	}
	b = packet(true, 443)
	b[6] = 44
	if _, err := ParsePacket(b); !errors.Is(err, ErrFragment) {
		t.Fatal(err)
	}
}

func TestUDPAndIPv6Extensions(t *testing.T) {
	b := packet(false, 53)[:28]
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:4], 28)
	binary.BigEndian.PutUint16(b[24:26], 8)
	e, err := ParsePacket(b)
	if err != nil || e.Transport != "udp" || e.DstPort != 53 {
		t.Fatalf("%+v %v", e, err)
	}
	b[25] = 9
	if _, err := ParsePacket(b); err == nil {
		t.Fatal("bad UDP length accepted")
	}
	b = packet(true, 443)
	b = append(b[:40], append([]byte{6, 0, 0, 0, 0, 0, 0, 0}, b[40:]...)...)
	b[6] = 0
	binary.BigEndian.PutUint16(b[4:6], 28)
	e, err = ParsePacket(b)
	if err != nil || e.DstPort != 443 {
		t.Fatalf("IPv6 hop-by-hop: %+v %v", e, err)
	}
	b[41] = 255
	if _, err := ParsePacket(b); err == nil {
		t.Fatal("extension overrun accepted")
	}
	f, _ := New(testConfig(), evaluatorFunc(func(PacketEvent) (Decision, error) {
		t.Fatal("fragment reached evaluator")
		return Decision{Allow}, nil
	}))
	b = packet(false, 443)
	b[6] = 0x20
	if f.decide(context.Background(), nil, b) != Deny || f.Stats().ParseErrors != 1 {
		t.Fatal("fragment failure policy not applied")
	}
}

func testConfig() Config {
	return Config{Namespace: "nfw-gateway", Interface: "client0", ProtectedCIDRs: []string{"10.80.0.0/24", "fd80::/64"}, Hook: "forward", Queue: 120, MaxQueueLen: 128, Deadline: 20 * time.Millisecond, FailureVerdict: Deny}
}

func TestVerdictsAndBoundedEvaluator(t *testing.T) {
	for _, v := range []Verdict{Allow, Deny, WouldDeny, "unknown"} {
		f, err := New(testConfig(), evaluatorFunc(func(PacketEvent) (Decision, error) { return Decision{v}, nil }))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		got := f.decide(ctx, f.worker(ctx), packet(false, 443))
		cancel()
		want := v
		if v == WouldDeny {
			want = Allow
		}
		if v == "unknown" {
			want = Deny
		}
		if got != want {
			t.Fatalf("%s: %s", v, got)
		}
	}
	blocked := make(chan struct{})
	entered := make(chan struct{})
	f, _ := New(testConfig(), evaluatorFunc(func(PacketEvent) (Decision, error) { close(entered); <-blocked; return Decision{Allow}, nil }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(blocked)
	jobs := f.worker(ctx)
	if f.decide(ctx, jobs, packet(false, 443)) != Deny {
		t.Fatal("deadline must fail closed")
	}
	<-entered
	if f.decide(ctx, jobs, packet(false, 443)) != Deny {
		t.Fatal("saturation must fail closed")
	}
	if f.Stats().Deadlines != 1 || f.Stats().Overloads != 1 {
		t.Fatal(f.Stats())
	}
}

func FuzzParsePacket(f *testing.F) {
	f.Add(packet(false, 443))
	f.Add(packet(true, 80))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParsePacket(b) })
}
