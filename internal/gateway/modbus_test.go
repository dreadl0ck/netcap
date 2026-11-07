package gateway

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

type evaluateFunc func(policy.Event) (policy.Decision, error)

func (f evaluateFunc) Evaluate(e policy.Event) (policy.Decision, error) { return f(e) }

func allowAll() Evaluator {
	return evaluateFunc(func(policy.Event) (policy.Decision, error) { return policy.Decision{Verdict: "allow"}, nil })
}

func adu(id uint16, pdu ...byte) []byte {
	b := make([]byte, 7, len(pdu)+7)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(pdu)+1))
	b[6] = 1
	return append(b, pdu...)
}

func receiveADU(c net.Conn) ([]byte, error) {
	b := make([]byte, 7)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if n < 2 || n > 254 {
		return nil, errModbus
	}
	p := make([]byte, n-1)
	_, err := io.ReadFull(c, p)
	return append(b, p...), err
}

// The origin deliberately does not use the gateway parser or policy. Its state
// and request count measure what actually crossed the enforcement boundary.
type modbusOrigin struct {
	listener    net.Listener
	connections atomic.Int32
	requests    atomic.Int32
	register    atomic.Uint32
	mu          sync.Mutex
	clients     []net.Conn
	wg          sync.WaitGroup
	acceptDone  chan struct{}
}

func startModbusOrigin(t *testing.T) *modbusOrigin {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &modbusOrigin{listener: l, acceptDone: make(chan struct{})}
	o.register.Store(42)
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer close(o.acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			o.connections.Add(1)
			o.mu.Lock()
			o.clients = append(o.clients, c)
			o.mu.Unlock()
			o.wg.Add(1)
			go func() {
				defer o.wg.Done()
				defer c.Close()
				for {
					r, err := receiveADU(c)
					if err != nil {
						return
					}
					o.requests.Add(1)
					var response []byte
					switch r[7] {
					case 6:
						o.register.Store(uint32(binary.BigEndian.Uint16(r[10:12])))
						response = r
					case 3:
						v := o.register.Load()
						response = adu(binary.BigEndian.Uint16(r), 3, 2, byte(v>>8), byte(v))
					default:
						o.register.Store(999)
						response = adu(binary.BigEndian.Uint16(r), r[7]|128, 1)
					}
					if _, err = c.Write(response); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-o.acceptDone
		o.mu.Lock()
		for _, c := range o.clients {
			_ = c.Close()
		}
		o.mu.Unlock()
		o.wg.Wait()
	})
	return o
}

func startTCPGateway(t *testing.T, cfg Config, p Evaluator) (net.Conn, context.CancelFunc, <-chan error) {
	t.Helper()
	g, err := New(cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, l) }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() {
		_ = c.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("gateway did not drain")
		}
	})
	return c, cancel, done
}

func TestModbusOriginEnforcementSplitAndCoalesced(t *testing.T) {
	o := startModbusOrigin(t)
	compiled, err := policy.Compile(policy.Bundle{Version: "1", ID: "industrial", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "protect-registers", Action: "deny", Expression: "Protocol == 'modbus' && Modbus.IsWrite && Modbus.EndAddress >= 100"}}})
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := startTCPGateway(t, Config{Protocol: "modbus", Upstream: o.listener.Addr().String()}, compiled)
	denied := adu(1, 6, 0, 100, 0, 99)
	for _, b := range denied {
		if _, err := c.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := receiveADU(c)
	if err != nil {
		t.Fatal(err)
	}
	if r[7] != 0x86 || r[8] != 1 || binary.BigEndian.Uint16(r) != 1 {
		t.Fatalf("denial %x", r)
	}
	if o.connections.Load() != 0 || o.requests.Load() != 0 {
		t.Fatal("denied request connected to origin")
	}
	read := adu(2, 3, 0, 100, 0, 1)
	// FC16 starts below the protected range but overlaps it.
	write := adu(3, 16, 0, 99, 0, 3, 6, 0, 1, 0, 2, 0, 3)
	if _, err := c.Write(append(read, write...)); err != nil {
		t.Fatal(err)
	}
	r, err = receiveADU(c)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(r) != 2 || r[7] != 3 || word(r[9:11]) != 42 {
		t.Fatalf("read %x", r)
	}
	r, err = receiveADU(c)
	if err != nil || r[7] != 0x90 || binary.BigEndian.Uint16(r) != 3 {
		t.Fatalf("coalesced deny %x %v", r, err)
	}
	if o.register.Load() != 42 || o.requests.Load() != 1 || o.connections.Load() != 1 {
		t.Fatalf("origin changed: register=%d requests=%d connections=%d", o.register.Load(), o.requests.Load(), o.connections.Load())
	}
	// A write outside the protected range must actually reach the origin.
	if _, err := c.Write(adu(4, 6, 0, 10, 0, 77)); err != nil {
		t.Fatal(err)
	}
	r, err = receiveADU(c)
	if err != nil || r[7] != 6 {
		t.Fatalf("allowed write %x %v", r, err)
	}
	if o.register.Load() != 77 || o.requests.Load() != 2 {
		t.Fatal("permitted write did not reach origin")
	}
}

func TestModbusRequestSemantics(t *testing.T) {
	tests := []struct {
		name              string
		pdu               []byte
		valid             bool
		address, quantity int
		write             bool
	}{
		{"read coils max", []byte{1, 0, 0, 7, 208}, true, 0, 2000, false},
		{"read registers max", []byte{3, 0, 0, 0, 125}, true, 0, 125, false},
		{"read zero", []byte{3, 0, 0, 0, 0}, false, 0, 0, false},
		{"read too many", []byte{3, 0, 0, 0, 126}, false, 0, 0, false},
		{"range overflow", []byte{3, 255, 255, 0, 2}, false, 0, 0, false},
		{"last register", []byte{6, 255, 255, 1, 2}, true, 65535, 1, true},
		{"coil on", []byte{5, 0, 10, 255, 0}, true, 10, 1, true},
		{"coil invalid", []byte{5, 0, 10, 1, 0}, false, 0, 0, false},
		{"coils", []byte{15, 0, 10, 0, 9, 2, 255, 1}, true, 10, 9, true},
		{"coil padding", []byte{15, 0, 10, 0, 9, 2, 255, 2}, false, 0, 0, false},
		{"registers", []byte{16, 0, 10, 0, 2, 4, 0, 1, 0, 2}, true, 10, 2, true},
		{"bad bytecount", []byte{16, 0, 10, 0, 2, 3, 0, 1, 0, 2}, false, 0, 0, false},
		{"mask", []byte{22, 0, 10, 255, 0, 0, 255}, true, 10, 1, true},
		{"read write", []byte{23, 0, 50, 0, 2, 0, 100, 0, 1, 2, 0, 99}, true, 100, 1, true},
		{"unsupported", []byte{8, 0, 0, 0, 0}, false, 0, 0, false},
		{"trailing", []byte{6, 0, 0, 0, 1, 0}, false, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := parseModbusRequest(adu(1, tt.pdu...))
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v err=%v", tt.valid, err)
			}
			if tt.valid && (m.Address != tt.address || m.Quantity != tt.quantity || m.IsWrite != tt.write || m.EndAddress != m.Address+m.Quantity-1) {
				t.Fatalf("metadata %+v", m)
			}
			if tt.valid && m.Function == 23 && (m.ReadAddress != 50 || m.ReadQuantity != 2 || m.ReadEndAddress != 51) {
				t.Fatalf("read range %+v", m)
			}
		})
	}
}

func TestModbusRejectsMalformedBeforeOrigin(t *testing.T) {
	for _, kind := range []string{"protocol", "oversize", "broadcast", "unsupported", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			o := startModbusOrigin(t)
			c, _, _ := startTCPGateway(t, Config{Protocol: "modbus", Upstream: o.listener.Addr().String(), IOTimeout: 30 * time.Millisecond}, allowAll())
			b := adu(1, 6, 0, 100, 0, 99)
			switch kind {
			case "protocol":
				b[3] = 1
			case "oversize":
				b[4], b[5] = 1, 0
			case "broadcast":
				b[6] = 0
			case "unsupported":
				b[7] = 8
			case "truncated":
				b = b[:9]
			}
			if _, err := c.Write(b); err != nil {
				t.Fatal(err)
			}
			var one [1]byte
			if n, err := c.Read(one[:]); n != 0 || err == nil {
				t.Fatal("malformed frame accepted")
			}
			if o.connections.Load() != 0 || o.register.Load() != 42 {
				t.Fatal("malformed request reached origin")
			}
		})
	}
}

func TestModbusResponseCorrelation(t *testing.T) {
	req := adu(1, 3, 0, 100, 0, 1)
	m, err := parseModbusRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	valid := adu(1, 3, 2, 0, 42)
	if validateModbusResponse(req, valid, m) != nil {
		t.Fatal("valid response rejected")
	}
	for _, kind := range []string{"transaction", "protocol", "unit", "function", "bytecount", "exception"} {
		t.Run(kind, func(t *testing.T) {
			b := append([]byte(nil), valid...)
			switch kind {
			case "transaction":
				b[1]++
			case "protocol":
				b[3] = 1
			case "unit":
				b[6]++
			case "function":
				b[7]++
			case "bytecount":
				b[8]++
			case "exception":
				b = adu(1, 0x83, 0)
			}
			if validateModbusResponse(req, b, m) == nil {
				t.Fatal("uncorrelated response accepted")
			}
		})
	}
}

func TestModbusCancellationDrainsPartialFrame(t *testing.T) {
	g, err := New(Config{Protocol: "modbus", Upstream: "127.0.0.1:1"}, allowAll())
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, l) }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{0})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("partial frame blocked cancellation")
	}
}

func FuzzModbusRequest(f *testing.F) {
	f.Add(adu(1, 23, 0, 50, 0, 2, 0, 100, 0, 1, 2, 0, 99))
	f.Add(adu(1, 6, 0, 100, 0, 99))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseModbusRequest(b)
		if err == nil && (m.Quantity < 1 || m.EndAddress > 65535 || len(b) > 260) {
			t.Fatal("invalid accepted range")
		}
	})
}
