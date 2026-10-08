package flowexport

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func testEnvelope(exporter string) Envelope {
	return Envelope{Exporter: exporter, Collector: "192.0.2.254:2055", ReceivedNs: 1700000000000000000}
}
func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func words(values ...uint32) []byte {
	b := make([]byte, len(values)*4)
	for i, n := range values {
		binary.BigEndian.PutUint32(b[i*4:], n)
	}
	return b
}
func shorts(values ...uint16) []byte {
	b := make([]byte, len(values)*2)
	for i, n := range values {
		binary.BigEndian.PutUint16(b[i*2:], n)
	}
	return b
}
func wide(n uint64) []byte              { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }
func set(id uint16, body []byte) []byte { return append(shorts(id, uint16(len(body)+4)), body...) }
func nf9(seq uint32, sets ...[]byte) []byte {
	b := append(shorts(9, uint16(len(sets))), words(120000, 1700000000, seq, 7)...)
	for _, s := range sets {
		b = append(b, s...)
	}
	return b
}
func ipfix(seq uint32, sets ...[]byte) []byte {
	b := append(shorts(10, 0), words(1700000000, seq, 7)...)
	for _, s := range sets {
		b = append(b, s...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func TestNetFlowV5NormalizedEvidence(t *testing.T) {
	e := testEngine(t)
	header := append(shorts(5, 1), words(120000, 1700000000, 123, 0)...)
	header = append(header, 1, 2)
	header = append(header, shorts(0x8064)...)
	record := append(net.IPv4(192, 0, 2, 1).To4(), net.IPv4(198, 51, 100, 1).To4()...)
	record = append(record, net.IPv4(192, 0, 2, 254).To4()...)
	record = append(record, shorts(2, 3)...)
	record = append(record, words(100, 600000000, 60000, 120000)...)
	record = append(record, shorts(12345, 443)...)
	record = append(record, 0, 0x12, 6, 0)
	record = append(record, shorts(64512, 64513)...)
	record = append(record, 24, 24, 0, 0)
	b, err := e.Decode(append(header, record...), testEnvelope("192.0.2.10:50000"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Observations) != 1 {
		t.Fatalf("records=%d", len(b.Observations))
	}
	o := b.Observations[0]
	if o.SrcIP != "192.0.2.1" || o.DstIP != "198.51.100.1" || *o.Bytes != 600000000 || *o.Packets != 100 || *o.Ingress != 2 || *o.Egress != 3 || *o.SrcAS != 64512 || *o.TCPFlags != 0x12 || *o.StartNs != 1699999940000000123 || *o.EndNs != 1700000000000000123 || o.Sampling.Interval != 100 {
		t.Fatalf("normalized record: %+v", o)
	}
	if o.CounterSemantics != "exported-delta-as-reported" || len(o.ID) != 64 {
		t.Fatal("missing count/provenance semantics")
	}
}

func TestNetFlowTemplatesIsolatedByExporterAndCapture(t *testing.T) {
	e := testEngine(t)
	a, b := testEnvelope("192.0.2.10:50000"), testEnvelope("192.0.2.11:50000")
	templateA := set(0, shorts(256, 3, 8, 4, 12, 4, 1, 4))
	templateB := set(0, shorts(256, 3, 12, 4, 8, 4, 1, 4))
	for _, tc := range []struct {
		env    Envelope
		packet []byte
	}{{a, nf9(0, templateA)}, {b, nf9(0, templateB)}} {
		if _, err := e.Decode(tc.packet, tc.env); err != nil {
			t.Fatal(err)
		}
	}
	data := append(net.IPv4(192, 0, 2, 1).To4(), net.IPv4(198, 51, 100, 1).To4()...)
	data = append(data, words(42)...)
	first, err := e.Decode(nf9(1, set(256, data)), a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Decode(nf9(1, set(256, data)), b)
	if err != nil {
		t.Fatal(err)
	}
	if first.Observations[0].SrcIP != "192.0.2.1" || second.Observations[0].SrcIP != "198.51.100.1" {
		t.Fatal("exporter templates collided")
	}
	missing, err := testEngine(t).Decode(nf9(1, set(256, data)), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing.Observations) != 0 || len(missing.Issues) != 1 || missing.Issues[0].Code != "missing-template" {
		t.Fatal("capture inherited templates or hid missing evidence")
	}
	duplicate, err := e.Decode(nf9(1, set(256, data)), a)
	if err != nil || len(duplicate.Observations) != 0 || e.Health().Duplicates != 1 {
		t.Fatal("duplicate export counted twice")
	}
}

func TestIPFIXEnterpriseVariableFieldsAndWithdrawal(t *testing.T) {
	e := testEngine(t)
	env := testEnvelope("[2001:db8::1]:50000")
	spec := shorts(300, 7, 27, 16, 28, 16, 1, 8, 2, 8, 152, 8, 153, 8, 0x8001, 65535)
	spec = append(spec, words(32473)...)
	if _, err := e.Decode(ipfix(0, set(2, spec)), env); err != nil {
		t.Fatal(err)
	}
	data := append(net.ParseIP("2001:db8::2").To16(), net.ParseIP("2001:db8::3").To16()...)
	data = append(data, wide(1<<63+5)...)
	data = append(data, wide(100)...)
	data = append(data, wide(1700000000000)...)
	data = append(data, wide(1700000060000)...)
	data = append(data, 255, 1, 44)
	data = append(data, []byte(strings.Repeat("x", 300))...)
	b, err := e.Decode(ipfix(0, set(300, data)), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Observations) != 1 {
		t.Fatal("record boundaries lost")
	}
	o := b.Observations[0]
	if *o.Bytes != 1<<63+5 || o.SrcIP != "2001:db8::2" || *o.EndNs-*o.StartNs != int64(time.Minute) || o.Fields[6].Enterprise != 32473 || len(o.Fields[6].Value) != 300 {
		t.Fatalf("IPFIX normalization: %+v", o)
	}
	encoded, err := json.Marshal(o)
	if err != nil || !strings.Contains(string(encoded), `"bytes":"9223372036854775813"`) {
		t.Fatal("wide counter lost JSON precision")
	}
	if _, err := e.Decode(ipfix(1, set(2, shorts(300, 0))), env); err != nil {
		t.Fatal(err)
	}
	missing, err := e.Decode(ipfix(1, set(300, data)), env)
	if err != nil || len(missing.Observations) != 0 || missing.Issues[0].Code != "missing-template" {
		t.Fatal("withdrawn template reused")
	}
}

func TestTemplatesExpireAndMalformedUpdatesAreAtomic(t *testing.T) {
	e := testEngine(t)
	env := testEnvelope("192.0.2.10:50000")
	if _, err := e.Decode(nf9(0, set(0, shorts(256, 1, 8, 4))), env); err != nil {
		t.Fatal(err)
	}
	bad := nf9(1, set(0, shorts(256, 2, 12, 4)))
	if _, err := e.Decode(bad, env); err == nil {
		t.Fatal("truncated template accepted")
	}
	b, err := e.Decode(nf9(1, set(256, net.IPv4(192, 0, 2, 1).To4())), env)
	if err != nil || b.Observations[0].SrcIP != "192.0.2.1" {
		t.Fatal("malformed update poisoned committed template")
	}
	env.ReceivedNs += int64(31 * time.Minute)
	b, err = e.Decode(nf9(2, set(256, net.IPv4(192, 0, 2, 1).To4())), env)
	if err != nil || len(b.Observations) != 0 || e.Health().ExpiredTemplates != 1 {
		t.Fatal("expired template silently reused")
	}
	if e.Health().Malformed != 1 || e.Health().MissingTemplates != 1 {
		t.Fatalf("health=%+v", e.Health())
	}
}

func TestSFlowSampleCountsRemainUnscaled(t *testing.T) {
	e := testEngine(t)
	env := testEnvelope("192.0.2.10:6343")
	ip := append(words(1500, 6), net.IPv4(192, 0, 2, 1).To4()...)
	ip = append(ip, net.IPv4(198, 51, 100, 1).To4()...)
	ip = append(ip, words(12345, 443, 0x12, 0)...)
	record := append(words(3, uint32(len(ip))), ip...)
	sample := append(words(1, 1, 1000, 1000, 0, 2, 3, 1), record...)
	data := append(words(5, 1), net.IPv4(192, 0, 2, 10).To4()...)
	data = append(data, words(1, 1, 120000, 1)...)
	data = append(data, words(1, uint32(len(sample)))...)
	data = append(data, sample...)
	b, err := e.Decode(data, env)
	if err != nil {
		t.Fatal(err)
	}
	o := b.Observations[0]
	if *o.Bytes != 1500 || *o.Packets != 1 || o.Sampling.Interval != 1000 || o.CounterSemantics != "sampled-packet-as-reported" || o.StartNs != nil || *o.Ingress != 2 || *o.Egress != 3 {
		t.Fatalf("sampling fabricated totals/time: %+v", o)
	}
	for length := 0; length < len(data); length++ {
		if _, err := testEngine(t).Decode(data[:length], env); err == nil {
			t.Fatalf("accepted truncated sFlow at %d", length)
		}
	}
}
