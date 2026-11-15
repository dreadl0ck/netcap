package zabbix

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"
)

func zabbixTestFrame(t *testing.T, payload []byte, compressed bool) []byte {
	t.Helper()
	wire := append([]byte(nil), zabbixMagic...)
	data := payload
	if compressed {
		wire[4] = 3
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		data = b.Bytes()
	}
	wire = binary.LittleEndian.AppendUint32(wire, uint32(len(data)))
	reserved := uint32(0)
	if compressed {
		reserved = uint32(len(payload))
	}
	wire = binary.LittleEndian.AppendUint32(wire, reserved)
	return append(wire, data...)
}

func TestZabbixCompressedAndPlainFrames(t *testing.T) {
	body := []byte(`{"request":"agent data","host":"synthetic","key":"fixture","value":"known"}`)
	var stream []byte
	for _, compressed := range []bool{false, true, false, true} {
		frame := zabbixTestFrame(t, body, compressed)
		if !Decoder.CanDecode(frame[:5], nil) {
			t.Fatal("compressed magic not recognized")
		}
		stream = append(stream, frame...)
	}
	records := (&zabbixReader{}).parseZabbixMessages(stream)
	if len(records) != 4 {
		t.Fatalf("got %d records", len(records))
	}
	for _, r := range records {
		if r.RequestType != "agent data" || r.Host != "synthetic" || r.Value != "known" || r.DataLength != int32(len(body)) {
			t.Fatal(r)
		}
	}
	for _, change := range []func([]byte){
		func(b []byte) { b[4] = 0x83 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[9:], maxZabbixPayload+1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[9:], uint32(len(body)+1)) },
		func(b []byte) { b[len(b)-1] ^= 0xff },
	} {
		frame := zabbixTestFrame(t, body, true)
		change(frame)
		if len((&zabbixReader{}).parseZabbixMessages(frame)) != 0 {
			t.Fatal("invalid compressed frame accepted")
		}
	}
}
