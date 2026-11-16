package rohc

import (
	"bytes"
	"encoding/binary"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"testing"
)

func TestUDPIRAndCompressedHeaderCRC(t *testing.T) {
	if CRC([]byte{0xfc, 0}, 8) != 0xb7 {
		t.Fatal("ROHC CRC8 bit order changed")
	}
	static := []byte{0x40, 17, 192, 0, 2, 1, 239, 1, 2, 3, 0x9c, 0x40, 0x27, 0x0f}
	dynamic := []byte{0, 64, 0, 0, 0xa0, 0, 0, 0, 0x10, 0}
	wire := append([]byte{0xfd, 2, 0}, static...)
	wire = append(wire, dynamic...)
	wire[2] = CRC(wire, 8)
	wire = append(wire, []byte("payload")...)
	ctx, packet, err := DecodeUDP(Context{}, wire, 0, 1)
	if err != nil || len(packet) != 35 || packet[6] != 0x40 || binary.BigEndian.Uint16(packet[20:]) != 40000 {
		t.Fatal(ctx, packet, err)
	}
	p := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeUDP) == nil {
		t.Fatal(p)
	}
	for _, kind := range []string{"uo0", "uo1", "uor2"} {
		expected, _ := ctx.packet([]byte("next"))
		var compressed []byte
		switch kind {
		case "uo0":
			compressed = []byte{byte((ctx.SN+1)&15)<<3 | CRC(crcHeader(expected, 4), 3)}
		case "uo1":
			compressed = []byte{0x80 | byte((ctx.ID-ctx.SN)&63), byte((ctx.SN+1)&31)<<3 | CRC(crcHeader(expected, 4), 3)}
		case "uor2":
			compressed = []byte{0xc0 | byte((ctx.SN+1)&31), CRC(crcHeader(expected, 4), 7)}
		}
		compressed = append(compressed, []byte("next")...)
		updated, got, err := DecodeUDP(ctx, compressed, 0, 1)
		if err != nil || !bytes.Equal(got, expected) || updated.SN != ctx.SN+1 {
			t.Fatal(kind, updated, err)
		}
		bad := bytes.Clone(compressed)
		if kind == "uo0" {
			bad[0] ^= 1
		} else {
			bad[1] ^= 1
		}
		unchanged, _, err := DecodeUDP(ctx, bad, 0, 1)
		if err == nil || unchanged != ctx {
			t.Fatal("CRC failure mutated context", kind)
		}
		ctx = updated
	}
	for n := 0; n < 27; n++ {
		if _, _, err := DecodeUDP(Context{}, wire[:n], 0, 1); err == nil {
			t.Fatal("truncated IR accepted", n)
		}
	}
}

func TestRDTAndCIDBounds(t *testing.T) {
	d, err := ParseRDT([]byte{4, 4, 0x3f, 1, 0, 2})
	if err != nil || d.PLP != 1 || d.MaxCID != 1 || len(d.Contexts) != 1 {
		t.Fatal(d, err)
	}
	for _, wire := range [][]byte{{4, 4, 0x3f}, {4, 4, 0x3f, 1, 2, 2}, {4, 4, 0x7f, 1, 0, 2, 255}} {
		if _, err := ParseRDT(wire); err == nil {
			t.Fatal("invalid RDT accepted", wire)
		}
	}
	for _, large := range []bool{false, true} {
		wire := []byte{0xfd, 2, 0}
		if large {
			wire = []byte{0xfd, 1, 2, 0}
		}
		id, first, after, err := PacketCID(wire, large)
		if err != nil || first != 0 || after != 1+int(boolInt(large)) || id != byte(boolInt(large)) {
			t.Fatal(id, first, after, err)
		}
	}
}

func TestUDPSequentialIPIDAndIPv6(t *testing.T) {
	ctx := Context{Version: 4, Static: true, Dynamic: true, Hop: 64, Flags: 0x20, ID: 1, SN: 100, SourcePort: 40000, DestinationPort: 9999}
	copy(ctx.Source[:4], []byte{192, 0, 2, 1})
	copy(ctx.Destination[:4], []byte{239, 1, 2, 3})
	want := ctx
	want.ID++
	want.SN++
	packet, _ := want.packet([]byte("payload"))
	wire := []byte{byte(want.SN&15)<<3 | CRC(crcHeader(packet, 4), 3)}
	wire = append(wire, []byte("payload")...)
	updated, got, err := DecodeUDP(ctx, wire, 0, 1)
	if err != nil || updated.ID != 2 || !bytes.Equal(got, packet) {
		t.Fatal(updated, err)
	}
	ctx = Context{Version: 6, Static: true, Dynamic: true, Hop: 64, Checksum: 0x1234, SN: 100, SourcePort: 40000, DestinationPort: 9999}
	ctx.Source[0], ctx.Destination[0] = 0x20, 0x20
	ctx.Source[15], ctx.Destination[15] = 1, 2
	packet, _ = ctx.packet([]byte("payload"))
	wire = []byte{byte((ctx.SN+1)&15)<<3 | CRC(crcHeader(packet, 6), 3), 0x12, 0x34}
	wire = append(wire, []byte("payload")...)
	_, got, err = DecodeUDP(ctx, wire, 0, 1)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatal(err)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func FuzzROHCUDPBounds(f *testing.F) {
	f.Add([]byte{0xfd, 2, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			t.Skip()
		}
		_, _, _ = DecodeUDP(Context{}, data, 0, 1)
		_, _ = ParseRDT(data)
	})
}
