package bacnet

import "testing"

func TestNPDUAndAPDUHeaders(t *testing.T) {
	read := []byte{1, 4, 0, 5, 17, 12, 0x0c, 2, 0, 0, 123, 0x19, 85}
	p, err := ParseNPDU(read)
	if err != nil || p.APDU == nil || *p.APDU.InvokeID != 17 || *p.APDU.Service != 12 || *p.APDU.ObjectID != 0x0200007b || *p.APDU.PropertyID != 85 {
		t.Fatal(p, err)
	}
	iam := []byte{1, 0, 0x10, 0, 0xc4, 2, 0, 0, 123, 0x22, 5, 0xc4, 0x91, 3, 0x21, 5}
	p, err = ParseNPDU(iam)
	if err != nil || p.APDU.DeviceInstance == nil || *p.APDU.DeviceInstance != 123 {
		t.Fatal(p, err)
	}
	p, err = ParseNPDU([]byte{1, 0x20, 0, 123, 1, 5, 255, 0x10, 8})
	if err != nil || *p.DNET != 123 || p.DADR != "05" || *p.HopCount != 255 || p.ApplicationOffset != 7 {
		t.Fatal(p, err)
	}
	for _, data := range [][]byte{{1, 0, 0, 5, 17}, {1, 0x20, 0, 1, 10, 5}, {1, 0x80, 0x80}, {1, 0, 0x0c, 5, 17, 0}, {1, 0, 0x30, 1}, {1, 0, 0xf0}} {
		if _, err := ParseNPDU(data); err == nil {
			t.Fatal("truncated or invalid PDU accepted", data)
		}
	}
	p, err = ParseNPDU([]byte{1, 4, 0x0c, 5, 17, 0, 4, 12, 0x0c, 2, 0, 0, 123, 0x19, 85})
	if err != nil || !p.APDU.Segmented || p.APDU.ObjectID != nil || len(p.APDU.Qualifications) == 0 {
		t.Fatal("segment parsed as complete service", p, err)
	}
	for _, wire := range [][]byte{{1, 0, 0x20, 1, 12}, {1, 0, 0x30, 1, 12}, {1, 0, 0x40, 1, 0, 4}, {1, 0, 0x50, 1, 12, 0x91, 1, 0x91, 32}, {1, 0, 0x60, 1, 2}, {1, 0, 0x70, 1, 2}} {
		if _, err := ParseNPDU(wire); err != nil {
			t.Fatal(wire, err)
		}
	}
}

func FuzzNPDUBounds(f *testing.F) {
	f.Add([]byte{1, 0, 0x10, 8})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		p, err := ParseNPDU(data)
		if err == nil && !p.NetworkMessage && (p.APDU == nil || p.ApplicationOffset < 2 || p.ApplicationOffset >= len(data)) {
			t.Fatal("NPDU boundary lost")
		}
	})
}
