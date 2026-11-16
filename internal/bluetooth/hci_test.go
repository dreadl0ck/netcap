package bluetooth

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestACLFragmentsATTAndDirectionIsolation(t *testing.T) {
	p := &Processor{}
	direction := byte(0)
	data := []byte{3, 0, 4, 0, 2, 23, 0}
	events, err := p.Push("bus", 2, []byte{1, 0x20, 5, 0}, data[:5], &direction, 1)
	if err != nil || len(events) != 1 || len(events[0].Qualifications) == 0 {
		t.Fatal(events, err)
	}
	other := byte(1)
	events, err = p.Push("bus", 2, []byte{1, 0x10, 2, 0}, data[5:], &other, 2)
	if err != nil || len(events) != 1 || len(events[0].Qualifications) == 0 {
		t.Fatal("direction crossed ACL streams")
	}
	events, err = p.Push("bus", 2, []byte{1, 0x10, 2, 0}, data[5:], &direction, 3)
	if err != nil || len(events) != 2 || events[1].Protocol != "ATT" || events[1].Fields["MTU"].(uint16) != 23 || len(events[1].Sources) != 2 {
		t.Fatal(events, err)
	}
	if p.credit != 0 {
		t.Fatal("fragment credits leaked")
	}
	secret := []byte("secret-not-metadata")
	att := append([]byte{0x12, 1, 0}, secret...)
	l2 := binary.LittleEndian.AppendUint16(nil, uint16(len(att)))
	l2 = append(l2, 4, 0)
	l2 = append(l2, att...)
	events = decodeL2CAP(l2, []uint64{4})
	output, _ := json.Marshal(events)
	if bytes.Contains(output, secret) || events[1].Fields["ValueLength"] != len(secret) {
		t.Fatal("ATT payload exposed as metadata", string(output))
	}
	if _, err = p.Push("bus", 2, []byte{1, 0x20, 5, 0}, data[:5], nil, 5); err != nil || p.credit != 0 {
		t.Fatal("directionless fragment retained")
	}
}

func TestHCIControllerVersion(t *testing.T) {
	p := &Processor{}
	events, err := p.Push("bus", 4, []byte{0x0e, 12}, []byte{1, 1, 0x10, 0, 9, 0x34, 0x12, 9, 0x4c, 0, 0x78, 0x56}, nil, 1)
	if err != nil || events[0].Fields["Manufacturer"].(uint16) != 76 || events[0].Fields["HCIRevision"].(uint16) != 0x1234 {
		t.Fatal(events, err)
	}
}

func FuzzL2CAPAndATTBounds(f *testing.F) {
	f.Add([]byte{3, 0, 4, 0, 2, 23, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65539 {
			t.Skip()
		}
		if len(data) >= 4 {
			_ = decodeL2CAP(data, []uint64{1})
		}
		_ = decodeATT(data)
	})
}
