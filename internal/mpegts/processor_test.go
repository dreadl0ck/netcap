package mpegts

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func section(data []byte) []byte {
	length := len(data) + 4 - 3
	data[1] = 0xb0 | byte(length>>8)
	data[2] = byte(length)
	return binary.BigEndian.AppendUint32(data, CRC(data))
}
func ts(pid uint16, cc byte, start bool, payload []byte) []byte {
	out := bytes.Repeat([]byte{0xff}, 188)
	out[0], out[1], out[2], out[3] = 0x47, byte(pid>>8&31), byte(pid), 0x30|cc
	if start {
		out[1] |= 0x40
	}
	n := 183 - len(payload)
	out[4] = byte(n)
	if n > 0 {
		out[5] = 0
	}
	copy(out[5+n:], payload)
	return out
}
func pat() []byte { return section([]byte{0, 0, 0, 0, 1, 0xc1, 0, 0, 0, 1, 0xe1, 0}) }
func pmt() []byte {
	return section([]byte{2, 0, 0, 0, 1, 0xc1, 0, 0, 0xe1, 1, 0xf0, 0, 0x1b, 0xe1, 1, 0xf0, 0, 0x0f, 0xe1, 2, 0xf0, 0})
}

func TestPATPMTPESAndElementaryMetadata(t *testing.T) {
	if CRC([]byte("123456789")) != 0x0376e6e7 {
		t.Fatal("MPEG-2 CRC polynomial changed")
	}
	p := &Processor{}
	ordinal := uint64(0)
	push := func(pid uint16, cc byte, start bool, payload []byte) []Event {
		ordinal++
		events, err := p.Push("stream-1", ts(pid, cc, start, payload), Source{Ordinal: ordinal, Length: 188})
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	first := pat()
	events := push(0, 0, true, append([]byte{0}, first[:7]...))
	if len(events) != 0 {
		t.Fatal("partial PAT emitted")
	}
	events = push(0, 1, false, first[7:])
	if len(events) != 1 || events[0].Kind != "PAT" || len(events[0].Qualifications) != 0 {
		t.Fatal(events)
	}
	events = push(0x100, 0, true, append([]byte{0}, pmt()...))
	if len(events) != 1 || events[0].Kind != "PMT" || len(events[0].Qualifications) != 0 {
		t.Fatal(events)
	}
	header := []byte{0, 0, 1, 0xe0, 0, 15, 0x80, 0x80, 5, 0x21, 0, 5, 0xbf, 0x21}
	video := append(header, 0, 0, 1, 0x65, 0x88, 0x84, 0x21)
	events = push(0x101, 0, true, video[:5])
	if len(events) != 0 {
		t.Fatal("partial PES emitted")
	}
	events = push(0x101, 1, false, video[5:])
	if len(events) != 2 || events[0].Kind != "PES-header" || events[1].Kind != "elementary-header" {
		t.Fatal(events)
	}
	fields := events[0].Fields.(map[string]any)
	if fields["PTS90kHz"].(uint64) != 90000 {
		t.Fatal(fields)
	}
	fields = events[1].Fields.(map[string]any)
	if fields["NALType"].(byte) != 5 || !fields["IDR"].(bool) {
		t.Fatal(fields)
	}
	audio := []byte{0, 0, 1, 0xc0, 0, 10, 0x80, 0, 0, 0xff, 0xf1, 0x50, 0x80, 0, 0xff, 0xfc}
	events = push(0x102, 0, true, audio)
	if len(events) != 2 || events[1].Kind != "AAC-ADTS" || events[1].Fields.(map[string]any)["SampleRate"].(int) != 44100 {
		t.Fatal(events)
	}
	p.Reset()
	if p.credit != 0 {
		t.Fatal("transport state credits leaked")
	}
}

func TestPSICRCIsolationAndBudget(t *testing.T) {
	p := &Processor{}
	bad := pat()
	bad[len(bad)-1] ^= 1
	events, err := p.Push("one", ts(0, 0, true, append([]byte{0}, bad...)), Source{Ordinal: 1})
	if err != nil || len(events) != 1 || len(events[0].Qualifications) == 0 {
		t.Fatal(events, err)
	}
	events, err = p.Push("two", ts(0x100, 0, true, append([]byte{0}, pmt()...)), Source{Ordinal: 2})
	if err != nil || len(events) != 0 {
		t.Fatal("PAT mapping crossed scopes")
	}
	p.Reset()
	p.Reserve = func(int) bool { return false }
	if _, err := p.Push("one", ts(0, 0, true, append([]byte{0}, pat()...)), Source{Ordinal: 3}); err == nil {
		t.Fatal("transport state limit ignored")
	}
}

func FuzzTransportFrameBounds(f *testing.F) {
	f.Add(ts(0, 0, true, append([]byte{0}, pat()...)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		p := &Processor{}
		_, _ = p.Push("scope", data, Source{Ordinal: 1})
		p.Reset()
		if p.credit != 0 {
			t.Fatal("transport credits leaked")
		}
	})
}
