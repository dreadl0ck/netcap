package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/mpegts"
	"github.com/gopacket/gopacket"
)

func tsSectionTest(data []byte) []byte {
	n := len(data) + 1
	data[1], data[2] = 0xb0|byte(n>>8), byte(n)
	return binary.BigEndian.AppendUint32(data, mpegts.CRC(data))
}
func tsFrameTest(pid uint16, data []byte) []byte {
	frame := bytes.Repeat([]byte{0xff}, 188)
	frame[0], frame[1], frame[2], frame[3] = 0x47, 0x40|byte(pid>>8), byte(pid), 0x30
	frame[4] = byte(182 - len(data))
	frame[5] = 0
	offset := 5 + int(frame[4])
	frame[offset] = 0
	copy(frame[offset+1:], data)
	return frame
}

func TestMPEGTSCollectorPSIMetadata(t *testing.T) {
	r := &linkReconstructor{}
	pat := tsSectionTest([]byte{0, 0, 0, 0, 1, 0xc1, 0, 0, 0, 1, 0xe1, 0})
	pmt := tsSectionTest([]byte{2, 0, 0, 0, 1, 0xc1, 0, 0, 0xe1, 1, 0xf0, 0, 0x1b, 0xe1, 1, 0xf0, 0})
	for i, data := range [][]byte{tsFrameTest(0, pat), tsFrameTest(0x100, pmt)} {
		p := gopacket.NewPacket(data, captureBusDecoder(243), gopacket.Default)
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100, int64(i)), Length: len(data), CaptureLength: len(data)}
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer())
		}
		f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
		r.enrichMPEGTS(p, f, uint64(i+1))
		var events []mpegts.Event
		if err := json.Unmarshal([]byte(f.Fields["mpeg_ts_events"]), &events); err != nil || len(events) != 1 || len(events[0].Qualifications) != 0 {
			t.Fatal(f, err)
		}
	}
	r.finish()
	if r.health.BufferedBytes != 0 {
		t.Fatal("MPEG transport credits leaked", r.health)
	}
}
