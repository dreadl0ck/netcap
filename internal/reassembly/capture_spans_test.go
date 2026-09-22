package reassembly

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

func TestCaptureSpansPages(t *testing.T) {
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(10, 123), CaptureLength: 5000, Length: 5000, InterfaceIndex: 7}
	ac := assemblerSimpleContext(ci)
	other := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Unix(20, 0)})
	payload := bytes.Repeat([]byte{0x42}, 2*pageBytes+5)
	live := &livePacket{bytes: payload, ac: &ac}
	// KeepFrom may pass the delivery's first context, not this packet's context.
	first, _, count := live.convertToPages(newPageCache(), 0, &other)
	if count != 3 {
		t.Fatalf("pages: %d", count)
	}
	sg := &reassemblyObject{all: []byteContainer{&livePacket{}}}
	for p := first; p != nil; p = p.next {
		sg.all = append(sg.all, p)
	}
	if got := sg.Stats().Packets; got != 2 { // One empty live container and one queued packet.
		t.Fatalf("packet statistics: %d", got)
	}
	var got []byte
	spans := 0
	sg.ForEach(func(data []byte, ctx AssemblerContext) {
		if ctx != &ac || !reflect.DeepEqual(ctx.GetCaptureInfo(), ci) {
			t.Fatal("page lost its capture context")
		}
		got = append(got, data...)
		spans++
	})
	if spans != 3 || !bytes.Equal(got, payload) {
		t.Fatalf("spans=%d bytes=%d", spans, len(got))
	}
	// A retained/overlapped tail must work even after its first page is removed.
	sg.all = sg.all[2:]
	if !reflect.DeepEqual(sg.CaptureInfo(0), ci) || !reflect.DeepEqual(sg.CaptureInfo(pageBytes), ci) {
		t.Fatal("continuation CaptureInfo lost after first page removed")
	}
	if sg.Stats().Packets != 0 {
		t.Fatal("continuation pages counted as new packets")
	}
	sg.ForEach(func(_ []byte, ctx AssemblerContext) {
		if ctx != &ac {
			t.Fatal("continuation context lost after first page removed")
		}
	})
}
