package collector

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/bluetooth"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/gopacket/gopacket"
)

func (r *linkReconstructor) enrichHCI(p gopacket.Packet, f *linkaudit.LinkFrame, ordinal uint64) {
	if r.err != nil {
		return
	}
	r.health.LimitBytes, r.health.AssemblyLimit = linkStateLimit, linkAssemblyLimit
	if r.hci == nil {
		r.hci = &bluetooth.Processor{Reserve: func(n int) bool { return r.reserve(uint64(n)) }, Release: func(n int) { r.health.BufferedBytes -= uint64(n) }}
	}
	offset := 0
	var direction *byte
	if f.Type == 201 {
		offset = 4
		if len(f.Header) < 5 {
			return
		}
		value := f.Header[3] & 1
		direction = &value
	}
	if len(f.Header) <= offset {
		return
	}
	kind := f.Header[offset]
	header := f.Header[offset+1:]
	length, err := strconv.Atoi(f.Fields["declared_payload_length"])
	if err != nil || length > len(f.Payload) || length < 0 {
		return
	}
	events, err := r.hci.Push(packetview.Scope(p), kind, header, f.Payload[:length], direction, ordinal)
	if err != nil {
		r.err = fmt.Errorf("Bluetooth reconstruction: %w", err)
		r.health.BudgetExceeded = true
		return
	}
	if len(events) > 0 {
		data, _ := json.Marshal(events)
		f.Fields["bluetooth_events"] = string(data)
		for _, event := range events {
			if len(event.Packet) > 0 {
				f.Decoded = event.Packet
			}
		}
	}
}

func (r *linkReconstructor) finishHCI() {
	if r.hci == nil {
		return
	}
	for _, event := range r.hci.Incomplete() {
		frame := busFrame(201, "Bluetooth reconstruction")
		data, _ := json.Marshal([]bluetooth.Event{event})
		frame.Fields["bluetooth_events"] = string(data)
		frame.Qualifications = []string{"L2CAP-reconstruction-incomplete"}
		p := gopacket.NewPacket(nil, gopacket.DecodeFunc(func(_ []byte, b gopacket.PacketBuilder) error { b.AddLayer(frame); return nil }), gopacket.Default)
		p.Metadata().CaptureInfo.Timestamp = r.watermark
		r.events = append(r.events, p)
	}
	r.hci.Reset()
}
