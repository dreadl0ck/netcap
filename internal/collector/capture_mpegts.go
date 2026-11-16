package collector

import (
	"encoding/json"
	"fmt"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/mpegts"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/gopacket/gopacket"
)

func (r *linkReconstructor) enrichMPEGTS(p gopacket.Packet, f *linkaudit.LinkFrame, ordinal uint64) {
	if r.err != nil {
		return
	}
	r.health.LimitBytes, r.health.AssemblyLimit = linkStateLimit, linkAssemblyLimit
	if r.transport == nil {
		r.transport = &mpegts.Processor{Reserve: func(n int) bool { return r.reserve(uint64(n)) }, Release: func(n int) { r.health.BufferedBytes -= uint64(n) }}
	}
	base := 0
	for _, layer := range p.Layers() {
		if layer == f {
			break
		}
		base += len(layer.LayerContents())
	}
	data := p.Data()[base:]
	if len(data)%188 != 0 || len(data)/188 > 128 {
		f.Qualifications = append(f.Qualifications, "MPEG-TS-batch-processing-limit")
		r.transport.Reset()
		return
	}
	scope := packetview.Scope(p)
	var events []mpegts.Event
	for offset := 0; offset < len(data); offset += 188 {
		source := mpegts.Source{Ordinal: ordinal, Offset: base + offset, Length: 188}
		if ctx := packetview.FromCapture(p.Metadata().CaptureInfo); ctx != nil && len(ctx.LinkTransformations) > 0 {
			source.Derived = true
			source.ChildOrdinal = ctx.LinkTransformations[0].ChildOrdinal
		}
		observations, err := r.transport.Push(scope, data[offset:offset+188], source)
		if err != nil {
			r.err = fmt.Errorf("MPEG-TS reconstruction: %w", err)
			r.health.BudgetExceeded = true
			return
		}
		if len(events)+len(observations) > 256 {
			f.Qualifications = append(f.Qualifications, "MPEG-TS-event-limit")
			r.transport.Reset()
			break
		}
		events = append(events, observations...)
	}
	if len(events) > 0 {
		data, _ := json.Marshal(events)
		f.Fields["mpeg_ts_events"] = string(data)
	}
}

func (r *linkReconstructor) finishMPEGTS() {
	if r.transport == nil {
		return
	}
	for _, event := range r.transport.Incomplete() {
		frame := busFrame(243, "MPEG-TS reconstruction")
		data, _ := json.Marshal([]mpegts.Event{event})
		frame.Fields["mpeg_ts_events"] = string(data)
		frame.Qualifications = []string{"MPEG-TS-reconstruction-incomplete"}
		p := gopacket.NewPacket(nil, gopacket.DecodeFunc(func(_ []byte, b gopacket.PacketBuilder) error { b.AddLayer(frame); return nil }), gopacket.Default)
		p.Metadata().CaptureInfo.Timestamp = r.watermark
		r.events = append(r.events, p)
	}
	r.transport.Reset()
}
