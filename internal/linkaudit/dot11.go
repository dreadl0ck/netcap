package linkaudit

import (
	"bytes"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type FrameCheck struct{ Known, Present bool }

func FrameCheckInfo(ci gopacket.CaptureInfo) FrameCheck {
	for _, item := range ci.AncillaryData {
		if check, ok := item.(*FrameCheck); ok {
			return *check
		}
	}
	return FrameCheck{}
}

// Dot11's upstream decoder requires a checksum trailer. Only its scratch view is padded.
func DecodeDot11(data []byte, p gopacket.PacketBuilder, present bool) error {
	if !present {
		data = append(bytes.Clone(data), 0, 0, 0, 0)
	}
	return DecodeDot11View(data, p, present)
}

func DecodeDot11View(data []byte, p gopacket.PacketBuilder, present bool) error {
	d := &layers.Dot11{}
	if err := d.DecodeFromBytes(data, p); err != nil {
		return err
	}
	if !present {
		d.Checksum = 0
	}
	p.AddLayer(d)
	if d.DataLayer != nil {
		p.AddLayer(d.DataLayer)
	}
	return p.NextDecoder(d.NextLayerType())
}

func DecodeRadioTap(data []byte, p gopacket.PacketBuilder, check *FrameCheck) error {
	r := &layers.RadioTap{}
	// Upstream may remove driver padding in-place; never expose capture storage to it.
	if err := r.DecodeFromBytes(bytes.Clone(data), p); err != nil {
		return err
	}
	p.AddLayer(r)
	check.Known = true
	if len(r.RadioTapValues) > 0 {
		check.Present = r.RadioTapValues[0].Flags.FCS()
	}
	return DecodeDot11View(r.LayerPayload(), p, check.Present)
}
