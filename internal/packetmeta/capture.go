// Package packetmeta persists the capture metadata consumed by deferred readers.
package packetmeta

import (
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/gopacket/gopacket"
)

type Capture struct {
	Timestamp                                          time.Time
	CaptureLength, Length, Interface, LogicalInterface int
	MissingTime                                        bool
	Context                                            *packetview.Context
	FCS                                                linkaudit.FrameCheck
}

func Save(ci gopacket.CaptureInfo) Capture {
	return Capture{Timestamp: ci.Timestamp, CaptureLength: ci.CaptureLength, Length: ci.Length, Interface: ci.InterfaceIndex, LogicalInterface: packetview.LogicalInterface(ci), MissingTime: packetview.TimeUnavailable(ci), Context: packetview.FromCapture(ci), FCS: linkaudit.FrameCheckInfo(ci)}
}

func (c Capture) Restore() gopacket.CaptureInfo {
	ci := gopacket.CaptureInfo{Timestamp: c.Timestamp, CaptureLength: c.CaptureLength, Length: c.Length, InterfaceIndex: c.Interface}
	ci.AncillaryData = []any{packetview.CaptureInterface(c.LogicalInterface), packetview.TimestampMissing(c.MissingTime), &c.FCS}
	if c.Context != nil {
		ci.AncillaryData = append(ci.AncillaryData, c.Context)
	}
	return ci
}
