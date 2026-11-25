package otframe

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type TSDU struct {
	Frame
	Type     gopacket.LayerType
	Carrier  layers.COTP
	WireSize int
	Pieces   uint32
}
type ISO struct {
	a      layers.COTPAssembler
	first  int64
	pieces uint32
}

func (s *ISO) Pending() bool { return s.a.Pending() > 0 }
func (s *ISO) Feed(f Frame) (TSDU, error) {
	var t layers.TPKT
	var c layers.COTP
	out := TSDU{Frame: f, WireSize: len(f.Data)}
	if err := t.DecodeFromBytes(f.Data, gopacket.NilDecodeFeedback); err != nil {
		*s = ISO{}
		return out, err
	}
	if err := c.DecodeFromBytes(t.Payload, gopacket.NilDecodeFeedback); err != nil {
		*s = ISO{}
		return out, err
	}
	out.Carrier = c
	if s.a.Pending() == 0 {
		s.first = f.At
		s.pieces = 0
	}
	s.pieces++
	body, next, err := s.a.Feed(&c)
	out.At = s.first
	out.Pieces = s.pieces
	out.Data = body
	out.Type = next
	return out, err
}
