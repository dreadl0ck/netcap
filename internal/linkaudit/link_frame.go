package linkaudit

import "github.com/gopacket/gopacket"

var LayerLinkFrame = gopacket.RegisterLayerType(12006, gopacket.LayerTypeMetadata{Name: "LinkFrame"})

type LinkFrame struct {
	Type                                           uint32
	Protocol, Source, Destination, PayloadProtocol string
	Header, Payload                                []byte
	Fields                                         map[string]string
	Qualifications                                 []string
}

func (*LinkFrame) LayerType() gopacket.LayerType { return LayerLinkFrame }
func (l *LinkFrame) LayerContents() []byte       { return l.Header }
func (l *LinkFrame) LayerPayload() []byte        { return l.Payload }
