package packet

import (
	"fmt"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

func legacyARPHandler(layer gopacket.Layer, timestamp int64) proto.Message {
	if arp, ok := layer.(*layers.ARP); ok {
		return decodeARP(arp, timestamp)
	}
	return nil
}

func legacyEthernetHandler(layer gopacket.Layer, timestamp int64) proto.Message {
	if eth, ok := layer.(*layers.Ethernet); ok {
		return decodeEthernet(eth, timestamp)
	}
	return nil
}

func TestTypedARPHandler(t *testing.T) {
	const timestamp int64 = 1723456789123456789
	for _, tc := range []struct {
		name                            string
		operation                       uint16
		src, dst                        []byte
		srcText                         string
		operationName                   string
		gratuitous, probe, announcement bool
	}{
		{"request", 1, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, "192.0.2.1", "Request", false, false, false},
		{"reply", 2, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, "192.0.2.1", "Reply", false, false, false},
		{"gratuitous", 2, []byte{192, 0, 2, 2}, []byte{192, 0, 2, 2}, "192.0.2.2", "Reply", true, false, false},
		{"probe", 1, []byte{0, 0, 0, 0}, []byte{192, 0, 2, 2}, "0.0.0.0", "Request", false, true, false},
		{"announcement", 1, []byte{192, 0, 2, 2}, []byte{192, 0, 2, 2}, "192.0.2.2", "Request", false, false, true},
		{"rarp-request", 3, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, "192.0.2.1", "RARP Request", false, false, false},
		{"rarp-reply", 4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, "192.0.2.1", "RARP Reply", false, false, false},
		{"unknown", 99, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}, "192.0.2.1", "Unknown", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layer := &layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: tc.operation,
				SourceHwAddress: []byte{0, 1, 2, 3, 4, 5}, DstHwAddress: []byte{6, 7, 8, 9, 10, 11},
				SourceProtAddress: tc.src, DstProtAddress: tc.dst,
			}
			want := &types.ARP{
				Timestamp: timestamp, AddrType: 1, Protocol: 0x0800,
				HwAddressSize: 6, ProtocolAddressSize: 4, Operation: int32(tc.operation),
				SrcHwAddress: "00:01:02:03:04:05", DstHwAddress: "06:07:08:09:0a:0b",
				SrcProtocolAddress: tc.srcText, DstProtocolAddress: "192.0.2.2",
				OperationName: tc.operationName, IsGratuitous: tc.gratuitous,
				IsProbe: tc.probe, IsAnnouncement: tc.announcement,
			}
			got := arpDecoder.Handler(layer, timestamp)
			if !proto.Equal(got, want) {
				t.Fatalf("got %v; want %v", got, want)
			}
			if legacy := legacyARPHandler(layer, timestamp); !proto.Equal(got, legacy) {
				t.Fatalf("generic %v differs from legacy %v", got, legacy)
			}
		})
	}
}

func TestTypedEthernetHandler(t *testing.T) {
	previous := conf
	conf = &config.Config{}
	t.Cleanup(func() { conf = previous })
	const timestamp int64 = 1723456789123456789
	for _, tc := range []struct {
		name                        string
		src, dst                    []byte
		srcText, dstText            string
		etherType                   layers.EthernetType
		typeName                    string
		broadcast, multicast, local bool
	}{
		{"unicast", []byte{0, 1, 2, 3, 4, 5}, []byte{6, 7, 8, 9, 10, 11}, "00:01:02:03:04:05", "06:07:08:09:0a:0b", layers.EthernetTypeIPv4, "IPv4", false, false, false},
		{"broadcast", []byte{2, 1, 2, 3, 4, 5}, []byte{255, 255, 255, 255, 255, 255}, "02:01:02:03:04:05", "ff:ff:ff:ff:ff:ff", layers.EthernetTypeARP, "ARP", true, false, true},
		{"multicast", []byte{0, 1, 2, 3, 4, 5}, []byte{1, 0, 94, 0, 0, 1}, "00:01:02:03:04:05", "01:00:5e:00:00:01", layers.EthernetTypeIPv6, "IPv6", false, true, false},
		{"empty-unknown", nil, nil, "", "", layers.EthernetType(0xffff), "Unknown", false, false, false},
	} {
		for _, calculateEntropy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/entropy=%t", tc.name, calculateEntropy), func(t *testing.T) {
				conf.CalculateEntropy = calculateEntropy
				layer := &layers.Ethernet{
					BaseLayer: layers.BaseLayer{Payload: []byte{0, 1, 2, 3}},
					SrcMAC:    tc.src, DstMAC: tc.dst, EthernetType: tc.etherType,
				}
				want := &types.Ethernet{
					Timestamp: timestamp, SrcMAC: tc.srcText, DstMAC: tc.dstText,
					EthernetType: int32(tc.etherType), EthernetTypeName: tc.typeName, PayloadSize: 4,
					IsBroadcast: tc.broadcast, IsMulticast: tc.multicast, IsLocallyAdministered: tc.local,
				}
				if calculateEntropy {
					want.PayloadEntropy = 2
				}
				got := ethernetDecoder.Handler(layer, timestamp)
				if !proto.Equal(got, want) {
					t.Fatalf("got %v; want %v", got, want)
				}
				if legacy := legacyEthernetHandler(layer, timestamp); !proto.Equal(got, legacy) {
					t.Fatalf("generic %v differs from legacy %v", got, legacy)
				}
			})
		}
	}
}

func TestTypedLayerHandlerNil(t *testing.T) {
	for _, decoder := range []*GoPacketDecoder{arpDecoder, ethernetDecoder} {
		for _, layer := range []gopacket.Layer{nil, &layers.IPv4{}} {
			if got := decoder.Handler(layer, 123); got != nil {
				t.Fatalf("%s mismatch returned non-nil interface: %#v", decoder.GetName(), got)
			}
		}
	}
	if arpDecoder.Handler(&layers.Ethernet{}, 123) != nil || ethernetDecoder.Handler(&layers.ARP{}, 123) != nil {
		t.Fatal("cross-protocol mismatch returned non-nil")
	}
	calls := 0
	handler := typedLayerHandler(func(layer *layers.ARP, timestamp int64) proto.Message {
		calls++
		if layer != nil || timestamp != 123 {
			t.Fatalf("converter arguments: %v, %d", layer, timestamp)
		}
		return nil
	})
	if handler(nil, 123) != nil || handler(&layers.Ethernet{}, 123) != nil || calls != 0 {
		t.Fatal("mismatch must return nil without calling converter")
	}
	// A matching typed nil still passes the assertion, just as in the legacy adapter.
	if handler((*layers.ARP)(nil), 123) != nil || calls != 1 {
		t.Fatal("matching typed nil or converter nil result was not preserved")
	}
}

var typedHandlerBenchmarkSink proto.Message

func BenchmarkTypedLayerHandler(b *testing.B) {
	previous := conf
	conf = &config.Config{}
	b.Cleanup(func() { conf = previous })
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: 1,
		SourceHwAddress: []byte{0, 1, 2, 3, 4, 5}, DstHwAddress: []byte{6, 7, 8, 9, 10, 11},
		SourceProtAddress: []byte{192, 0, 2, 1}, DstProtAddress: []byte{192, 0, 2, 2},
	}
	eth := &layers.Ethernet{
		BaseLayer: layers.BaseLayer{Payload: []byte{0, 1, 2, 3, 0, 1, 2, 3}},
		SrcMAC:    []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4,
	}
	for _, tc := range []struct {
		name             string
		layer            gopacket.Layer
		legacy, generic  goPacketDecoderHandler
		calculateEntropy bool
	}{
		{"ARP", arp, legacyARPHandler, arpDecoder.Handler, false},
		{"Ethernet", eth, legacyEthernetHandler, ethernetDecoder.Handler, false},
		{"EthernetEntropy", eth, legacyEthernetHandler, ethernetDecoder.Handler, true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			conf.CalculateEntropy = tc.calculateEntropy
			for _, adapter := range []struct {
				name    string
				handler goPacketDecoderHandler
			}{{"legacy", tc.legacy}, {"generic", tc.generic}} {
				b.Run(adapter.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						typedHandlerBenchmarkSink = adapter.handler(tc.layer, 1723456789123456789)
					}
				})
			}
		})
	}
}
