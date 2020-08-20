/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Package decoder implements decoders to transform network packets into protocol buffers for various protocols
package decoder

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// contains all available gopacket decoders.
var defaultGoPacketDecoders = []*GoPacketDecoder{
	tcpDecoder,
	udpDecoder,
	ipv4Decoder,
	ipv6Decoder,
	dhcpv4Decoder,
	dhcpv6Decoder,
	icmpv4Decoder,
	icmpv6Decoder,
	icmpv6EchoDecoder,
	icmpv6NeighborSolicitationDecoder,
	icmpv6RouterSolicitationDecoder,
	dnsDecoder,
	arpDecoder,
	ethernetDecoder,
	dot1QDecoder,
	dot11Decoder,
	ntpDecoder,
	sipDecoder,
	igmpDecoder,
	llcDecoder,
	ipv6HopByHopDecoder,
	sctpDecoder,
	snapDecoder,
	linkLayerDiscoveryDecoder,
	icmpv6NeighborAdvertisementDecoder,
	icmpv6RouterAdvertisementDecoder,
	ethernetCTPDecoder,
	ethernetCTPReplyDecoder,
	linkLayerDiscoveryInfoDecoder,
	ipSecAHDecoder,
	ipSecESPDecoder,
	geneveDecoder,
	ip6FragmentDecoder,
	vxlanDecoder,
	usbDecoder,
	lcmDecoder,
	mplsDecoder,
	modbusDecoder,
	ospfv2Decoder,
	ospfv3Decoder,
	bfdDecoder,
	greDecoder,
	fddiDecoder,
	eapDecoder,
	vrrpv2Decoder,
	eapolDecoder,
	eapolkeyDecoder,
	ciscoDiscoveryDecoder,
	ciscoDiscoveryInfoDecoder,
	usbRequestBlockSetupDecoder,
	nortelDiscoveryDecoder,
	cipDecoder,
	ethernetIPDecoder,
	smtpDecoder,
	diameterDecoder,
}

type (
	// goPacketDecoderHandler is the handler function for a layer encoder.
	goPacketDecoderHandler = func(layer gopacket.Layer, timestamp string) proto.Message

	// GoPacketDecoder represents an encoder for the gopacket.Layer type
	// this structure has an optimized field order to avoid excessive padding.
	GoPacketDecoder struct {
		Description string
		Layer       gopacket.LayerType
		Handler     goPacketDecoderHandler

		writer netcap.AuditRecordWriter
		Type   types.Type
		export bool
	}
)

// InitGoPacketDecoders initializes all gopacket decoders.
func InitGoPacketDecoders(c *Config) (decoders map[gopacket.LayerType][]*GoPacketDecoder, err error) {
	decoders = map[gopacket.LayerType][]*GoPacketDecoder{}

	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []*GoPacketDecoder
	)

	// if there are includes and the first item is not an empty string
	if len(in) > 0 && in[0] != "" { // iterate over includes
		for _, name := range in {
			if name != "" { // check if proto exists
				if _, ok := allDecoderNames[name]; !ok {
					return nil, errors.Wrap(ErrInvalidDecoder, name)
				}

				// add to include map
				inMap[name] = true
			}
		}

		// iterate over gopacket decoders and collect those that are named in the includeMap
		for _, e := range defaultGoPacketDecoders {
			if _, ok := inMap[e.Layer.String()]; ok {
				selection = append(selection, e)
			}
		}

		// update gopacket decoders to new selection
		defaultGoPacketDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" { // check if proto exists
			if _, ok := allDecoderNames[name]; !ok {
				return nil, errors.Wrap(ErrInvalidDecoder, name)
			}

			// remove named encoder from defaultGoPacketDecoders
			for i, e := range defaultGoPacketDecoders {
				if name == e.Layer.String() {
					// remove encoder
					defaultGoPacketDecoders = append(defaultGoPacketDecoders[:i], defaultGoPacketDecoders[i+1:]...)
					break
				}
			}
		}
	}

	// initialize decoders
	for _, e := range defaultGoPacketDecoders { // fmt.Println("init", e.Layer)
		filename := e.Layer.String()

		// handle inconsistencies in gopacket naming convention
		switch e.Type {
		case types.Type_NC_OSPFv2:
			filename = "OSPFv2"
		case types.Type_NC_OSPFv3:
			filename = "OSPFv3"
		case types.Type_NC_ENIP:
			filename = "ENIP"
		}

		// hookup writer
		e.writer = netcap.NewAuditRecordWriter(&netcap.WriterConfig{
			CSV:     c.CSV,
			Proto:   c.Proto,
			JSON:    c.JSON,
			Chan:    c.Chan,
			Null:    c.Null,
			Elastic: c.Elastic,
			ElasticConfig: netcap.ElasticConfig{
				ElasticAddrs:   c.ElasticAddrs,
				ElasticUser:    c.ElasticUser,
				ElasticPass:    c.ElasticPass,
				KibanaEndpoint: c.KibanaEndpoint,
				BulkSize:       c.BulkSizeGoPacket,
			},
			Name:             filename,
			Buffer:           c.Buffer,
			Compress:         c.Compression,
			Out:              c.Out,
			MemBufferSize:    c.MemBufferSize,
			Source:           c.Source,
			Version:          netcap.Version,
			IncludesPayloads: c.IncludePayloads,
			StartTime:        time.Now(),
		})

		// write netcap header
		err = e.writer.WriteHeader(e.Type)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write header for audit record "+e.Type.String())
		}

		// export metrics?
		e.export = c.ExportMetrics

		// add to gopacket decoders map
		decoders[e.Layer] = append(decoders[e.Layer], e)
	}

	utils.DebugLog.Println("initialized", len(decoders), "gopacket decoders")

	return decoders, nil
}

// newGoPacketDecoder returns a new GoPacketDecoder instance.
func newGoPacketDecoder(nt types.Type, lt gopacket.LayerType, description string, handler goPacketDecoderHandler) *GoPacketDecoder {
	return &GoPacketDecoder{
		Layer:       lt,
		Handler:     handler,
		Type:        nt,
		Description: description,
	}
}

// Decode is called for each layer
// this calls the handler function of the encoder
// and writes the serialized protobuf into the data pipe.
func (dec *GoPacketDecoder) Decode(ctx *types.PacketContext, p gopacket.Packet, l gopacket.Layer) error {
	record := dec.Handler(l, utils.TimeToString(p.Metadata().Timestamp))
	if record != nil {

		if ctx != nil {
			// assert to audit record
			if auditRecord, ok := record.(types.AuditRecord); ok {
				auditRecord.SetPacketContext(ctx)
			} else {
				fmt.Printf("type: %#v\n", record)
				log.Fatal("type does not implement the types.AuditRecord interface")
			}
		}

		err := dec.writer.Write(record)
		if err != nil {
			return err
		}

		// export metrics if configured
		if dec.export {
			// assert to audit record
			if auditRecord, ok := record.(types.AuditRecord); ok {
				// export metrics
				auditRecord.Inc()
			} else {
				fmt.Printf("type: %#v\n", record)
				log.Fatal("type does not implement the types.AuditRecord interface")
			}
		}
	}

	return nil
}

// GetChan returns a channel to receive serialized protobuf data from the encoder.
func (cd *GoPacketDecoder) GetChan() <-chan []byte {
	if cw, ok := cd.writer.(netcap.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// Destroy closes and flushes all writers.
func (dec *GoPacketDecoder) Destroy() (name string, size int64) {
	return dec.writer.Close()
}
