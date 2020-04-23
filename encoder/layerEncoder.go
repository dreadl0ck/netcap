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

// Implements encoders to transform network packets into protocol buffers for various protocols
package encoder

import (
	"fmt"
	"log"
	"strings"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/golang/protobuf/proto"
)

var (
	// Quiet disables logging to stdout
	Quiet bool

	// LayerEncoders map contains initialized encoders at runtime
	// for usage from other packages
	LayerEncoders = map[gopacket.LayerType][]*LayerEncoder{}

	// contains all available layer encoders
	layerEncoderSlice = []*LayerEncoder{
		tcpEncoder,
		udpEncoder,
		ipv4Encoder,
		ipv6Encoder,
		dhcpv4Encoder,
		dhcpv6Encoder,
		icmpv4Encoder,
		icmpv6Encoder,
		icmpv6EchoEncoder,
		icmpv6NeighborSolicitationEncoder,
		icmpv6RouterSolicitationEncoder,
		dnsEncoder,
		arpEncoder,
		ethernetEncoder,
		dot1QEncoder,
		dot11Encoder,
		ntpEncoder,
		sipEncoder,
		igmpEncoder,
		llcEncoder,
		ipv6HopByHopEncoder,
		sctpEncoder,
		snapEncoder,
		linkLayerDiscoveryEncoder,
		icmpv6NeighborAdvertisementEncoder,
		icmpv6RouterAdvertisementEncoder,
		ethernetCTPEncoder,
		ethernetCTPReplyEncoder,
		linkLayerDiscoveryInfoEncoder,
		ipSecAHEncoder,
		ipSecESPEncoder,
		geneveEncoder,
		ip6FragmentEncoder,
		vxlanEncoder,
		usbEncoder,
		lcmEncoder,
		mplsEncoder,
		modbusEncoder,
		ospfv2Encoder,
		ospfv3Encoder,
		bfdEncoder,
		greEncoder,
		fddiEncoder,
		eapEncoder,
		vrrpv2Encoder,
		eapolEncoder,
		eapolkeyEncoder,
		ciscoDiscoveryEncoder,
		ciscoDiscoveryInfoEncoder,
		usbRequestBlockSetupEncoder,
		nortelDiscoveryEncoder,
		cipEncoder,
		ethernetIPEncoder,
		smtpEncoder,
		diameterEncoder,
	}

	// set via encoder config
	// used to request a content from being set on the audit records
	AddContext bool
)

type (
	// LayerEncoderHandler is the handler function for a layer encoder
	LayerEncoderHandler = func(layer gopacket.Layer, timestamp string) proto.Message

	// LayerEncoder represents an encoder for the gopacket.Layer type
	LayerEncoder struct {

		// public fields
		Layer gopacket.LayerType
		Type  types.Type

		Handler LayerEncoderHandler
		writer  *netcap.Writer
		export  bool
	}
)

// InitLayerEncoders initializes all layer encoders
func InitLayerEncoders(c Config, quiet bool) {

	// Flush layer encoders in case they have been initialized before
	LayerEncoders = map[gopacket.LayerType][]*LayerEncoder{}

	var (
		// values from command-line flags
		in = strings.Split(c.IncludeEncoders, ",")
		ex = strings.Split(c.ExcludeEncoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []*LayerEncoder
	)

	AddContext = c.AddContext

	// if there are includes and the first item is not an empty string
	if len(in) > 0 && in[0] != "" {

		// iterate over includes
		for _, name := range in {
			if name != "" {

				// check if proto exists
				if _, ok := allEncoderNames[name]; !ok {
					invalidEncoder(name)
				}

				// add to include map
				inMap[name] = true
			}
		}

		// iterate over layer encoders and collect those that are named in the includeMap
		for _, e := range layerEncoderSlice {
			if _, ok := inMap[e.Layer.String()]; ok {
				selection = append(selection, e)
			}
		}

		// update layer encoders to new selection
		layerEncoderSlice = selection
	}

	// iterate over excluded encoders
	for _, name := range ex {
		if name != "" {

			// check if proto exists
			if _, ok := allEncoderNames[name]; !ok {
				invalidEncoder(name)
			}

			// remove named encoder from layerEncoderSlice
			for i, e := range layerEncoderSlice {
				if name == e.Layer.String() {
					// remove encoder
					layerEncoderSlice = append(layerEncoderSlice[:i], layerEncoderSlice[i+1:]...)
					break
				}
			}
		}
	}

	// initialize encoders
	for _, e := range layerEncoderSlice {

		//fmt.Println("init", e.Layer)
		var filename = e.Layer.String()

		// handle inconsistencies in gopacket naming convention
		switch e.Type {
		case types.Type_NC_OSPFv2:
			filename = "OSPFv2"
		case types.Type_NC_OSPFv3:
			filename = "OSPFv3"
		case types.Type_NC_ENIP:
			filename = "ENIP"
		}
		e.writer = netcap.NewWriter(filename, c.Buffer, c.Compression, c.CSV, c.Out, c.WriteChan, c.MemBufferSize)

		err := e.writer.WriteHeader(e.Type, c.Source, netcap.Version, c.IncludePayloads)
		if err != nil {
			log.Fatal("failed to write header for audit record: ", e.Type.String())
		}

		// export metrics?
		e.export = c.Export

		// add to layer encoders map
		LayerEncoders[e.Layer] = append(LayerEncoders[e.Layer], e)
	}

	if !quiet {
		fmt.Println("initialized", len(LayerEncoders), "layer encoders")
	}
}

// CreateLayerEncoder returns a new LayerEncoder instance
func CreateLayerEncoder(nt types.Type, lt gopacket.LayerType, handler LayerEncoderHandler) *LayerEncoder {
	return &LayerEncoder{
		Layer:   lt,
		Handler: handler,
		Type:    nt,
	}
}

// Encode is called for each layer
// this calls the handler function of the encoder
// and writes the serialized protobuf into the data pipe
func (e *LayerEncoder) Encode(ctx *types.PacketContext, p gopacket.Packet, l gopacket.Layer) error {

	record := e.Handler(l, utils.TimeToString(p.Metadata().Timestamp))
	if record != nil {

		if ctx != nil {
			// assert to audit record
			if p, ok := record.(types.AuditRecord); ok {
				p.SetPacketContext(ctx)
			} else {
				fmt.Printf("type: %#v\n", record)
				log.Fatal("type does not implement the types.AuditRecord interface")
			}
		}

		if e.writer.IsCSV() {
			_, err := e.writer.WriteCSV(record)
			if err != nil {
				return err
			}
		} else {
			// write record
			err := e.writer.WriteProto(record)
			if err != nil {
				return err
			}
		}

		// export metrics if configured
		if e.export {
			// assert to audit record
			if p, ok := record.(types.AuditRecord); ok {
				// export metrics
				p.Inc()
			} else {
				fmt.Printf("type: %#v\n", record)
				log.Fatal("type does not implement the types.AuditRecord interface")
			}
		}
	}
	return nil
}

// GetChan returns a channel to receive serialized protobuf data from the encoder
func (e *LayerEncoder) GetChan() <-chan []byte {
	return e.writer.GetChan()
}

// Destroy closes and flushes all writers
func (e *LayerEncoder) Destroy() (name string, size int64) {
	return e.writer.Close()
}
