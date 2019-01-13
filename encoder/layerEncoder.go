/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"kythe.io/kythe/go/platform/delimited"
)

var (
	// LayerEncoders map contains initialized encoders at runtime
	// for usage from other packages
	LayerEncoders = map[gopacket.LayerType]*LayerEncoder{}

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
		modbusTCPEncoder,
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
	}
)

type (
	// LayerEncoderHandler is the handler function for a layer encoder
	LayerEncoderHandler = func(layer gopacket.Layer, timestamp string) proto.Message

	// LayerEncoder represents an encoder for the gopacket.Layer type
	LayerEncoder struct {

		// public fields
		Layer gopacket.LayerType
		Type  types.Type

		// private fields
		file      *os.File
		bWriter   *bufio.Writer
		gWriter   *gzip.Writer
		dWriter   *delimited.Writer
		aWriter   *AtomicDelimitedWriter
		Handler   LayerEncoderHandler
		cWriter   *chanWriter
		csvWriter *csvWriter

		// configuration
		compress bool
		csv      bool
		buffer   bool
		out      string

		teardownMerged func()
	}
)

// InitLayerEncoders initializes all layer encoders
func InitLayerEncoders(c Config) {

	var (
		// values from command-line flags
		in = strings.Split(c.IncludeEncoders, ",")
		ex = strings.Split(c.ExcludeEncoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []*LayerEncoder
	)

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

		// fmt.Println("init", d.layer)
		e.Init(c.Buffer, c.Compression, c.CSV, c.Out, c.WriteChan)

		// write header
		if e.csv {
			_, err := e.csvWriter.WriteHeader(netcap.InitRecord(e.Type))
			if err != nil {
				panic(err)
			}
		} else {
			err := e.aWriter.PutProto(NewHeader(e.Type, c))
			if err != nil {
				fmt.Println("failed to write header")
				panic(err)
			}
		}

		// check if an encoder for the specified layertype exists
		if existing, ok := LayerEncoders[e.Layer]; ok {
			// wrap it
			LayerEncoders[e.Layer] = mergeEncoders(existing, e)
		} else {
			// add to layer encoders map
			LayerEncoders[e.Layer] = e
		}
	}
	fmt.Println("initialized", len(LayerEncoders), "layer encoders | buffer size:", BlockSize)
}

// merge two encoders to a dummy encoder
// that simply calls both encoders after one another
// this is done to allow several encoders for the same gopacket.LayerType
// while being able to handle different versions of the same protocol separately
// it was introduced for the OSPFv2 and v3 encoders
func mergeEncoders(first, second *LayerEncoder) *LayerEncoder {

	merged := CreateLayerEncoder(first.Type, first.Layer, func(layer gopacket.Layer, timestamp string) proto.Message {
		err := first.Encode(layer, utils.StringToTime(timestamp))
		if err != nil {
			// @TODO log errors to logfile
			// c.logPacketError(p, "Layer Encoder Error: "+layer.LayerType().String()+": "+err.Error())
		}
		err = second.Encode(layer, utils.StringToTime(timestamp))
		if err != nil {
			// @TODO log errors to logfile
			// c.logPacketError(p, "Layer Encoder Error: "+layer.LayerType().String()+": "+err.Error())
		}
		return nil
	})

	merged.teardownMerged = func() {
		// TODO add to stats somehow
		first.Destroy()
		second.Destroy()
	}

	return merged
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
func (d *LayerEncoder) Encode(l gopacket.Layer, timestamp time.Time) error {

	// fmt.Println("decode", d.Layer.String())

	decoded := d.Handler(l, utils.TimeToString(timestamp))
	if decoded != nil {
		if d.csv {
			_, err := d.csvWriter.WriteRecord(decoded)
			if err != nil {
				return err
			}
		} else {
			err := d.aWriter.PutProto(decoded)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Init initializes and configures the encoder
func (d *LayerEncoder) Init(buffer, compress, csv bool, out string, writeChan bool) {

	if *debug {
		fmt.Println("INIT", d.Type, d.Layer)
	}

	protocol := strings.TrimPrefix(d.Type.String(), "NC_")

	d.compress = compress
	d.buffer = buffer
	d.csv = csv
	d.out = out

	if csv {

		// create file
		if compress {
			d.file = CreateFile(filepath.Join(out, protocol), ".csv.gz")
		} else {
			d.file = CreateFile(filepath.Join(out, protocol), ".csv")
		}

		if buffer {

			d.bWriter = bufio.NewWriterSize(d.file, BlockSize)

			if compress {
				d.gWriter = gzip.NewWriter(d.bWriter)
				d.csvWriter = NewCSVWriter(d.gWriter)
			} else {
				d.csvWriter = NewCSVWriter(d.bWriter)
			}
		} else {
			if compress {
				d.gWriter = gzip.NewWriter(d.file)
				d.csvWriter = NewCSVWriter(d.gWriter)
			} else {
				d.csvWriter = NewCSVWriter(d.file)
			}
		}
		return
	}

	if writeChan && buffer || writeChan && compress {
		panic("buffering or compression cannot be activated when running using writeChan")
	}

	// write into channel OR into file
	if writeChan {
		d.cWriter = newChanWriter()
	} else {
		if compress {
			d.file = CreateFile(filepath.Join(out, protocol), ".ncap.gz")
		} else {
			d.file = CreateFile(filepath.Join(out, protocol), ".ncap")
		}
	}

	// buffer data?
	// when using writeChan buffering is not possible
	if buffer {

		d.bWriter = bufio.NewWriterSize(d.file, BlockSize)
		if compress {
			d.gWriter = gzip.NewWriter(d.bWriter)
			d.dWriter = delimited.NewWriter(d.gWriter)
		} else {
			d.dWriter = delimited.NewWriter(d.bWriter)
		}
	} else {
		if compress {
			d.gWriter = gzip.NewWriter(d.file)
			d.dWriter = delimited.NewWriter(d.gWriter)
		} else {
			if writeChan {
				// write into channel writer without compression
				d.dWriter = delimited.NewWriter(d.cWriter)
			} else {
				d.dWriter = delimited.NewWriter(d.file)
			}
		}
	}

	d.aWriter = NewAtomicDelimitedWriter(d.dWriter)
}

// GetChan returns a channel to receive serialized protobuf data from the encoder
func (d *LayerEncoder) GetChan() <-chan []byte {
	return d.cWriter.Chan()
}

// Destroy closes and flushes all writers
func (d *LayerEncoder) Destroy() (name string, size int64) {
	if d.teardownMerged != nil {
		d.teardownMerged()
	}
	if d.compress {
		CloseGzipWriters(d.gWriter)
	}
	if d.buffer {
		FlushWriters(d.bWriter)
	}
	return CloseFile(d.out, d.file, strings.TrimPrefix("NC_", d.Type.String()))
}
