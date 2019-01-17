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
	"kythe.io/kythe/go/platform/delimited"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
)

var (
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

		// fmt.Println("init", e.layer)
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

		// add to layer encoders map
		LayerEncoders[e.Layer] = append(LayerEncoders[e.Layer], e)
	}
	fmt.Println("initialized", len(LayerEncoders), "layer encoders | buffer size:", BlockSize)
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
func (e *LayerEncoder) Encode(l gopacket.Layer, timestamp time.Time) error {

	// fmt.Println("decode", e.Layer.String())

	decoded := e.Handler(l, utils.TimeToString(timestamp))
	if decoded != nil {
		if e.csv {
			_, err := e.csvWriter.WriteRecord(decoded)
			if err != nil {
				return err
			}
		} else {
			err := e.aWriter.PutProto(decoded)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Init initializes and configures the encoder
func (e *LayerEncoder) Init(buffer, compress, csv bool, out string, writeChan bool) {

	if *debug {
		fmt.Println("INIT", e.Type, e.Layer)
	}

	protocol := strings.TrimPrefix(e.Type.String(), "NC_")

	e.compress = compress
	e.buffer = buffer
	e.csv = csv
	e.out = out

	if csv {

		// create file
		if compress {
			e.file = CreateFile(filepath.Join(out, protocol), ".csv.gz")
		} else {
			e.file = CreateFile(filepath.Join(out, protocol), ".csv")
		}

		if buffer {

			e.bWriter = bufio.NewWriterSize(e.file, BlockSize)

			if compress {
				e.gWriter = gzip.NewWriter(e.bWriter)
				e.csvWriter = NewCSVWriter(e.gWriter)
			} else {
				e.csvWriter = NewCSVWriter(e.bWriter)
			}
		} else {
			if compress {
				e.gWriter = gzip.NewWriter(e.file)
				e.csvWriter = NewCSVWriter(e.gWriter)
			} else {
				e.csvWriter = NewCSVWriter(e.file)
			}
		}
		return
	}

	if writeChan && buffer || writeChan && compress {
		panic("buffering or compression cannot be activated when running using writeChan")
	}

	// write into channel OR into file
	if writeChan {
		e.cWriter = newChanWriter()
	} else {
		if compress {
			e.file = CreateFile(filepath.Join(out, protocol), ".ncap.gz")
		} else {
			e.file = CreateFile(filepath.Join(out, protocol), ".ncap")
		}
	}

	// buffer data?
	// when using writeChan buffering is not possible
	if buffer {

		e.bWriter = bufio.NewWriterSize(e.file, BlockSize)
		if compress {
			e.gWriter = gzip.NewWriter(e.bWriter)
			e.dWriter = delimited.NewWriter(e.gWriter)
		} else {
			e.dWriter = delimited.NewWriter(e.bWriter)
		}
	} else {
		if compress {
			e.gWriter = gzip.NewWriter(e.file)
			e.dWriter = delimited.NewWriter(e.gWriter)
		} else {
			if writeChan {
				// write into channel writer without compression
				e.dWriter = delimited.NewWriter(e.cWriter)
			} else {
				e.dWriter = delimited.NewWriter(e.file)
			}
		}
	}

	e.aWriter = NewAtomicDelimitedWriter(e.dWriter)
}

// GetChan returns a channel to receive serialized protobuf data from the encoder
func (e *LayerEncoder) GetChan() <-chan []byte {
	return e.cWriter.Chan()
}

// Destroy closes and flushes all writers
func (e *LayerEncoder) Destroy() (name string, size int64) {
	if e.compress {
		CloseGzipWriters(e.gWriter)
	}
	if e.buffer {
		FlushWriters(e.bWriter)
	}
	return CloseFile(e.out, e.file, strings.TrimPrefix("NC_", e.Type.String()))
}
