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

package encoder

import (
	"fmt"
	"log"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var (
	// CustomEncoders slice contains initialized encoders at runtime
	// for usage from other packages
	CustomEncoders, customEncoderSlice = []*CustomEncoder{}, []*CustomEncoder{
		tlsClientHelloEncoder,
		tlsServerHelloEncoder,
		httpEncoder,
		flowEncoder,
		connectionEncoder,
		profileEncoder,
		fileEncoder,
		pop3Encoder,
	} // contains all available custom encoders
)

type (
	// CustomEncoderHandler takes a gopacket.Packet and returns a proto.Message
	CustomEncoderHandler = func(p gopacket.Packet) proto.Message

	// CustomEncoder implements custom logic to decode data from a gopacket.Packet
	CustomEncoder struct {

		// public fields
		Name string

		Type     types.Type
		Handler  CustomEncoderHandler
		postinit func(*CustomEncoder) error
		deinit   func(*CustomEncoder) error

		// used to keep track of the number of generated audit records
		numRecords int64

		// HTTP specific stats
		numRequests             int64
		numResponses            int64
		numUnmatchedResp        int64
		numNilRequests          int64
		numFoundRequests        int64
		numRemovedRequests      int64
		numUnansweredRequests   int64
		numClientStreamNotFound int64

		writer *netcap.Writer
		export bool
	}
)

// package level init
func init() {
	// collect all names for custom encoders on startup
	for _, e := range customEncoderSlice {
		allEncoderNames[e.Name] = struct{}{}
	}
	// collect all names for custom encoders on startup
	for _, e := range layerEncoderSlice {
		allEncoderNames[e.Layer.String()] = struct{}{}
	}
}

// InitCustomEncoders initializes all custom encoders
func InitCustomEncoders(c Config, quiet bool) {

	// Flush custom encoders in case they have been initialized before
	CustomEncoders = []*CustomEncoder{}

	var (
		// values from command-line flags
		in = strings.Split(c.IncludeEncoders, ",")
		ex = strings.Split(c.ExcludeEncoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []*CustomEncoder
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

		// iterate over custom encoders and collect those that are named in the includeMap
		for _, e := range customEncoderSlice {
			if _, ok := inMap[e.Name]; ok {
				selection = append(selection, e)
			}
		}

		// update custom encoders to new selection
		customEncoderSlice = selection
	}

	// iterate over excluded encoders
	for _, name := range ex {
		if name != "" {

			// check if proto exists
			if _, ok := allEncoderNames[name]; !ok {
				invalidEncoder(name)
			}

			// remove named encoder from customEncoderSlice
			for i, e := range customEncoderSlice {
				if name == e.Name {
					// remove encoder
					customEncoderSlice = append(customEncoderSlice[:i], customEncoderSlice[i+1:]...)
					break
				}
			}
		}
	}

	// initialize encoders
	for _, e := range customEncoderSlice {

		// fmt.Println("init custom encoder", e.name)
		e.writer = netcap.NewWriter(e.Name, c.Buffer, c.Compression, c.CSV, c.Out, c.WriteChan, c.MemBufferSize)

		// call postinit func if set
		if e.postinit != nil {
			err := e.postinit(e)
			if err != nil {
				panic(err)
			}
		}

		// export metrics?
		e.export = c.Export

		// write header
		err := e.writer.WriteHeader(e.Type, c.Source, netcap.Version, c.IncludePayloads)
		if err != nil {
			log.Fatal("failed to write header for audit record: ", e.Name)
		}

		// append to custom encoders slice
		CustomEncoders = append(CustomEncoders, e)
	}

	if !quiet {
		fmt.Println("initialized", len(CustomEncoders), "custom encoders")
	}
}

// CreateCustomEncoder returns a new CustomEncoder instance
func CreateCustomEncoder(t types.Type, name string, postinit func(*CustomEncoder) error, handler CustomEncoderHandler, deinit func(*CustomEncoder) error) *CustomEncoder {
	return &CustomEncoder{
		Name:     name,
		Handler:  handler,
		deinit:   deinit,
		postinit: postinit,
		Type:     t,
	}
}

// Encode is called for each layer
// this calls the handler function of the encoder
// and writes the serialized protobuf into the data pipe
func (e *CustomEncoder) Encode(p gopacket.Packet) error {

	// call the Handler function of the encoder
	record := e.Handler(p)
	if record != nil {

		// increase counter
		atomic.AddInt64(&e.numRecords, 1)


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

// Destroy closes and flushes all writers and calls deinit if set
func (e *CustomEncoder) Destroy() (name string, size int64) {
	if e.deinit != nil {
		err := e.deinit(e)
		if err != nil {
			panic(err)
		}
	}
	return e.writer.Close()
}

// GetChan returns a channel to receive serialized protobuf data from the encoder
func (e *CustomEncoder) GetChan() <-chan []byte {
	return e.writer.GetChan()
}

// NumRecords returns the number of written records
func (e *CustomEncoder) NumRecords() int64 {
	return atomic.LoadInt64(&e.numRecords)
}
