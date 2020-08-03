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

package decoder

import (
	"fmt"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/mgutz/ansi"
	"github.com/pkg/errors"
	"log"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var (
	ErrInvalidDecoder = errors.New("invalid decoder")

	defaultCustomDecoders = []*CustomDecoder{
		tlsClientHelloDecoder,
		tlsServerHelloDecoder,
		httpDecoder,
		flowDecoder,
		connectionDecoder,
		profileDecoder,
		fileDecoder,
		pop3Decoder,
		softwareDecoder,
		serviceDecoder,
		credentialsDecoder,
		sshDecoder,
		vulnerabilityDecoder,
		exploitDecoder,
	} // contains all available custom decoders
)

type (
	// CustomDecoderHandler takes a gopacket.Packet and returns a proto.Message
	CustomDecoderHandler = func(p gopacket.Packet) proto.Message

	// CustomDecoder implements custom logic to decode data from a gopacket.Packet
	// this structure has an optimized field order to avoid excessive padding
	CustomDecoder struct {

		// public fields
		Name        string
		Description string
		Icon        string

		numResponses int64 // HTTP

		Handler CustomDecoderHandler

		postinit func(*CustomDecoder) error
		deinit   func(*CustomDecoder) error

		// used to keep track of the number of generated audit records
		numRecords int64

		numRequests int64 // HTTP

		writer *netcap.Writer

		// TODO: refactor this to avoid bloating the structure
		numUnmatchedResp        int64 // HTTP
		numNilRequests          int64 // HTTP
		numFoundRequests        int64 // HTTP
		numRemovedRequests      int64 // HTTP
		numUnansweredRequests   int64 // HTTP
		numClientStreamNotFound int64 // HTTP

		Type   types.Type
		export bool
	}
)

// package level init
func init() {
	// collect all names for custom decoders on startup
	for _, e := range defaultCustomDecoders {
		allDecoderNames[e.Name] = struct{}{}
	}
	// collect all names for custom decoders on startup
	for _, e := range defaultGoPacketDecoders {
		allDecoderNames[e.Layer.String()] = struct{}{}
	}
}

// InitCustomDecoders initializes all custom decoders
func InitCustomDecoders(c Config) (decoders []*CustomDecoder, err error) {

	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []*CustomDecoder
	)

	// if there are includes and the first item is not an empty string
	if len(in) > 0 && in[0] != "" {

		// iterate over includes
		for _, name := range in {
			if name != "" {

				// check if proto exists
				if _, ok := allDecoderNames[name]; !ok {
					return nil, errors.Wrap(ErrInvalidDecoder, name)
				}

				// add to include map
				inMap[name] = true
			}
		}

		// iterate over custom decoders and collect those that are named in the includeMap
		for _, e := range defaultCustomDecoders {
			if _, ok := inMap[e.Name]; ok {
				selection = append(selection, e)
			}
		}

		// update custom decoders to new selection
		defaultCustomDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" {

			// check if proto exists
			if _, ok := allDecoderNames[name]; !ok {
				return nil, errors.Wrap(ErrInvalidDecoder, name)
			}

			// remove named encoder from defaultCustomDecoders
			for i, e := range defaultCustomDecoders {
				if name == e.Name {
					// remove encoder
					defaultCustomDecoders = append(defaultCustomDecoders[:i], defaultCustomDecoders[i+1:]...)
					break
				}
			}
		}
	}

	// initialize decoders
	for _, e := range defaultCustomDecoders {

		// fmt.Println("init custom encoder", e.name)
		e.writer = netcap.NewWriter(e.Name, c.Buffer, c.Compression, c.CSV, c.Out, c.WriteChan, c.MemBufferSize)

		// call postinit func if set
		if e.postinit != nil {
			err := e.postinit(e)
			if err != nil {
				if c.IgnoreDecoderInitErrors {
					fmt.Println(ansi.Red, err, ansi.Reset)
				} else {
					return nil, errors.Wrap(err, "postinit failed")
				}
			}
		}

		// export metrics?
		e.export = c.Export

		// write header
		err := e.writer.WriteHeader(e.Type, c.Source, netcap.Version, c.IncludePayloads)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write header for audit record " + e.Name)
		}

		// append to custom decoders slice
		decoders = append(decoders, e)
	}

	if isCustomDecoderLoaded(credentialsDecoderName) {
		useHarvesters = true
	}

	utils.DebugLog.Println("initialized", len(decoders), "custom decoders")

	return decoders, nil
}

func isCustomDecoderLoaded(name string) bool {
	for _, e := range defaultCustomDecoders {
		if e.Name == name {
			return true
		}
	}
	return false
}

// NewCustomDecoder returns a new CustomDecoder instance
func NewCustomDecoder(t types.Type, name string, description string, postinit func(*CustomDecoder) error, handler CustomDecoderHandler, deinit func(*CustomDecoder) error) *CustomDecoder {
	return &CustomDecoder{
		Name:        name,
		Handler:     handler,
		deinit:      deinit,
		postinit:    postinit,
		Type:        t,
		Description: description,
	}
}

// Decode is called for each layer
// this calls the handler function of the encoder
// and writes the serialized protobuf into the data pipe
func (e *CustomDecoder) Decode(p gopacket.Packet) error {

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
func (e *CustomDecoder) Destroy() (name string, size int64) {
	if e.deinit != nil {
		err := e.deinit(e)
		if err != nil {
			panic(err)
		}
	}
	return e.writer.Close()
}

// GetChan returns a channel to receive serialized protobuf data from the encoder
func (e *CustomDecoder) GetChan() <-chan []byte {
	return e.writer.GetChan()
}

// NumRecords returns the number of written records
func (e *CustomDecoder) NumRecords() int64 {
	return atomic.LoadInt64(&e.numRecords)
}
