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
	"log"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

var (
	ErrInvalidDecoder = errors.New("invalid decoder")

	defaultCustomDecoders = []CustomDecoderAPI{
		tlsClientHelloDecoder,
		tlsServerHelloDecoder,
		httpDecoder,
		flowDecoder,
		connDecoder,
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
	// customDecoderHandler takes a gopacket.Packet and returns a proto.Message.
	customDecoderHandler = func(p gopacket.Packet) proto.Message

	// customDecoder implements custom logic to decode data from a gopacket.Packet
	// this structure has an optimized field order to avoid excessive padding.
	customDecoder struct {

		// public fields
		Name        string
		Description string
		Icon        string

		Handler  customDecoderHandler
		postinit func(*customDecoder) error
		deinit   func(*customDecoder) error

		// used to keep track of the number of generated audit records
		numRecords int64

		writer *netcap.Writer

		Type types.Type
	}

	// CustomDecoderAPI describes an interface that all custom encoder need to implement
	// this will allow to supply a custom structure and maintain state for advanced protocol analysis.
	CustomDecoderAPI interface {
		Decode(p gopacket.Packet) error
		PostInit() error
		DeInit() error
		GetName() string
		SetWriter(*netcap.Writer)
		GetType() types.Type
		GetDescription() string
		GetChan() <-chan []byte
		Destroy() (string, int64)
		NumRecords() int64
	}
)

func (cd *customDecoder) PostInit() error {
	if cd.postinit == nil {
		return nil
	}
	return cd.postinit(cd)
}

func (cd *customDecoder) DeInit() error {
	if cd.deinit == nil {
		return nil
	}
	return cd.deinit(cd)
}

func (cd *customDecoder) GetName() string {
	return cd.Name
}

func (cd *customDecoder) SetWriter(w *netcap.Writer) {
	cd.writer = w
}

func (cd *customDecoder) GetType() types.Type {
	return cd.Type
}

func (cd *customDecoder) GetDescription() string {
	return cd.Description
}

// package level init.
func init() {
	// collect all names for custom decoders on startup
	for _, d := range defaultCustomDecoders {
		allDecoderNames[d.GetName()] = struct{}{}
	}
	// collect all names for custom decoders on startup
	for _, d := range defaultGoPacketDecoders {
		allDecoderNames[d.Layer.String()] = struct{}{}
	}
}

// InitCustomDecoders initializes all custom decoders.
func InitCustomDecoders(c *Config) (decoders []CustomDecoderAPI, err error) {
	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []CustomDecoderAPI
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

		// iterate over custom decoders and collect those that are named in the includeMap
		for _, e := range defaultCustomDecoders {
			if _, ok := inMap[e.GetName()]; ok {
				selection = append(selection, e)
			}
		}

		// update custom decoders to new selection
		defaultCustomDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" { // check if proto exists
			if _, ok := allDecoderNames[name]; !ok {
				return nil, errors.Wrap(ErrInvalidDecoder, name)
			}

			// remove named encoder from defaultCustomDecoders
			for i, e := range defaultCustomDecoders {
				if name == e.GetName() {
					// remove encoder
					defaultCustomDecoders = append(defaultCustomDecoders[:i], defaultCustomDecoders[i+1:]...)

					break
				}
			}
		}
	}

	// initialize decoders
	for _, d := range defaultCustomDecoders { // fmt.Println("init custom encoder", e.name)
		w := netcap.NewWriter(d.GetName(), c.Buffer, c.Compression, c.CSV, c.Out, c.WriteChan, c.MemBufferSize)
		d.SetWriter(w)

		// call postinit func if set
		err = d.PostInit()
		if err != nil {
			if c.IgnoreDecoderInitErrors {
				fmt.Println(ansi.Red, err, ansi.Reset)
			} else {
				return nil, errors.Wrap(err, "postinit failed")
			}
		}

		// write header
		err = w.WriteHeader(d.GetType(), c.Source, netcap.Version, c.IncludePayloads)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write header for audit record "+d.GetName())
		}

		// append to custom decoders slice
		decoders = append(decoders, d)
	}

	if isCustomDecoderLoaded(credentialsDecoderName) {
		useHarvesters = true
	}

	utils.DebugLog.Println("initialized", len(decoders), "custom decoders")

	return decoders, nil
}

func isCustomDecoderLoaded(name string) bool {
	for _, e := range defaultCustomDecoders {
		if e.GetName() == name {
			return true
		}
	}
	return false
}

// newCustomDecoder returns a new customDecoder instance.
func newCustomDecoder(t types.Type, name string, description string, postinit func(*customDecoder) error, handler customDecoderHandler, deinit func(*customDecoder) error) *customDecoder {
	return &customDecoder{
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
// and writes the serialized protobuf into the data pipe.
func (cd *customDecoder) Decode(p gopacket.Packet) error {
	// call the Handler function of the encoder
	record := cd.Handler(p)
	if record != nil {

		// increase counter
		atomic.AddInt64(&cd.numRecords, 1)

		if cd.writer.IsCSV() {
			_, err := cd.writer.WriteCSV(record)
			if err != nil {
				return err
			}
		} else {
			// write record
			err := cd.writer.WriteProto(record)
			if err != nil {
				return err
			}
		}

		// export metrics if configured
		if conf.Export {
			// assert to audit record
			if r, ok := record.(types.AuditRecord); ok {
				// export metrics
				r.Inc()
			} else {
				fmt.Printf("type: %#v\n", record)
				log.Fatal("type does not implement the types.AuditRecord interface")
			}
		}
	}

	return nil
}

// Destroy closes and flushes all writers and calls deinit if set.
func (cd *customDecoder) Destroy() (name string, size int64) {
	err := cd.DeInit()
	if err != nil {
		panic(err)
	}

	return cd.writer.Close()
}

// GetChan returns a channel to receive serialized protobuf data from the encoder.
func (cd *customDecoder) GetChan() <-chan []byte {
	return cd.writer.GetChan()
}

// NumRecords returns the number of written records.
func (cd *customDecoder) NumRecords() int64 {
	return atomic.LoadInt64(&cd.numRecords)
}
