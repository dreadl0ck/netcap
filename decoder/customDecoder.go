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
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

var (
	// ErrInvalidDecoder occurs when a decoder name is unknown during initialization.
	ErrInvalidDecoder = errors.New("invalid decoder")

	defaultCustomDecoders = []CustomDecoderAPI{
		tlsClientHelloDecoder,
		tlsServerHelloDecoder,
		httpDecoder,
		flowDecoder,
		connDecoder,
		deviceProfileDecoder,
		ipProfileDecoder,
		fileDecoder,
		pop3Decoder,
		softwareDecoder,
		serviceDecoder,
		credentialsDecoder,
		sshDecoder,
		vulnerabilityDecoder,
		exploitDecoder,
		mailDecoder,
	} // contains all available custom decoders
)

type (
	// customDecoderHandler takes a gopacket.Packet and returns a proto.Message.
	customDecoderHandler = func(p gopacket.Packet) proto.Message

	// customDecoder implements custom logic to decode data from a gopacket.Packet
	// this structure has an optimized field order to avoid excessive padding.
	customDecoder struct {

		// Name of the decoder
		Name string

		// Description of the decoder
		Description string

		// Icon name for the decoder (for Maltego)
		Icon string

		// Handler to process packets
		Handler customDecoderHandler

		// init functions
		postInit func(*customDecoder) error
		deInit   func(*customDecoder) error

		// used to keep track of the number of generated audit records
		numRecords int64

		// writer for audit records
		writer io.AuditRecordWriter

		// Type of the audit records produced by this decoder
		Type types.Type
	}

	// CustomDecoderAPI describes an interface that all custom encoder need to implement
	// this allows to supply a custom structure and maintain state for advanced protocol analysis.
	CustomDecoderAPI interface {

		// Decode parses a gopacket and returns an error
		Decode(p gopacket.Packet) error

		// PostInit is called after the decoder has been initialized
		PostInit() error

		// DeInit is called prior to teardown
		DeInit() error

		// GetName returns the name of the decoder
		GetName() string

		// SetWriter sets the netcap writer to use for the decoder
		SetWriter(io.AuditRecordWriter)

		// GetType returns the netcap type of the decoder
		GetType() types.Type

		// GetDescription returns the description of the decoder
		GetDescription() string

		// GetChan returns a channel to receive serialized audit records from the decoder
		GetChan() <-chan []byte

		// Destroy initiates teardown
		Destroy() (string, int64)

		// NumRecords returns the number of processed audit records
		NumRecords() int64
	}
)

// PostInit is called after the decoder has been initialized.
func (cd *customDecoder) PostInit() error {
	if cd.postInit == nil {
		return nil
	}

	return cd.postInit(cd)
}

// DeInit is called prior to teardown.
func (cd *customDecoder) DeInit() error {
	if cd.deInit == nil {
		return nil
	}

	return cd.deInit(cd)
}

// GetName returns the name of the decoder.
func (cd *customDecoder) GetName() string {
	return cd.Name
}

// SetWriter sets the netcap writer to use for the decoder.
func (cd *customDecoder) SetWriter(w io.AuditRecordWriter) {
	cd.writer = w
}

// GetType returns the netcap type of the decoder.
func (cd *customDecoder) GetType() types.Type {
	return cd.Type
}

// GetDescription returns the description of the decoder.
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
	for _, d := range defaultCustomDecoders {
		w := io.NewAuditRecordWriter(&io.WriterConfig{
			CSV:     c.CSV,
			Proto:   c.Proto,
			JSON:    c.JSON,
			Name:    d.GetName(),
			Type:    d.GetType(),
			Null:    c.Null,
			Elastic: c.Elastic,
			ElasticConfig: io.ElasticConfig{
				ElasticAddrs:   c.ElasticAddrs,
				ElasticUser:    c.ElasticUser,
				ElasticPass:    c.ElasticPass,
				KibanaEndpoint: c.KibanaEndpoint,
				BulkSize:       c.BulkSizeCustom,
			},
			Buffer:               c.Buffer,
			Compress:             c.Compression,
			Out:                  c.Out,
			Chan:                 c.Chan,
			ChanSize:             c.ChanSize,
			MemBufferSize:        c.MemBufferSize,
			Source:               c.Source,
			Version:              netcap.Version,
			IncludesPayloads:     c.IncludePayloads,
			StartTime:            time.Now(),
			CompressionBlockSize: c.CompressionBlockSize,
			CompressionLevel:     c.CompressionLevel,
		})
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
		err = w.WriteHeader(d.GetType())
		if err != nil {
			return nil, errors.Wrap(err, "failed to write header for audit record "+d.GetName())
		}

		// append to custom decoders slice
		decoders = append(decoders, d)
	}

	if isCustomDecoderLoaded(credentialsDecoderName) {
		useHarvesters = true
	}

	decoderLog.Info("initialized custom decoders", zap.Int("total", len(decoders)))

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
func newCustomDecoder(t types.Type, name, description string, postinit func(*customDecoder) error, handler customDecoderHandler, deinit func(*customDecoder) error) *customDecoder {
	return &customDecoder{
		Name:        name,
		Handler:     handler,
		deInit:      deinit,
		postInit:    postinit,
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

		err := cd.writer.Write(record)
		if err != nil {
			return err
		}

		// export metrics if configured
		if conf.ExportMetrics {
			// assert to audit record
			if r, ok := record.(types.AuditRecord); ok {

				// TODO: remove for production builds?
				defer func() {
					if errRecover := recover(); errRecover != nil {
						spew.Dump(r)
						fmt.Println("recovered from panic", errRecover)
					}
				}()

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
	if cw, ok := cd.writer.(io.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// NumRecords returns the number of written records.
func (cd *customDecoder) NumRecords() int64 {
	return atomic.LoadInt64(&cd.numRecords)
}
