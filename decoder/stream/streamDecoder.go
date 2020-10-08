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

package stream

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/mgutz/ansi"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// ErrInvalidStreamDecoder occurs when a decoder name is unknown during initialization.
	ErrInvalidStreamDecoder = errors.New("invalid stream decoder")

	// decoders mapped to their default ports
	// int32 are used to avoid casting when looking up values
	defaultStreamDecoders = map[int32]DecoderAPI{
		// TODO: add abstract decoders for those and make them accessible for the stream decoders
		70000: fileDecoder,
		70001: serviceDecoder,
		70002: exploitDecoder,
		70003: mailDecoder,
		70004: softwareDecoder,
		70005: vulnerabilityDecoder,
		70006: credentialsDecoder,

		80:  httpDecoder,
		110: pop3Decoder,
		22:  sshDecoder,
		25:  smtpDecoder,
	} // contains all available stream decoders
)

type (
	// Decoder implements custom logic to decode data from a TCP / UDP network conversation
	// this structure has an optimized field order to avoid excessive padding.
	Decoder struct {

		// Name of the decoder
		Name string

		// Description of the decoder
		Description string

		// Icon name for the decoder (for Maltego)
		Icon string

		// init functions
		postInit func(decoder *Decoder) error
		deInit   func(decoder *Decoder) error

		// used to keep track of the number of generated audit records
		numRecords int64

		// writer for audit records
		writer netio.AuditRecordWriter

		// Type of the audit records produced by this decoder
		Type types.Type

		// canDecode checks whether the decoder can parse the protocol
		canDecode func(client []byte, server []byte) bool

		// factory for stream readers
		factory streamDecoderFactory
	}

	// DecoderAPI describes an interface that all stream decoders need to implement
	// this allows to supply a custom structure and maintain state for advanced protocol analysis.
	DecoderAPI interface {

		core.DecoderAPI

		// CanDecode determines if this decoder can understand the protocol used
		CanDecode(client []byte, server []byte) bool

		// GetReaderFactory returns a factory for processing streams of the current encoder
		GetReaderFactory() streamDecoderFactory
	}
)

// NewStreamDecoder returns a new PacketDecoder instance.
func NewStreamDecoder(
	t types.Type,
	name string,
	description string,
	postinit func(*Decoder) error,
	canDecode func(client, server []byte) bool,
	deinit func(*Decoder) error,
	factory streamDecoderFactory,
) *Decoder {
	return &Decoder{
		Name:        name,
		deInit:      deinit,
		postInit:    postinit,
		Type:        t,
		Description: description,
		canDecode:   canDecode,
		factory:     factory,
	}
}

// InitDecoders initializes all stream decoders.
func InitDecoders(c *decoder.Config) (decoders []DecoderAPI, err error) {
	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection = make(map[int32]DecoderAPI)
	)

	// if there are includes and the first item is not an empty string
	if len(in) > 0 && in[0] != "" { // iterate over includes
		for _, name := range in {
			if name != "" { // check if proto exists
				if _, ok := decoderutils.AllDecoderNames[name]; !ok {
					return nil, errors.Wrap(ErrInvalidStreamDecoder, name)
				}

				// add to include map
				inMap[name] = true
			}
		}

		// iterate over packet decoders and collect those that are named in the includeMap
		for port, dec := range defaultStreamDecoders {
			if _, ok := inMap[dec.GetName()]; ok {
				selection[port] = dec
			}
		}

		// update packet decoders to new selection
		defaultStreamDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" { // check if proto exists
			if _, ok := decoderutils.AllDecoderNames[name]; !ok {
				return nil, errors.Wrap(ErrInvalidStreamDecoder, name)
			}

			// remove named decoder from defaultPacketDecoders
			for port, dec := range defaultStreamDecoders {
				if name == dec.GetName() {
					// remove encoder
					delete(defaultStreamDecoders, port)

					break
				}
			}
		}
	}

	// initialize decoders
	for _, d := range defaultStreamDecoders {
		w := netio.NewAuditRecordWriter(&netio.WriterConfig{
			CSV:     c.CSV,
			Proto:   c.Proto,
			JSON:    c.JSON,
			Name:    d.GetName(),
			Type:    d.GetType(),
			Null:    c.Null,
			Elastic: c.Elastic,
			ElasticConfig: netio.ElasticConfig{
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

		// append to packet decoders slice
		decoders = append(decoders, d)
	}

	if isStreamDecoderLoaded(credentialsDecoderName) {
		useHarvesters = true
	}

	streamLog.Info("initialized packet decoders", zap.Int("total", len(decoders)))

	return decoders, nil
}

// StreamDecoderAPI interface implementation

// GetReaderFactory returns a new stream reader for the decoder type.
func (sd *Decoder) GetReaderFactory() streamDecoderFactory {
	return sd.factory
}

// PostInit is called after the decoder has been initialized.
func (sd *Decoder) PostInit() error {
	if sd.postInit == nil {
		return nil
	}

	return sd.postInit(sd)
}

// DeInit is called prior to teardown.
func (sd *Decoder) DeInit() error {
	if sd.deInit == nil {
		return nil
	}

	return sd.deInit(sd)
}

// GetName returns the name of the
func (sd *Decoder) GetName() string {
	return sd.Name
}

// SetWriter sets the netcap writer to use for the
func (sd *Decoder) SetWriter(w netio.AuditRecordWriter) {
	sd.writer = w
}

// GetType returns the netcap type of the
func (sd *Decoder) GetType() types.Type {
	return sd.Type
}

// GetDescription returns the description of the
func (sd *Decoder) GetDescription() string {
	return sd.Description
}

// Destroy closes and flushes all writers and calls deinit if set.
func (sd *Decoder) Destroy() (name string, size int64) {
	err := sd.DeInit()
	if err != nil {
		panic(err)
	}

	return sd.writer.Close(sd.numRecords)
}

// GetChan returns a channel to receive serialized protobuf data from the encoder.
func (sd *Decoder) GetChan() <-chan []byte {
	if cw, ok := sd.writer.(netio.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// NumRecords returns the number of written records.
func (sd *Decoder) NumRecords() int64 {
	return atomic.LoadInt64(&sd.numRecords)
}

// CanDecode invokes the canDecode function of the underlying decoder
// to determine whether the decoder can understand the protocol.
func (sd *Decoder) CanDecode(client []byte, server []byte) bool {
	return sd.canDecode(client, server)
}

/*
 * Utils
 */

// isStreamDecoderLoaded checks if an abstract decoder is loaded.
func isStreamDecoderLoaded(name string) bool {
	for _, e := range defaultStreamDecoders {
		if e.GetName() == name {
			return true
		}
	}

	return false
}
