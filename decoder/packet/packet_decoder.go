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

package packet

import (
	"fmt"
	"go.uber.org/zap"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"
	"github.com/pkg/errors"
)

var conf *config.Config

// SetConfig can be used to set a configuration for the package.
func SetConfig(cfg *config.Config) {
	conf = cfg
}

var (
	// ErrInvalidDecoder occurs when a decoder name is unknown during initialization.
	ErrInvalidDecoder = errors.New("invalid decoder")

	// contains all available custom decoders at runtime
	defaultPacketDecoders []DecoderAPI
)

type (
	// packetDecoderHandler takes a gopacket.Packet and returns a proto.Message.
	packetDecoderHandler = func(p gopacket.Packet) proto.Message

	// Decoder implements custom logic to decode data from a gopacket.Packet
	// this structure has an optimized field order to avoid excessive padding.
	Decoder struct {

		// used to keep track of the number of generated audit records
		NumRecordsWritten int64

		// Name of the decoder
		Name string

		// Description of the decoder
		Description string

		// Icon name for the decoder (for Maltego)
		Icon string

		// Handler to process packets
		Handler packetDecoderHandler

		// init functions
		PostInit func(*Decoder) error
		DeInit   func(*Decoder) error

		// Writer for audit records
		Writer io.AuditRecordWriter

		// Type of the audit records produced by this decoder
		Type types.Type
	}

	// DecoderAPI PacketDecoderAPI describes an interface that all custom decoders need to implement
	// this allows to supply a custom structure and maintain state for advanced protocol analysis.
	DecoderAPI interface {
		core.DecoderAPI

		// Decode parses a gopacket and returns an error
		Decode(p gopacket.Packet) error
	}
)

// package level init.
func init() {
	// collect all names for packet decoders on startup
	for _, d := range defaultPacketDecoders {
		decoderutils.AllDecoderNames[d.GetName()] = struct{}{}
	}
	// collect all names for gopacket decoders on startup
	for _, d := range defaultGoPacketDecoders {
		decoderutils.AllDecoderNames[d.Layer.String()] = struct{}{}
	}
}

// newPacketDecoder returns a new Decoder instance.
func newPacketDecoder(t types.Type, name, description string, postinit func(*Decoder) error, handler packetDecoderHandler, deinit func(*Decoder) error) *Decoder {
	d := &Decoder{
		Name:        strings.Title(name),
		Handler:     handler,
		DeInit:      deinit,
		PostInit:    postinit,
		Type:        t,
		Description: description,
	}
	defaultPacketDecoders = append(defaultPacketDecoders, d)
	return d
}

// InitPacketDecoders initializes all packet decoders.
func InitPacketDecoders(c *config.Config) (decoders []DecoderAPI, err error) {
	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []DecoderAPI
	)

	// if there are includes and the first item is not an empty string
	if len(in) > 0 && in[0] != "" { // iterate over includes
		for _, name := range in {
			if name != "" { // check if proto exists
				if _, ok := decoderutils.AllDecoderNames[name]; !ok {
					return nil, errors.Wrap(ErrInvalidDecoder, name)
				}

				// add to include map
				inMap[name] = true
			}
		}

		// iterate over packet decoders and collect those that are named in the includeMap
		for _, e := range defaultPacketDecoders {
			if _, ok := inMap[e.GetName()]; ok {
				selection = append(selection, e)
			}
		}

		// update packet decoders to new selection
		defaultPacketDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" { // check if proto exists
			if _, ok := decoderutils.AllDecoderNames[name]; !ok {
				return nil, errors.Wrap(ErrInvalidDecoder, name)
			}

			// remove named decoder from defaultPacketDecoders
			for i, e := range defaultPacketDecoders {
				if name == e.GetName() {
					// remove decoder
					defaultPacketDecoders = append(defaultPacketDecoders[:i], defaultPacketDecoders[i+1:]...)

					break
				}
			}
		}
	}

	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)

	// initialize decoders
	for _, d := range defaultPacketDecoders {

		// reset decoder stat in case it is reinitialized at runtime.
		d.(*Decoder).NumRecordsWritten = 0

		wg.Add(1)

		go func(dec DecoderAPI) {
			w := io.NewAuditRecordWriter(&io.WriterConfig{
				UnixSocket: c.UnixSocket,
				CSV:        c.CSV,
				Label:      c.Label,
				Encode:     c.Encode,
				Proto:      c.Proto,
				JSON:       c.JSON,
				Name:       dec.GetName(),
				Type:       dec.GetType(),
				Null:       c.Null,
				Elastic:    c.Elastic,
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
			dec.SetWriter(w)

			// call postinit func if set
			errInit := dec.PostInitFunc()
			if errInit != nil {
				if c.IgnoreDecoderInitErrors {
					fmt.Println("error while initializing", dec.GetName(), "packet decoder:", ansi.Red, errInit, ansi.Reset)
				} else {
					log.Fatal(errors.Wrap(errInit, "postinit failed"))
				}
			}

			// write header
			errInit = w.WriteHeader(dec.GetType())
			if errInit != nil {
				log.Fatal(errors.Wrap(errInit, "failed to write header for audit record "+dec.GetName()))
			}

			// append to packet decoders slice
			mu.Lock()
			decoders = append(decoders, dec)
			mu.Unlock()

			wg.Done()
		}(d)
	}

	wg.Wait()
	decoderLog.Info("initialized packet decoders", zap.Int("total", len(decoders)))

	return decoders, nil
}

// PacketDecoderAPI interface implementation

// PostInitFunc is called after the decoder has been initialized.
func (pd *Decoder) PostInitFunc() error {
	if pd.PostInit == nil {
		return nil
	}

	return pd.PostInit(pd)
}

// DeInitFunc is called prior to teardown.
func (pd *Decoder) DeInitFunc() error {
	if pd.DeInit == nil {
		return nil
	}

	return pd.DeInit(pd)
}

// GetName returns the name of the decoder.
func (pd *Decoder) GetName() string {
	return strings.Title(pd.Name)
}

// SetWriter sets the netcap writer to use for the decoder.
func (pd *Decoder) SetWriter(w io.AuditRecordWriter) {
	pd.Writer = w
}

// GetType returns the netcap type of the decoder.
func (pd *Decoder) GetType() types.Type {
	return pd.Type
}

// GetDescription returns the description of the decoder.
func (pd *Decoder) GetDescription() string {
	return pd.Description
}

// Decode is called for each layer
// this calls the handler function of the decoder
// and writes the serialized protobuf into the data pipe.
func (pd *Decoder) Decode(p gopacket.Packet) error {
	// call the Handler function of the decoder
	record := pd.Handler(p)
	if record != nil {

		// increase counter
		atomic.AddInt64(&pd.NumRecordsWritten, 1)

		err := pd.Writer.Write(record)
		if err != nil {
			return err
		}

		// export metrics if configured
		if conf.ExportMetrics {
			// assert to audit record
			if r, ok := record.(types.AuditRecord); ok {

				if conf.Debug {
					defer func() {
						if errRecover := recover(); errRecover != nil {
							spew.Dump(r)
							fmt.Println("recovered from panic", errRecover)
						}
					}()
				}

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
func (pd *Decoder) Destroy() (name string, size int64) {
	err := pd.DeInitFunc()
	if err != nil {
		panic(err)
	}

	return pd.Writer.Close(pd.NumRecordsWritten)
}

// GetChan returns a channel to receive serialized protobuf data from the decoder.
func (pd *Decoder) GetChan() <-chan []byte {
	if cw, ok := pd.Writer.(io.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// NumRecords returns the number of written records.
func (pd *Decoder) NumRecords() int64 {
	return atomic.LoadInt64(&pd.NumRecordsWritten)
}

// writeDeviceProfile writes the profile.
func (pd *Decoder) write(r types.AuditRecord) {
	if conf.ExportMetrics {

		if conf.Debug {
			defer func() {
				if errRecover := recover(); errRecover != nil {
					spew.Dump(r)
					fmt.Println("recovered from panic", errRecover)
				}
			}()
		}

		r.Inc()
	}

	atomic.AddInt64(&pd.NumRecordsWritten, 1)
	err := pd.Writer.Write(r.(proto.Message))
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}

/*
 * Utils
 */

// isPacketDecoderLoaded checks if a decoder is loaded.
func isPacketDecoderLoaded(name string) bool {
	for _, e := range defaultPacketDecoders {
		if e.GetName() == name {
			return true
		}
	}

	return false
}
