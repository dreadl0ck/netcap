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

// Package packet Package decoder implements decoders to transform network packets into protocol buffers for various protocols
package packet

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder/config"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// contains all available gopacket decoders.
var defaultGoPacketDecoders []*GoPacketDecoder

type (
	// goPacketDecoderHandler is the handler function for a layer decoder.
	goPacketDecoderHandler = func(layer gopacket.Layer, timestamp int64) proto.Message

	// GoPacketDecoder represents an decoder for the gopacket.Layer type
	// this structure has an optimized field order to avoid excessive padding.
	GoPacketDecoder struct {
		// used to keep track of the number of generated audit records
		numRecords  int64
		Description string
		Layer       gopacket.LayerType
		Handler     goPacketDecoderHandler

		writer io.AuditRecordWriter
		Type   types.Type
		export bool
	}
)

func (dec *GoPacketDecoder) PostInitFunc() error {
	return nil
}

func (dec *GoPacketDecoder) DeInitFunc() error {
	return nil
}

func (dec *GoPacketDecoder) GetName() string {
	return dec.Type.String()
}

func (dec *GoPacketDecoder) SetWriter(writer io.AuditRecordWriter) {
	dec.writer = writer
}

func (dec *GoPacketDecoder) GetType() types.Type {
	return dec.Type
}

func (dec *GoPacketDecoder) GetDescription() string {
	return dec.Description
}

func (dec *GoPacketDecoder) NumRecords() int64 {
	return dec.numRecords
}

// InitGoPacketDecoders initializes all gopacket decoders.
func InitGoPacketDecoders(c *config.Config) (decoders map[gopacket.LayerType][]*GoPacketDecoder, err error) {
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
				if _, ok := decoderutils.AllDecoderNames[name]; !ok {
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
			if _, ok := decoderutils.AllDecoderNames[name]; !ok {
				return nil, errors.Wrap(ErrInvalidDecoder, name)
			}

			// remove named decoder from defaultGoPacketDecoders
			for i, e := range defaultGoPacketDecoders {
				if name == e.Layer.String() {
					// remove decoder
					defaultGoPacketDecoders = append(defaultGoPacketDecoders[:i], defaultGoPacketDecoders[i+1:]...)
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
	for _, e := range defaultGoPacketDecoders { // fmt.Println("init", e.Layer)

		// reset decoder stat in case it is reinitialized at runtime.
		e.numRecords = 0

		wg.Add(1)

		go func(dec *GoPacketDecoder) {
			filename := dec.Layer.String()

			// handle inconsistencies in gopacket naming convention
			// TODO: fix in gopacket and refactor the packet decoders to map to a single decoder instead of an array again
			switch dec.Type {
			case types.Type_NC_OSPFv2:
				filename = "OSPFv2"
			case types.Type_NC_OSPFv3:
				filename = "OSPFv3"
			case types.Type_NC_ENIP:
				filename = "ENIP"
			}

			// hookup writer
			dec.writer = io.NewAuditRecordWriter(&io.WriterConfig{
				UnixSocket: c.UnixSocket,
				CSV:        c.CSV,
				Encode:     c.Encode,
				Label:      c.Label,
				Proto:      c.Proto,
				JSON:       c.JSON,
				Chan:       c.Chan,
				Null:       c.Null,
				Elastic:    c.Elastic,
				ElasticConfig: io.ElasticConfig{
					ElasticAddrs:   c.ElasticAddrs,
					ElasticUser:    c.ElasticUser,
					ElasticPass:    c.ElasticPass,
					KibanaEndpoint: c.KibanaEndpoint,
					BulkSize:       c.BulkSizeGoPacket,
				},
				Name:                 filename,
				Buffer:               c.Buffer,
				Compress:             c.Compression,
				Out:                  c.Out,
				MemBufferSize:        c.MemBufferSize,
				Source:               c.Source,
				Version:              netcap.Version,
				IncludesPayloads:     c.IncludePayloads,
				StartTime:            time.Now(),
				CompressionBlockSize: c.CompressionBlockSize,
				CompressionLevel:     c.CompressionLevel,
			})

			// write netcap header
			errInit := dec.writer.WriteHeader(dec.Type)
			if errInit != nil {
				log.Fatal(errors.Wrap(errInit, "failed to write header for audit record "+dec.Type.String()))
			}

			// export metrics?
			dec.export = c.ExportMetrics

			// add to gopacket decoders map
			mu.Lock()
			decoders[dec.Layer] = append(decoders[dec.Layer], dec)
			mu.Unlock()

			wg.Done()
		}(e)
	}

	wg.Wait()
	decoderLog.Info("initialized gopacket decoders", zap.Int("total", len(decoders)))

	return decoders, nil
}

// newGoPacketDecoder returns a new GoPacketDecoder instance and registers it.
func newGoPacketDecoder(nt types.Type, lt gopacket.LayerType, description string, handler goPacketDecoderHandler) *GoPacketDecoder {
	d := &GoPacketDecoder{
		Layer:       lt,
		Handler:     handler,
		Type:        nt,
		Description: description,
	}
	defaultGoPacketDecoders = append(defaultGoPacketDecoders, d)
	return d
}

// Decode is called for each layer
// this calls the handler function of the decoder
// and writes the serialized protobuf into the data pipe.
func (dec *GoPacketDecoder) Decode(ctx *types.PacketContext, p gopacket.Packet, l gopacket.Layer) error {
	record := dec.Handler(l, p.Metadata().Timestamp.UnixNano())
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

		atomic.AddInt64(&dec.numRecords, 1)
		err := dec.writer.Write(record)
		if err != nil {
			return err
		}

		// export metrics if configured
		if dec.export {
			// assert to audit record
			if auditRecord, ok := record.(types.AuditRecord); ok {

				if conf.Debug {
					defer func() {
						if r := recover(); r != nil {
							spew.Dump(auditRecord)
							fmt.Println("recovered from panic", r)
						}
					}()
				}

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

// GetChan returns a channel to receive serialized protobuf data from the decoder.
func (cd *GoPacketDecoder) GetChan() <-chan []byte {
	if cw, ok := cd.writer.(io.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// Destroy closes and flushes all writers.
func (dec *GoPacketDecoder) Destroy() (name string, size int64) {
	return dec.writer.Close(atomic.LoadInt64(&dec.numRecords))
}
