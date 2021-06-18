package stream

import (
	"fmt"
	"github.com/dreadl0ck/netcap/decoder"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/decoder/stream/http"
	"github.com/dreadl0ck/netcap/decoder/stream/pop3"
	"github.com/dreadl0ck/netcap/decoder/stream/smtp"
	"github.com/dreadl0ck/netcap/decoder/stream/ssh"

	"github.com/mgutz/ansi"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"

	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	netio "github.com/dreadl0ck/netcap/io"
)

// errInvalidStreamDecoder occurs when a decoder name is unknown during initialization.
var errInvalidStreamDecoder = errors.New("invalid stream decoder")

// Debug controls debug log messages and behavior
var Debug bool

// DefaultStreamDecoders contains stream decoders mapped to their protocols default port
// int32 is used to avoid casting when looking up values
var DefaultStreamDecoders = map[int32]core.StreamDecoderAPI{
	80:  http.Decoder,
	110: pop3.Decoder,
	22:  ssh.Decoder,
	25:  smtp.Decoder,
} // contains all available stream decoders

// package level init.
func init() {
	// collect all names for stream decoders on startup
	for _, d := range DefaultStreamDecoders {
		decoderutils.AllDecoderNames[d.GetName()] = struct{}{}
	}
}

// ApplyActionToStreamDecoders can be used to run custom code for all stream decoders.
func ApplyActionToStreamDecoders(action func(api core.StreamDecoderAPI)) {
	for _, d := range DefaultStreamDecoders {
		action(d)
	}
}

// ApplyActionToStreamDecodersAsync can be used to run custom code for all gopacket decoders asynchronously.
func ApplyActionToStreamDecodersAsync(action func(api core.StreamDecoderAPI)) {

	// when debugging, enforce sequential processing so the logs are in order
	if Debug {
		ApplyActionToStreamDecoders(action)
		return
	}

	wg := sync.WaitGroup{}
	for _, d := range DefaultStreamDecoders {
		wg.Add(1)
		go func(d core.StreamDecoderAPI) {
			action(d)
			wg.Done()
		}(d)
	}
	wg.Wait()
}

// InitDecoders initializes all stream decoders.
func InitDecoders(c *config.Config) (decoders []core.StreamDecoderAPI, err error) {
	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection = make(map[int32]core.StreamDecoderAPI)
	)

	// if there are includes and the first item is not an empty string
	if len(in) > 0 && in[0] != "" { // iterate over includes
		for _, name := range in {
			if name != "" { // check if proto exists
				if _, ok := decoderutils.AllDecoderNames[name]; !ok {
					return nil, errors.Wrap(errInvalidStreamDecoder, name)
				}

				// add to include map
				inMap[name] = true
			}
		}

		// iterate over packet decoders and collect those that are named in the includeMap
		for port, dec := range DefaultStreamDecoders {
			if _, ok := inMap[dec.GetName()]; ok {
				selection[port] = dec
			}
		}

		// update packet decoders to new selection
		DefaultStreamDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" { // check if proto exists
			if _, ok := decoderutils.AllDecoderNames[name]; !ok {
				return nil, errors.Wrap(errInvalidStreamDecoder, name)
			}

			// remove named decoder from defaultPacketDecoders
			for port, dec := range DefaultStreamDecoders {
				if name == dec.GetName() {
					// remove decoder
					delete(DefaultStreamDecoders, port)

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
	for _, d := range DefaultStreamDecoders {

		// reset decoder stat in case it is reinitialized at runtime.
		d.(*decoder.StreamDecoder).NumRecordsWritten = 0

		wg.Add(1)

		go func(dec core.StreamDecoderAPI) {
			w := netio.NewAuditRecordWriter(&netio.WriterConfig{
				CSV:     c.CSV,
				Encode:  c.Encode,
				Label:   c.Label,
				Proto:   c.Proto,
				JSON:    c.JSON,
				Name:    dec.GetName(),
				Type:    dec.GetType(),
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
			dec.SetWriter(w)

			// call postinit func if set
			errInit := dec.PostInitFunc()
			if errInit != nil {
				if c.IgnoreDecoderInitErrors {
					fmt.Println("error while initializing", dec.GetName(), "stream decoder:", ansi.Red, errInit, ansi.Reset)
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

	// TODO: log to decoderLog

	return decoders, nil
}

// isStreamDecoderLoaded checks if an abstract decoder is loaded.
func isStreamDecoderLoaded(name string) bool {
	for _, e := range DefaultStreamDecoders {
		if e.GetName() == name {
			return true
		}
	}

	return false
}
