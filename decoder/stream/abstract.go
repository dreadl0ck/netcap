package stream

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/decoder"

	"github.com/dreadl0ck/netcap/decoder/stream/alert"
	"github.com/dreadl0ck/netcap/decoder/stream/exploit"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/decoder/stream/mail"
	"github.com/dreadl0ck/netcap/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	"github.com/dreadl0ck/netcap/decoder/stream/tls"
	"github.com/dreadl0ck/netcap/decoder/stream/vulnerability"

	"github.com/mgutz/ansi"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"

	//"github.com/dreadl0ck/netcap/decoder/stream/secret"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	netio "github.com/dreadl0ck/netcap/io"
)

// errInvalidAbstractDecoder occurs when an abstract decoder name is unknown during initialization.
var errInvalidAbstractDecoder = errors.New("invalid abstract decoder")

// DefaultAbstractDecoders contains decoders for custom abstractions
// that do not represent a specific network protocol.
var DefaultAbstractDecoders = []core.DecoderAPI{
	file.Decoder,
	service.Decoder,
	exploit.Decoder,
	mail.Decoder,
	software.Decoder,
	vulnerability.Decoder,
	secret.Decoder,
	alert.Decoder,
	tls.RecordDecoder,
} // contains all available abstract decoders

// package level init.
func init() {
	// collect all names for stream decoders on startup
	for _, d := range DefaultAbstractDecoders {
		decoderutils.AllDecoderNames[d.GetName()] = struct{}{}
	}
}

// ApplyActionToAbstractDecoders can be used to run custom code for all stream decoders.
func ApplyActionToAbstractDecoders(action func(api core.DecoderAPI)) {
	for _, d := range DefaultAbstractDecoders {
		action(d)
	}
}

// ApplyActionToAbstractDecodersAsync can be used to run custom code for all gopacket decoders asynchronously.
func ApplyActionToAbstractDecodersAsync(action func(api core.DecoderAPI)) {

	// when debugging, enforce sequential processing so the logs are in order
	if Debug {
		ApplyActionToAbstractDecoders(action)
		return
	}

	wg := sync.WaitGroup{}
	for _, d := range DefaultAbstractDecoders {
		wg.Add(1)
		go func(d core.DecoderAPI) {
			action(d)
			wg.Done()
		}(d)
	}
	wg.Wait()
}

// InitAbstractDecoders initializes all stream decoders.
func InitAbstractDecoders(c *config.Config) (decoders []core.DecoderAPI, err error) {
	tls.RecordDecoder.Writer = nil
	active, err := decoderutils.SelectDecoders(DefaultAbstractDecoders, c.IncludeDecoders, c.ExcludeDecoders, core.DecoderAPI.GetName, errInvalidAbstractDecoder)
	if err != nil {
		return nil, err
	}

	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)

	// initialize decoders
	for _, d := range active {

		// reset decoder stat in case it is reinitialized at runtime.
		d.(*decoder.AbstractDecoder).NumRecordsWritten = 0

		wg.Add(1)

		func(d core.DecoderAPI) {
			w := netio.NewAuditRecordWriter(&netio.WriterConfig{
				CSV:     c.CSV,
				Encode:  c.Encode,
				Label:   c.Label,
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
				PerfTracker:          c.PerfTracker,
				LabelManager:         c.LabelManager,
			})
			d.SetWriter(w)

			// call postinit func if set
			err = d.PostInitFunc()
			if err != nil {
				if c.IgnoreDecoderInitErrors {
					fmt.Println("error while initializing", d.GetName(), "abstract decoder:", ansi.Red, err, ansi.Reset)
				} else {
					log.Fatal(errors.Wrap(err, "postinit failed"))
				}
			}

			// write header
			err = w.WriteHeader(d.GetType())
			if err != nil {
				log.Fatal(errors.Wrap(err, "failed to write header for audit record "+d.GetName()))
			}

			// append to packet decoders slice
			mu.Lock()
			decoders = append(decoders, d)
			mu.Unlock()

			wg.Done()
		}(d)
	}

	wg.Wait()

	// TODO: log to decoderLog

	return decoders, nil
}

// isAbstractDecoderLoaded checks if an abstract decoder is loaded.
//func isAbstractDecoderLoaded(name string) bool {
//	for _, e := range defaultAbstractDecoders {
//		if e.GetName() == name {
//			return true
//		}
//	}
//
//	return false
//}
