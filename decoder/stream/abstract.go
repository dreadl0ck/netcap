package stream

import (
	"fmt"
	"strings"
	"time"

	"github.com/mgutz/ansi"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/decoder/stream/exploit"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/decoder/stream/mail"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	"github.com/dreadl0ck/netcap/decoder/stream/vulnerability"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	netio "github.com/dreadl0ck/netcap/io"
)

// errInvalidAbstractDecoder occurs when an abstract decoder name is unknown during initialization.
var errInvalidAbstractDecoder = errors.New("invalid abstract decoder")

// defaultAbstractDecoders contains decoders for custom abstractions
// that do not represent a specific network protocol.
var defaultAbstractDecoders = []core.DecoderAPI{
	file.Decoder,
	service.Decoder,
	exploit.Decoder,
	mail.Decoder,
	software.Decoder,
	vulnerability.Decoder,
	credentials.Decoder,
} // contains all available abstract decoders

// package level init.
func init() {
	// collect all names for stream decoders on startup
	for _, d := range defaultAbstractDecoders {
		decoderutils.AllDecoderNames[d.GetName()] = struct{}{}
	}
}

// ApplyActionToAbstractDecoders can be used to run custom code for all stream decoders.
func ApplyActionToAbstractDecoders(action func(api core.DecoderAPI)) {
	for _, d := range defaultAbstractDecoders {
		action(d)
	}
}

// InitAbstractDecoders initializes all stream decoders.
func InitAbstractDecoders(c *config.Config) (decoders []core.DecoderAPI, err error) {
	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection []core.DecoderAPI
	)

	// if there are includes and the first item is not an empty string
	if len(in) > 0 && in[0] != "" { // iterate over includes
		for _, name := range in {
			if name != "" { // check if proto exists
				if _, ok := decoderutils.AllDecoderNames[name]; !ok {
					return nil, errors.Wrap(errInvalidAbstractDecoder, name)
				}

				// add to include map
				inMap[name] = true
			}
		}

		// iterate over packet decoders and collect those that are named in the includeMap
		for _, dec := range defaultAbstractDecoders {
			if _, ok := inMap[dec.GetName()]; ok {
				selection = append(selection, dec)
			}
		}

		// update packet decoders to new selection
		defaultAbstractDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" { // check if proto exists
			if _, ok := decoderutils.AllDecoderNames[name]; !ok {
				return nil, errors.Wrap(errInvalidAbstractDecoder, name)
			}

			// remove named decoder from defaultPacketDecoders
			for i, dec := range defaultAbstractDecoders {
				if name == dec.GetName() {
					// remove encoder
					defaultAbstractDecoders = append(defaultAbstractDecoders[:i], defaultAbstractDecoders[i+1:]...)

					break
				}
			}
		}
	}

	// initialize decoders
	for _, d := range defaultAbstractDecoders {
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

	if isAbstractDecoderLoaded(credentials.DecoderName) {
		credentials.UseHarvesters = true
	}

	return decoders, nil
}

// isAbstractDecoderLoaded checks if an abstract decoder is loaded.
func isAbstractDecoderLoaded(name string) bool {
	for _, e := range defaultAbstractDecoders {
		if e.GetName() == name {
			return true
		}
	}

	return false
}
