package stream

import (
	"fmt"
	"strings"
	"time"

	"github.com/mgutz/ansi"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/decoder/stream/exploit"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/decoder/stream/http"
	"github.com/dreadl0ck/netcap/decoder/stream/mail"
	"github.com/dreadl0ck/netcap/decoder/stream/pop3"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/decoder/stream/smtp"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	"github.com/dreadl0ck/netcap/decoder/stream/ssh"
	"github.com/dreadl0ck/netcap/decoder/stream/vulnerability"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	netio "github.com/dreadl0ck/netcap/io"
)

// ErrInvalidStreamDecoder occurs when a decoder name is unknown during initialization.
var ErrInvalidStreamDecoder = errors.New("invalid stream decoder")

// DefaultStreamDecoders contains stream decoders mapped to their protocols default port
// int32 is used to avoid casting when looking up values
var DefaultStreamDecoders = map[int32]decoder.StreamDecoderAPI{
	// TODO: add abstract decoders for those and make them accessible for the stream decoders
	70000: file.FileDecoder,
	70001: service.ServiceDecoder,
	70002: exploit.ExploitDecoder,
	70003: mail.MailDecoder,
	70004: software.SoftwareDecoder,
	70005: vulnerability.VulnerabilityDecoder,
	70006: credentials.CredentialsDecoder,

	80:  http.HTTPDecoder,
	110: pop3.POP3Decoder,
	22:  ssh.SSHDecoder,
	25:  smtp.SMTPDecoder,
} // contains all available stream decoders

// package level init.
func init() {
	// collect all names for stream decoders on startup
	for _, d := range DefaultStreamDecoders {
		decoderutils.AllDecoderNames[d.GetName()] = struct{}{}
	}
}

// InitDecoders initializes all stream decoders.
func InitDecoders(c *config.Config) (decoders []decoder.StreamDecoderAPI, err error) {
	var (
		// values from command-line flags
		in = strings.Split(c.IncludeDecoders, ",")
		ex = strings.Split(c.ExcludeDecoders, ",")

		// include map
		inMap = make(map[string]bool)

		// new selection
		selection = make(map[int32]decoder.StreamDecoderAPI)
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
				return nil, errors.Wrap(ErrInvalidStreamDecoder, name)
			}

			// remove named decoder from defaultPacketDecoders
			for port, dec := range DefaultStreamDecoders {
				if name == dec.GetName() {
					// remove encoder
					delete(DefaultStreamDecoders, port)

					break
				}
			}
		}
	}

	// initialize decoders
	for _, d := range DefaultStreamDecoders {
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

	if isStreamDecoderLoaded(credentials.CredentialsDecoderName) {
		credentials.UseHarvesters = true
	}

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