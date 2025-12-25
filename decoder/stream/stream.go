package stream

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/decoder"

	"github.com/dreadl0ck/netcap/decoder/stream/bacnetip"
	"github.com/dreadl0ck/netcap/decoder/stream/bgp"
	"github.com/dreadl0ck/netcap/decoder/stream/cip"
	"github.com/dreadl0ck/netcap/decoder/stream/dnp3"
	"github.com/dreadl0ck/netcap/decoder/stream/ftp"
	"github.com/dreadl0ck/netcap/decoder/stream/http"
	"github.com/dreadl0ck/netcap/decoder/stream/iec62351"
	"github.com/dreadl0ck/netcap/decoder/stream/imap"
	"github.com/dreadl0ck/netcap/decoder/stream/irc"
	"github.com/dreadl0ck/netcap/decoder/stream/modbus"
	"github.com/dreadl0ck/netcap/decoder/stream/mqttsn"
	"github.com/dreadl0ck/netcap/decoder/stream/opcua"
	"github.com/dreadl0ck/netcap/decoder/stream/pop3"
	"github.com/dreadl0ck/netcap/decoder/stream/profinet"
	"github.com/dreadl0ck/netcap/decoder/stream/quic"
	"github.com/dreadl0ck/netcap/decoder/stream/rdp"
	"github.com/dreadl0ck/netcap/decoder/stream/s7comm"
	"github.com/dreadl0ck/netcap/decoder/stream/smb"
	"github.com/dreadl0ck/netcap/decoder/stream/smtp"
	"github.com/dreadl0ck/netcap/decoder/stream/socks"
	"github.com/dreadl0ck/netcap/decoder/stream/ssh"
	"github.com/dreadl0ck/netcap/decoder/stream/syslog"
	"github.com/dreadl0ck/netcap/decoder/stream/tls"

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
// Note: Multiple decoders can share the same port if they use different transports (TCP vs UDP).
// The Transport() method is checked before CanDecode() to filter appropriately.
var DefaultStreamDecoders = map[int32]core.StreamDecoderAPI{
	21:    ftp.Decoder,
	22:    ssh.Decoder,
	25:    smtp.Decoder,
	80:    http.Decoder,
	102:   s7comm.Decoder, // S7comm ICS/SCADA (Siemens S7 PLCs)
	110:   pop3.Decoder,
	143:   imap.Decoder,
	179:   bgp.Decoder, // BGP routing protocol
	443:   tls.Decoder,
	445:   smb.Decoder,
	502:   modbus.Decoder,   // Modbus TCP ICS/SCADA
	514:   syslog.Decoder,   // Syslog (UDP/TCP)
	1080:  socks.Decoder,    // SOCKS proxy
	1883:  mqttsn.Decoder,   // MQTT-SN IoT sensor networks (UDP)
	1884:  mqttsn.Decoder,   // MQTT-SN alternate port (UDP)
	2222:  cip.Decoder,      // CIP ICS/SCADA (direct)
	3389:  rdp.Decoder,      // RDP remote desktop
	4840:  opcua.Decoder,    // OPC UA ICS/SCADA
	6667:  irc.Decoder,      // Common IRC port
	8443:  tls.Decoder,      // Common alternate HTTPS port
	20000: dnp3.Decoder,     // DNP3 ICS/SCADA
	2404:  iec62351.Decoder, // IEC 62351 security for IEC 60870-5-104
	34964: profinet.Decoder, // PROFINET IO Context Manager (DCE/RPC)
	44818: cip.Decoder,      // CIP ICS/SCADA (via EtherNet/IP)
	47808: bacnetip.Decoder, // BACnet/IP building automation (UDP port 0xBAC0)
} // contains all available stream decoders

// UDPStreamDecoders contains additional stream decoders specifically for UDP protocols.
// These are checked by the UDP stream processor when no match is found in DefaultStreamDecoders.
// This is particularly useful for protocols that share port numbers with TCP protocols
// (e.g., QUIC uses UDP port 443 while TLS uses TCP port 443).
var UDPStreamDecoders = []core.StreamDecoderAPI{
	quic.Decoder, // QUIC/HTTP3 (UDP port 443)
}

// package level init.
func init() {
	// collect all names for stream decoders on startup
	for _, d := range DefaultStreamDecoders {
		decoderutils.AllDecoderNames[d.GetName()] = struct{}{}
	}
	// also collect UDP-specific stream decoders
	for _, d := range UDPStreamDecoders {
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

		// Work with a copy of the decoders map to avoid modifying global state
		// This is important for test isolation and concurrent usage
		activeDecoders = make(map[int32]core.StreamDecoderAPI)
	)

	// Copy all default decoders to the active map
	for port, dec := range DefaultStreamDecoders {
		activeDecoders[port] = dec
	}

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

		// Filter activeDecoders to only those named in the includeMap
		selection := make(map[int32]core.StreamDecoderAPI)
		for port, dec := range activeDecoders {
			if _, ok := inMap[dec.GetName()]; ok {
				selection[port] = dec
			}
		}
		activeDecoders = selection
	}

	// iterate over excluded decoders
	for _, name := range ex {
		if name != "" { // check if proto exists
			if _, ok := decoderutils.AllDecoderNames[name]; !ok {
				return nil, errors.Wrap(errInvalidStreamDecoder, name)
			}

			// remove named decoder from activeDecoders
			for port, dec := range activeDecoders {
				if name == dec.GetName() {
					// remove decoder
					delete(activeDecoders, port)

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
	for _, d := range activeDecoders {

		// reset decoder stat in case it is reinitialized at runtime.
		d.(*decoder.StreamDecoder).NumRecordsWritten = 0

		// Log which decoders are being initialized
		log.Printf("[StreamDecoder] Initializing stream decoder: %s (type: %s)",
			d.GetName(), d.GetType())

		wg.Add(1)

		go func(dec core.StreamDecoderAPI) {
			// Use shared writer to handle the case where the same decoder is registered
			// on multiple ports (e.g., CIP on ports 2222 and 44818). This prevents race
			// conditions and ensures correct cleanup when files are shared.
			w := netio.GetSharedAuditRecordWriter(&netio.WriterConfig{
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
				PerfTracker:          c.PerfTracker,
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

			log.Printf("[StreamDecoder] Successfully initialized %s decoder (writer: %v, type: %s)",
				dec.GetName(), w != nil, dec.GetType())

			// append to packet decoders slice
			mu.Lock()
			decoders = append(decoders, dec)
			mu.Unlock()

			wg.Done()
		}(d)
	}

	wg.Wait()

	// Initialize UDP-specific stream decoders (e.g., QUIC)
	for _, d := range UDPStreamDecoders {
		// reset decoder stat in case it is reinitialized at runtime.
		d.(*decoder.StreamDecoder).NumRecordsWritten = 0

		// Log which decoders are being initialized
		log.Printf("[StreamDecoder] Initializing UDP stream decoder: %s (type: %s)",
			d.GetName(), d.GetType())

		wg.Add(1)

		go func(dec core.StreamDecoderAPI) {
			w := netio.GetSharedAuditRecordWriter(&netio.WriterConfig{
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
				PerfTracker:          c.PerfTracker,
			})
			dec.SetWriter(w)

			// call postinit func if set
			errInit := dec.PostInitFunc()
			if errInit != nil {
				if c.IgnoreDecoderInitErrors {
					fmt.Println("error while initializing", dec.GetName(), "UDP stream decoder:", ansi.Red, errInit, ansi.Reset)
				} else {
					log.Fatal(errors.Wrap(errInit, "postinit failed"))
				}
			}

			// write header
			errInit = w.WriteHeader(dec.GetType())
			if errInit != nil {
				log.Fatal(errors.Wrap(errInit, "failed to write header for audit record "+dec.GetName()))
			}

			log.Printf("[StreamDecoder] Successfully initialized %s UDP decoder (writer: %v, type: %s)",
				dec.GetName(), w != nil, dec.GetType())

			// append to decoders slice
			mu.Lock()
			decoders = append(decoders, dec)
			mu.Unlock()

			wg.Done()
		}(d)
	}

	wg.Wait()

	// Log summary of initialized decoders
	log.Printf("[StreamDecoder] Stream decoder initialization complete: %d decoders ready", len(decoders))
	for _, dec := range decoders {
		log.Printf("[StreamDecoder]   - %s (type: %s, transport: %v)",
			dec.GetName(), dec.GetType(), dec.Transport())
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
