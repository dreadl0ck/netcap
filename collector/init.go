package collector

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/dreadl0ck/gopacket/pcap"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/mgutz/ansi"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

var errAborted = errors.New("operation aborted by user")

// Init sets up the collector and starts the configured number of workers
// must be called prior to usage of the collector instance.
func (c *Collector) Init() (err error) {

	// Catch attempts to set the timeout to 0, this is explicitly not recommended.
	// From the gopacket docs:
	//   This means that if you only capture one packet,
	//   the kernel might decide to wait 'timeout' for more packets to batch with it before returning.
	//   A timeout of 0, then, means 'wait forever for more packets', which is... not good.
	if c.config.Timeout == 0 {
		c.config.Timeout = pcap.BlockForever
	}

	// set configuration for decoder pkg
	decoder.SetConfig(c.config.DecoderConfig)

	// handle signals for a clean exit
	c.handleSignals()

	// init logfile if necessary
	if c.netcapLogFile == nil && c.config.DecoderConfig.Quiet {
		err = c.initLogging()
		if err != nil {
			return err
		}
	}

	// start workers
	c.workers = c.initWorkers()
	c.log.Info("spawned workers", zap.Int("total", c.config.Workers))

	// create full output directory path if set
	if c.config.DecoderConfig.Out != "" {
		err = os.MkdirAll(c.config.DecoderConfig.Out, c.config.OutDirPermission)
		if err != nil {
			return err
		}
	}

	// init deep packet inspection
	if c.config.DPI {
		dpi.Init()
	}

	// initialize resolvers
	resolvers.Init(c.config.ResolverConfig, c.config.DecoderConfig.Quiet)

	if c.config.ResolverConfig.LocalDNS {
		decoder.LocalDNS = true
	}

	// check for files from previous run in the output directory
	// and ask the user if they can be overwritten
	files, _ := filepath.Glob(filepath.Join(c.config.DecoderConfig.Out, "*.ncap.gz"))
	filesBare, _ := filepath.Glob(filepath.Join(c.config.DecoderConfig.Out, "*.ncap"))

	files = append(files, filesBare...)

	udpPath := filepath.Join(c.config.DecoderConfig.Out, "udp")
	tcpPath := filepath.Join(c.config.DecoderConfig.Out, "tcp")
	_, errStreams := os.Stat(udpPath)
	_, errConns := os.Stat(tcpPath)
	if len(files) > 0 || errStreams == nil || errConns == nil {

		// only prompt if quiet mode is not active AND prompting for human interaction is not disabled
		if !c.config.DecoderConfig.Quiet && !c.config.NoPrompt {
			msg := strconv.Itoa(len(files)) + " audit record files found in output path! Overwrite?"
			if errStreams == nil {
				msg = "Data from previous runs found in output path! Overwrite?"
			}

			if !confirm(msg) {
				return errAborted
			}
		}

		// wipe extracted files
		_ = os.RemoveAll(filepath.Join(c.config.DecoderConfig.Out, defaults.FileStorage))

		// clear streams if present
		if errStreams == nil || errConns == nil {
			_ = os.RemoveAll(udpPath)
			_ = os.RemoveAll(tcpPath)
		}
	}

	c.printStdOut("initializing decoders... ")
	c.netcapLog.Println("initializing decoders... ")

	if c.config.DecoderConfig.ExportMetrics {
		for i, m := range types.Metrics {
			err = prometheus.Register(m)
			if err != nil {
				spew.Dump(m)
				log.Fatal("array index:", i, ", error:", err)
			}
		}
	}

	start := time.Now()

	// initialize decoders
	c.goPacketDecoders, err = decoder.InitGoPacketDecoders(c.config.DecoderConfig)
	handleDecoderInitError(err, "gopacket")

	c.customDecoders, err = decoder.InitCustomDecoders(c.config.DecoderConfig)
	handleDecoderInitError(err, "custom")

	c.buildProgressString()
	c.printlnStdOut("done in", time.Since(start))

	// set pointer of collectors atomic counter map in encoder pkg
	decoder.SetErrorMap(c.errorMap)

	// create pcap files for packets
	// with unknown protocols or errors while decoding
	if err = c.createUnknownPcap(); err != nil {
		log.Fatal("failed to create pcap file for unknown packets: ", err)
	}

	if err = c.createErrorsPcap(); err != nil {
		log.Fatal("failed to create pcap decoding errors file: ", err)
	}

	if c.config.FreeOSMem != 0 {
		fmt.Println("will free the OS memory every", c.config.FreeOSMem, "minutes")

		go c.freeOSMemory()
	}

	return nil
}

// displays a prompt message to the terminal and returns a bool indicating the user decision.
func confirm(s string) bool {
	r := bufio.NewReader(os.Stdin)

	fmt.Printf("%s [Y/n]: ", s)

	res, err := r.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	// empty input, e.g: "\n"
	if len(res) < 2 {
		return true
	}

	trimmed := strings.TrimSpace(res)
	if len(trimmed) == 0 {
		return true
	}

	return strings.ToLower(trimmed)[0] != 'n'
}

func handleDecoderInitError(err error, target string) {
	if errors.Is(err, decoder.ErrInvalidDecoder) {
		invalidDecoder(strings.Split(errors.Unwrap(err).Error(), ":")[0])
	} else if err != nil {
		log.Fatal("failed to initialize "+target+" decoders: ", err)
	}
}

func invalidDecoder(name string) {
	fmt.Println("invalid encoder: " + ansi.Red + name + ansi.Reset)
	decoder.ShowDecoders(false)
	os.Exit(1)
}
