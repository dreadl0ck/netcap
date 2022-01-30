package collector

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/io"

	"github.com/dreadl0ck/netcap/utils"

	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/gopacket/pcap"
	"github.com/mgutz/ansi"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/reassembly"
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

	// set configuration for decoder pkgs
	packet.SetConfig(c.config.DecoderConfig)

	decoderconfig.Instance = c.config.DecoderConfig
	stream.Debug = c.config.DecoderConfig.Debug
	if c.config.Labels != "" {
		io.InitLabelManager(c.config.Labels, c.config.DecoderConfig.Debug, c.config.Scatter, c.config.ScatterDuration)
	}

	// create state machine options
	tcp.StreamFactory.FSMOptions = reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: c.config.DecoderConfig.AllowMissingInit,
	}

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
		c.printlnStdOut("initializing dpi libs")
		dpi.Init()
	}

	// initialize resolvers
	resolvers.Init(c.config.ResolverConfig, c.config.DecoderConfig.Quiet)

	if c.config.ResolverConfig.LocalDNS {
		packet.LocalDNS = true
	}

	// check for files from previous run in the output directory
	// and ask the user if they can be overwritten
	var (
		// create paths
		files, _     = filepath.Glob(filepath.Join(c.config.DecoderConfig.Out, "*.ncap.gz"))
		filesBare, _ = filepath.Glob(filepath.Join(c.config.DecoderConfig.Out, "*.ncap"))
		udpPath      = filepath.Join(c.config.DecoderConfig.Out, "udp")
		tcpPath      = filepath.Join(c.config.DecoderConfig.Out, "tcp")

		// make stat syscall
		_, errStreams = os.Stat(udpPath)
		_, errConns   = os.Stat(tcpPath)
	)

	// collect files
	files = append(files, filesBare...)

	// check
	if len(files) > 0 || errStreams == nil || errConns == nil {

		// only prompt if quiet mode is not active AND prompting for human interaction is not disabled
		if !c.config.DecoderConfig.Quiet && !c.config.NoPrompt {
			msg := strconv.Itoa(len(files)) + " audit record files found in output path! Overwrite?"
			if errStreams == nil {
				msg = "Data from previous runs found in output path! Overwrite?"
			}

			if !utils.Confirm(msg) {
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

	encoder.SetConfig(&encoder.Config{
		//MinMax: true,
		ZScore: true,
		//NormalizeCategoricals: true,
	})

	var (
		start = time.Now()
		wg    sync.WaitGroup
	)

	wg.Add(4)

	go func() {
		// initialize decoders
		var errInit error
		c.goPacketDecoders, errInit = packet.InitGoPacketDecoders(c.config.DecoderConfig)
		handleDecoderInitError(errInit, "gopacket")
		wg.Done()
	}()

	go func() {
		var errInit error
		c.packetDecoders, errInit = packet.InitPacketDecoders(c.config.DecoderConfig)
		handleDecoderInitError(errInit, "packet")
		wg.Done()
	}()

	go func() {
		var errInit error
		c.streamDecoders, errInit = stream.InitDecoders(c.config.DecoderConfig)
		handleDecoderInitError(errInit, "stream")
		wg.Done()
	}()

	go func() {
		var errInit error
		c.abstractDecoders, errInit = stream.InitAbstractDecoders(c.config.DecoderConfig)
		handleDecoderInitError(errInit, "abstract")
		wg.Done()
	}()

	// set pointer of collectors atomic counter map in decoder pkg
	decoderutils.SetErrorMap(c.errorMap)

	// create pcap files for packets
	// with unknown protocols or errors while decoding
	if err = c.createUnknownPcap(); err != nil {
		log.Fatal("failed to create pcap file for unknown packets: ", err)
	}

	// create error pcap file for packets that had an error during processing
	if err = c.createErrorsPcap(); err != nil {
		log.Fatal("failed to create pcap decoding errors file: ", err)
	}

	// start routine to force releasing memory back to the OS in a fixed interval
	// this is meant for diagnostic purposes and should not be used in production
	if c.config.FreeOSMem != 0 {
		fmt.Println("will free the OS memory every", c.config.FreeOSMem, "minutes")

		go c.freeOSMemory()
	}

	// wait for decoder init to finish
	wg.Wait()
	c.log.Info("initialized decoders",
		zap.Int("packetDecoders", len(c.packetDecoders)),
		zap.Int("streamDecoders", len(c.streamDecoders)),
		zap.Int("goPacketDecoders", len(c.goPacketDecoders)),
		zap.Int("abstractDecoders", len(c.abstractDecoders)),
	)

	c.buildProgressString()
	c.printlnStdOut("done in", time.Since(start))

	return nil
}

func handleDecoderInitError(err error, target string) {
	if errors.Is(err, packet.ErrInvalidDecoder) {
		invalidDecoder(strings.Split(errors.Unwrap(err).Error(), ":")[0])
	} else if err != nil {
		log.Fatal("failed to initialize "+target+" decoders: ", err)
	}
}

func invalidDecoder(name string) {
	fmt.Println("invalid decoder: " + ansi.Red + name + ansi.Reset)
	packet.ShowDecoders(false)
	os.Exit(1)
}
