package collector

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// Init sets up the collector and starts the configured number of workers
// must be called prior to usage of the collector instance.
func (c *Collector) Init() (err error) {
	decoder.SetConfig(c.config.DecoderConfig)

	// start workers
	c.workers = c.initWorkers()
	utils.DebugLog.Println("spawned", c.config.Workers, "workers")

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
	resolvers.Init(c.config.ResolverConfig, c.config.Quiet)

	if c.config.ResolverConfig.LocalDNS {
		decoder.LocalDNS = true
	}

	// set quiet mode for other subpackages
	if c.config.Quiet {
		c.config.DecoderConfig.Quiet = true
	}

	// init logfile if necessary
	if logFileHandle == nil && c.config.Quiet {
		err = c.InitLogging()
		if err != nil {
			return err
		}
	}

	// check for files from previous run in the output directory
	// and ask the user if they can be overwritten
	files, _ := filepath.Glob(filepath.Join(c.config.DecoderConfig.Out, "*.ncap.gz"))
	filesBare, _ := filepath.Glob(filepath.Join(c.config.DecoderConfig.Out, "*.ncap"))

	files = append(files, filesBare...)

	udpPath := filepath.Join(c.config.DecoderConfig.Out, "udpConnections")
	tcpPath := filepath.Join(c.config.DecoderConfig.Out, "tcpConnections")
	_, errStreams := os.Stat(udpPath)
	_, errConns := os.Stat(tcpPath)
	if len(files) > 0 || errStreams == nil || errConns == nil {

		// only prompt if quiet mode is not active
		if !c.config.Quiet {
			msg := strconv.Itoa(len(files)) + " audit record files found in output path! Overwrite?"
			if errStreams == nil {
				msg = "Data from previous runs found in output path! Overwrite?"
			}
			if !confirm(msg) {
				return errors.New("aborted")
			}
		}

		// wipe extracted files
		os.RemoveAll(filepath.Join(c.config.DecoderConfig.Out, "files"))

		// clear streams if present
		if errStreams == nil || errConns == nil {
			os.RemoveAll(udpPath)
			os.RemoveAll(tcpPath)
		}
	}

	c.printStdOut("initializing decoders... ")

	// initialize decoders
	c.goPacketDecoders, err = decoder.InitGoPacketDecoders(c.config.DecoderConfig)
	handleDecoderInitError(err, "gopacket")

	c.customDecoders, err = decoder.InitCustomDecoders(c.config.DecoderConfig)
	handleDecoderInitError(err, "custom")

	c.buildProgressString()
	c.printlnStdOut("done")

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

	// handle signal for a clean exit
	c.handleSignals()

	if c.config.FreeOSMem != 0 {
		fmt.Println("will free the OS memory every", c.config.FreeOSMem, "minutes")
		go c.FreeOSMemory()
	}

	// create log file
	c.mu.Lock()
	c.errorLogFile, err = os.Create(filepath.Join(c.config.DecoderConfig.Out, "errors.log"))
	c.mu.Unlock()

	return
}

// displays a prompt message to the terminal and returns a bool indicating the user decision
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

	return strings.ToLower(strings.TrimSpace(res))[0] != 'n'
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
