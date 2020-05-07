package collector

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Init sets up the collector and starts the configured number of workers
// must be called prior to usage of the collector instance.
func (c *Collector) Init() (err error) {

	encoder.SetConfig(c.config.EncoderConfig)

	// start workers
	c.workers = c.initWorkers()
	utils.DebugLog.Println("spawned", c.config.Workers, "workers")

	// create full output directory path if set
	if c.config.EncoderConfig.Out != "" {
		err = os.MkdirAll(c.config.EncoderConfig.Out, c.config.OutDirPermission)
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
		encoder.LocalDNS = true
	}

	// set quiet mode for other subpackages
	encoder.Quiet = c.config.Quiet

	if logFileHandle == nil && c.config.Quiet {
		err = c.InitLogging()
		if err != nil {
			return err
		}
	}

	// check for files from previous run in the output directory
	// and ask the user if they can be overwritten
	files, _ := filepath.Glob(filepath.Join(c.config.EncoderConfig.Out, "*.ncap.gz"))
	filesBare, _ := filepath.Glob(filepath.Join(c.config.EncoderConfig.Out, "*.ncap"))

	files = append(files, filesBare...)

	streamPath := filepath.Join(c.config.EncoderConfig.Out, "tcpStreams")
	connPath := filepath.Join(c.config.EncoderConfig.Out, "tcpConnections")
	_, errStreams := os.Stat(streamPath)
	_, errConns := os.Stat(connPath)
	if len(files) > 0 || errStreams == nil || errConns == nil {

		// only prompt if quiet mode is not active
		if !c.config.Quiet {
			var msg = strconv.Itoa(len(files)) + " audit record files found in output path! Overwrite?"
			if errStreams == nil {
				msg = "Data from previous runs found in output path! Overwrite?"
			}
			if !confirm(msg) {
				return errors.New("aborted.")
			}
		}

		// clear streams if present
		if errStreams == nil || errConns == nil {
			os.RemoveAll(streamPath)
			os.RemoveAll(connPath)
		}
	}

	// initialize encoders
	encoder.InitLayerEncoders(c.config.EncoderConfig, c.config.Quiet)
	encoder.InitCustomEncoders(c.config.EncoderConfig, c.config.Quiet)

	// set pointer of collectors atomic counter map in encoder pkg
	encoder.SetErrorMap(c.errorMap)

	// create pcap files for packets
	// with unknown protocols or errors while decoding
	if err := c.createUnknownPcap(); err != nil {
		log.Fatal("failed to create pcap file for unkown packets: ", err)
	}
	if err := c.createErrorsPcap(); err != nil {
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
	c.errorLogFile, err = os.Create(filepath.Join(c.config.EncoderConfig.Out, "errors.log"))
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
