package collector

import (
	"fmt"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"log"
	"os"
	"path/filepath"
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
