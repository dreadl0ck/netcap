package collector

import (
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dustin/go-humanize"
	"log"
)

// cleanup before leaving. closes all buffers and displays stats.
func (c *Collector) cleanup(force bool) {

	// stop all workers.
	// this will block until all workers are stopped
	// all packets left in the packet queues will be processed
	c.stopWorkers()

	if c.config.ReassembleConnections {
		// teardown the TCP stream reassembly and print stats
		encoder.CleanupReassembly(!force)
	}
	encoder.Cleanup()

	c.printlnStdOut("waiting for main collector wait group")
	c.statMutex.Lock()
	c.wg.Wait()
	c.statMutex.Unlock()

	// flush all layer encoders
	for _, encoders := range encoder.LayerEncoders {
		for _, e := range encoders {
			name, size := e.Destroy()
			if size != 0 {
				c.totalBytesWritten += size
				c.files[name] = humanize.Bytes(uint64(size))
			}
		}
	}

	// flush all custom encoders
	for _, e := range encoder.CustomEncoders {
		name, size := e.Destroy()
		if size != 0 {
			c.totalBytesWritten += size
			c.files[name] = humanize.Bytes(uint64(size))
		}
	}

	if c.isLive {
		c.statMutex.Lock()
		c.numPackets = c.current
		c.statMutex.Unlock()
	}

	// sync pcap file
	if err := c.closePcapFiles(); err != nil {
		log.Fatal("failed to close pcap files: ", err)
	}

	c.closeErrorLogFile()
	c.Stats()

	// encoder.DumpTop5LinkFlows()
	// encoder.DumpTop5NetworkFlows()
	// encoder.DumpTop5TransportFlows()

	if c.config.EncoderConfig.Debug {
		c.printErrors()
	}

	if logFileHandle != nil {
		err := logFileHandle.Close()
		if err != nil {
			c.printStdOut("failed to close logfile:", err)
		}
	}
}
