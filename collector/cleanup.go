package collector

import (
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"log"
	"time"
)

// cleanup before leaving. closes all buffers and displays stats.
func (c *Collector) cleanup(force bool) {

	c.statMutex.Lock()
	c.shutdown = true
	c.statMutex.Unlock()

	// stop all workers.
	// this will block until all workers are stopped
	// all packets left in the packet queues will be processed
	c.stopWorkers()
	waitForCollector := func() chan struct{} {
		ch := make(chan struct{})

		go func() {
			c.statMutex.Lock()
			c.wg.Wait()
			c.statMutex.Unlock()

			ch <- struct{}{}
		}()

		return ch
	}

	c.printStdOut("\nwaiting for main collector wait group...")
	select {
	case <-waitForCollector():
		c.printlnStdOut(" done!")
	case <-time.After(netcap.DefaultReassemblyTimeout):
		c.printStdOut(" timeout after ", netcap.DefaultReassemblyTimeout)
	}

	if c.config.ReassembleConnections {
		// teardown the TCP stream reassembly and print stats
		encoder.CleanupReassembly(!force, c.assemblers)
	}

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

	resolvers.SaveFingerprintDB()

	// close the encoder logs
	utils.CloseLogFiles()

	c.mu.Lock()
	if c.isLive {
		c.statMutex.Lock()
		c.numPackets = c.current
		c.statMutex.Unlock()
	}
	c.mu.Unlock()

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

	c.printlnStdOut("execution time", time.Since(c.start))

	if logFileHandle != nil {
		err := logFileHandle.Close()
		if err != nil {
			c.printStdOut("failed to close logfile:", err)
		}
	}
}
