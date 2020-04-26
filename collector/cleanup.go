package collector

import (
	"github.com/dreadl0ck/netcap/encoder"
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

	if c.config.ReassembleConnections {
		// teardown the TCP stream reassembly and print stats
		encoder.CleanupReassembly(!force)
	}
	encoder.Cleanup()

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

	c.printStdOut("waiting for main collector wait group...")
	select {
	case <- waitForCollector():
		c.printlnStdOut(" done!")
	case <- time.After(c.config.EncoderConfig.ClosePendingTimeOut):
		c.printStdOut(" timeout after ", c.config.EncoderConfig.ClosePendingTimeOut)
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
