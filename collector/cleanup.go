/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package collector

import (
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/decoder/stream/alert"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/label/manager"

	"github.com/dustin/go-humanize"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/resolvers"
)

// cleanup before leaving. closes all buffers and displays stats.
func (c *Collector) cleanup(force bool) {

	if c.log == nil {
		return
	}
	c.log.Info("cleanup started", zap.Bool("force", force))
	c.printlnStdOut("\nstopping workers and waiting for collector to finish...")

	_, _ = c.netcapLogFile.WriteString(newMemStats().String())

	c.statMutex.Lock()
	c.shutdown = true
	c.statMutex.Unlock()

	// Stop all workers.
	// this will block until all workers are stopped
	// all packets left in the packet queues will be processed
	workerStop := time.Now()
	c.log.Info("stopping workers")
	c.stopWorkers()
	c.log.Info("workers completed after", zap.Duration("delta", time.Since(workerStop)))
	c.printlnStdOut("workers completed after", time.Since(workerStop))

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

	c.log.Info("waiting for main collector wait group...")
	select {
	case <-waitForCollector():
		//case <-time.After(defaults.ReassemblyTimeout):
		//	c.log.Info(" timeout after ", zap.Duration("reassemblyTimeout", defaults.ReassemblyTimeout))
	}

	if c.config.ReassembleConnections {
		// teardown the TCP stream reassembly and print stats
		tcp.CleanupReassembly(!force, c.assemblers)
	}

	c.teardown()
}

func (c *Collector) teardown() {
	c.log.Info("teardown")

	// flush all gopacket decoders
	for _, decoders := range c.goPacketDecoders {
		for _, e := range decoders {
			name, size := e.Destroy()
			if size != 0 {
				c.totalBytesWritten += size
				c.files[name] = humanize.Bytes(uint64(size))
			}
		}
	}

	// flush all custom decoders
	for _, d := range c.packetDecoders {
		name, size := d.Destroy()
		if size != 0 {
			c.totalBytesWritten += size
			c.files[name] = humanize.Bytes(uint64(size))
		}
	}

	// flush all stream decoders
	for _, d := range c.streamDecoders {
		name, size := d.Destroy()
		if size != 0 {
			c.totalBytesWritten += size
			c.files[name] = humanize.Bytes(uint64(size))
		}
	}

	// flush all abstract decoders
	for _, d := range c.abstractDecoders {
		name, size := d.Destroy()
		if size != 0 {
			c.totalBytesWritten += size
			c.files[name] = humanize.Bytes(uint64(size))
		}
	}

	if alert.SocketConn != nil {
		err := alert.SocketConn.Close()
		if err != nil {
			log.Println("failed to close alert socket", err)
		}
		c.log.Debug("closing alert socket connection", zap.Error(err))
		alert.SocketConn = nil
	}

	resolvers.SaveFingerprintDB()

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
	c.stats()

	if c.config.DecoderConfig.Debug {
		c.printErrors()
	}

	if c.numEpochs > 1 {
		c.printlnStdOut(c.numEpochs, "/", c.Epochs, "execution time", time.Since(c.start), "total", time.Since(c.startFirst))
	} else {
		c.printlnStdOut("execution time", time.Since(c.start), c.config.DecoderConfig.Out)
	}

	c.log.Info("decoder teardown complete, closing logfiles")

	// sync the logs
	for _, l := range c.zapLoggers {
		err := l.Sync()
		if err != nil {
			fmt.Println("failed to sync zap logger:", err)
		}
	}

	// close the log file handles
	for _, l := range c.logFileHandles {
		if l != nil {
			err := l.Sync()
			if err != nil {
				fmt.Println("failed to sync logfile:", err)
			}
			err = l.Close()
			if err != nil {
				fmt.Println("failed to close logfile handle:", err)
			}
		}
	}
	c.logFileHandles = []*os.File{}
	c.zapLoggers = []*zap.Logger{}

	manager.Render(c.config.DecoderConfig.Out)

	if c.Epochs > 0 && c.numEpochs < c.Epochs {

		if c.numEpochs == 1 {
			c.startFirst = c.start
		}

		// reset collector
		c.unknownProtosAtomic = decoderutils.NewAtomicCounterMap()
		c.allProtosAtomic = decoderutils.NewAtomicCounterMap()
		c.errorMap = decoderutils.NewAtomicCounterMap()
		c.files = map[string]string{}
		c.start = time.Now()
		c.abstractDecoders = nil
		c.goPacketDecoders = nil
		c.streamDecoders = nil
		c.abstractDecoders = nil
		c.packetDecoders = nil
		manager.ResetStats()

		c.statMutex.Lock()
		c.shutdown = false
		c.statMutex.Unlock()

		atomic.StoreInt64(&c.current, 0)
		atomic.StoreInt64(&c.numPackets, 0)
		atomic.StoreInt64(&c.numPacketsLast, 0)

		// increment epoch
		c.numEpochs++
		fmt.Println("================ Epoch", c.numEpochs, "/", c.Epochs, "=======================")

		// start timer
		start := time.Now()

		// ensure the logfile handle gets opened
		err := c.initLogging()
		if err != nil {
			log.Fatal("failed to open logfile:", err)
		}

		// in case a BPF should be set, the gopacket/pcap version with libpcap bindings needs to be used
		// setting BPF filters is not yet supported by the pcapgo package
		if c.Bpf != "" {
			if err = c.CollectBPF(c.InputFile, c.Bpf); err != nil {
				log.Fatal("failed to set BPF: ", err)
			}

			return
		}

		// if not, use native pcapgo version
		isPcap, err := IsPcap(c.InputFile)
		if err != nil {
			// invalid path
			fmt.Println("failed to open file:", err)
			os.Exit(1)
		}

		if isPcap {
			if err = c.CollectPcap(c.InputFile); err != nil {
				log.Fatal("failed to collect audit records from pcap file: ", err)
			}
		} else {
			if err = c.CollectPcapNG(c.InputFile); err != nil {
				log.Fatal("failed to collect audit records from pcapng file: ", err)
			}
		}

		if c.PrintTime {
			// stat input file
			stat, _ := os.Stat(c.InputFile)
			fmt.Println("size", humanize.Bytes(uint64(stat.Size())), "done in", time.Since(start), "total", time.Since(c.startFirst))
		}
	}
}

// CloseFileHandleOnShutdown allows to register file handles for close on shutdown.
func (c *Collector) CloseFileHandleOnShutdown(f *os.File) {
	c.logFileHandles = append(c.logFileHandles, f)
}
