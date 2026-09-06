/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package collector

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/decoder/stream/alert"
	"github.com/dreadl0ck/netcap/decoder/stream/network"
	"github.com/dreadl0ck/netcap/decoder/stream/udp"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/label/manager"

	"github.com/dustin/go-humanize"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/resolvers"
)

// cleanup before leaving. closes all buffers and displays stats.
func (c *Collector) cleanup(force bool) {
	// Use sync.Once to ensure cleanup only runs once, preventing double-close of log files
	c.cleanupOnce.Do(func() {
		c.lifecycleMu.Lock()
		c.lifecycleStopped = true
		if c.runCancel != nil {
			c.runCancel()
		}
		c.lifecycleMu.Unlock()
		c.statMutex.Lock()
		c.shutdown = true
		c.statMutex.Unlock()
		c.stopWorkers()
		c.producersWG.Wait()
		c.backgroundWG.Wait()
		if c.log == nil {
			return
		}
		c.doCleanup(force)
	})
}

// doCleanup is the actual cleanup implementation, called only once by cleanupOnce
func (c *Collector) doCleanup(force bool) {
	c.log.Info("cleanup started", zap.Bool("force", force))
	c.printlnStdOut("\nworkers and capture tasks stopped, finalizing collector...")

	// Write memory stats (check if file is still open)
	if c.netcapLogFile != nil {
		_, _ = c.netcapLogFile.WriteString(newMemStats().String())
	}

	// Stop signal handler goroutines if running
	// This prevents goroutine leaks in multi-file processing mode
	if c.signalStop != nil {
		c.signalStop()
		c.signalStop = nil
	}

	// Exclude external flushes until readers are closed and references released.
	c.dispatchMu.Lock()
	if c.config.ReassembleConnections {
		// Flushes every pool, then closes and joins the stream readers.
		// Readers must finish before teardown() closes the log files.
		tcp.CleanupReassembly(!force, c.assemblers)
	}
	c.assemblers = nil

	// CRITICAL: Close and nil worker channels to allow GC
	// Worker goroutines have already exited (stopWorkers sent nil to each)
	// But the channels themselves need to be closed and nil'd
	for i := range c.workers {
		close(c.workers[i])
		c.workers[i] = nil
	}
	c.workers = nil
	c.dispatchMu.Unlock()

	c.teardown()

	// Reset package-level stream pools so a subsequent CollectPcap call in
	// the same process starts from a clean slate. Without this, tests (or
	// any library consumer) that run multiple captures back-to-back leak
	// UDP/network streams between runs, fooling per-run record counts and
	// occasionally producing records into a previous run's writer.
	// The capture binary performs the same reset between files in
	// cmd/capture/main.go.
	udp.ResetStreams()
	network.ResetStreams()
	tcp.ResetStreamFactory()
}

// FlushAssemblers synchronously flushes connections, retaining live assemblers.
// Page caches are reclaimed only when cleanup releases the stopped assemblers.
func (c *Collector) FlushAssemblers() {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	if c.workersStopped {
		c.workersWG.Wait()
		for _, asm := range c.assemblers {
			if asm != nil {
				asm.FlushAll()
			}
		}
		return
	}
	done := make([]chan struct{}, len(c.workers))
	for i, w := range c.workers {
		done[i] = make(chan struct{})
		w <- &workerControl{all: true, done: done[i]}
	}
	for _, ch := range done {
		<-ch
	}
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
		atomic.StoreInt64(&c.numPackets, atomic.LoadInt64(&c.current))
		c.statMutex.Unlock()
	}
	c.mu.Unlock()

	// sync pcap file
	if err := c.closePcapFiles(); err != nil {
		log.Fatal("failed to close pcap files: ", err)
	}

	c.closeErrorLogFile()
	c.stats()

	// Collect final performance statistics
	c.perfTracker.SetTotalPacketsAndBytes(c.numPackets, c.totalBytesWritten)

	// Update decoder metrics in performance tracker
	c.updatePerformanceTrackerWithDecoderStats()

	// Write performance report
	var perfLogPath string
	if c.config.DecoderConfig.Out != "" {
		perfLogPath = filepath.Join(c.config.DecoderConfig.Out, "performance.log")
	} else {
		perfLogPath = "performance.log"
	}
	if err := c.perfTracker.WriteReport(perfLogPath); err != nil {
		c.log.Error("failed to write performance report", zap.Error(err))
		fmt.Println("failed to write performance report:", err)
	} else {
		c.printlnStdOut("performance report written to", perfLogPath)
	}

	if c.config.DecoderConfig.Debug {
		c.printErrors()
	}

	if c.numEpochs > 1 {
		c.printlnStdOut(c.numEpochs, "/", c.Epochs, "execution time", time.Since(c.start), "total", time.Since(c.startFirst))
	} else {
		c.printlnStdOut("execution time", time.Since(c.start), c.config.DecoderConfig.Out)
	}

	c.log.Info("decoder teardown complete, closing logfiles")

	// Mark that log files are being closed to prevent double-close attempts
	if c.logFilesClosed.CompareAndSwap(false, true) {
		// sync the logs
		for _, l := range c.zapLoggers {
			err := l.Sync()
			if err != nil {
				fmt.Println("failed to sync zap logger:", err)
			}
		}

		// close the log file handles and remove empty log files
		for _, l := range c.logFileHandles {
			if l != nil {
				// Get file info before closing
				info, err := l.Stat()
				if err != nil {
					fmt.Println("failed to stat logfile:", err)
				}

				fileName := l.Name()

				err = l.Sync()
				if err != nil {
					fmt.Println("failed to sync logfile:", err)
				}
				err = l.Close()
				if err != nil {
					fmt.Println("failed to close logfile handle:", err)
				}

				// Remove log file if it's empty (similar to how audit record files are handled)
				if info != nil && info.Size() == 0 {
					err = os.Remove(fileName)
					if err != nil {
						fmt.Println("failed to remove empty log file:", fileName, err)
					}
				}
			}
		}
		c.logFileHandles = []*os.File{}
		c.zapLoggers = []*zap.Logger{}

		// Nil out the main log file pointers to prevent any further writes
		c.netcapLogFile = nil
	}

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

// updatePerformanceTrackerWithDecoderStats updates the performance tracker with final decoder statistics
func (c *Collector) updatePerformanceTrackerWithDecoderStats() {
	// Update GoPacket decoder stats
	for k, v := range c.allProtosAtomic.Snapshot() {
		if k != "Payload" {
			// Find the file size for this decoder
			var fileSize int64
			for filename := range c.files {
				if filename == k+".ncap" || filename == k+".ncap.gz" {
					// File size tracking is handled at the I/O level
					fileSize = 0
					break
				}
			}
			c.perfTracker.UpdateDecoderRecords("gopacket", k, v, fileSize)
		}
	}

	// Update packet decoder stats
	for _, d := range c.packetDecoders {
		if d.NumRecords() > 0 {
			// Try to find file size from c.files map
			var fileSize int64
			for filename := range c.files {
				if filename == d.GetName()+".ncap" || filename == d.GetName()+".ncap.gz" {
					fileSize = 0
					break
				}
			}
			c.perfTracker.UpdateDecoderRecords("custom", d.GetName(), d.NumRecords(), fileSize)
		}
	}

	// Update stream decoder stats
	for _, d := range c.streamDecoders {
		if d.NumRecords() > 0 {
			c.perfTracker.UpdateDecoderRecords("stream", d.GetName(), d.NumRecords(), 0)
		}
	}

	// Update abstract decoder stats
	for _, d := range c.abstractDecoders {
		if d.NumRecords() > 0 {
			c.perfTracker.UpdateDecoderRecords("abstract", d.GetName(), d.NumRecords(), 0)
		}
	}
}
