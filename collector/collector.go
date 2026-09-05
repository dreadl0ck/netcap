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

// Package collector provides a mechanism to collect network packets from a network interface on macOS, linux and windows
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/table"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/decoder/stream/udp"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/internal/performance"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/label/manager"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// errInvalidOutputDirectory indicates that a file path was supplied instead of a directory.
var errInvalidOutputDirectory = errors.New("expected a directory, but got a file for output path")

// headerPrinted tracks whether the netcap header has been printed to prevent duplicate headers
// when processing multiple input files
var (
	headerPrinted     bool
	headerPrintedLock sync.Mutex
)

// Collector provides an interface to collect data from PCAP or a network interface.
// this structure has an optimized field order to avoid excessive padding.
type Collector struct {
	mu                sync.Mutex
	statMutex         sync.Mutex
	current           int64
	numPacketsLast    int64
	totalBytesWritten int64
	numPackets        int64
	numWorkers        int
	workers           []chan gopacket.Packet
	start             time.Time

	// when running multiple epochs, the timestamp of the first run can be preserved.
	startFirst               time.Time
	assemblers               []*reassembly.Assembler
	goPacketDecoders         map[gopacket.LayerType][]*packet.GoPacketDecoder
	packetDecoders           []packet.DecoderAPI
	streamDecoders           []core.StreamDecoderAPI
	abstractDecoders         []core.DecoderAPI
	progressString           string
	next                     atomic.Int64
	unkownPcapWriterAtomic   *atomicPcapGoWriter
	unknownPcapFile          *os.File
	errorsPcapWriterBuffered *bufio.Writer
	errorsPcapWriterAtomic   *atomicPcapGoWriter
	errorsPcapFile           *os.File
	errorLogFile             *os.File
	unknownProtosAtomic      *decoderutils.AtomicCounterMap
	allProtosAtomic          *decoderutils.AtomicCounterMap
	files                    map[string]string
	inputSize                int64
	unkownPcapWriterBuffered *bufio.Writer
	config                   *Config
	errorMap                 *decoderutils.AtomicCounterMap
	wg                       sync.WaitGroup
	shutdown                 bool
	isLive                   bool
	cleanupOnce              sync.Once          // ensure cleanup only runs once
	logFilesClosed           atomic.Bool        // track if log files have been closed
	freeOSMemCancel          context.CancelFunc // cancel function for freeOSMemory goroutine
	signalChan               chan os.Signal     // signal channel for cleanup
	signalStop               func()             // function to stop signal handling and cleanup goroutines

	// logging
	log           *zap.Logger // collector.log
	netcapLog     *log.Logger // netcap.log
	netcapLogFile *os.File

	zapLoggers      []*zap.Logger
	logFileHandles  []*os.File
	atomicLogLevels []*zap.AtomicLevel // atomic levels for runtime log level changes

	InputFile string
	PrintTime bool
	Bpf       string

	Epochs    int
	numEpochs int

	// throughput measurements in timestamps mapped to packets per second values
	pps map[time.Time]float64

	// interval for tracking collector stats
	statsInterval time.Duration

	// performance tracker
	perfTracker *performance.Tracker

	// filtering and rules
	filterPrograms map[types.Type]*filter.CompiledFilter
	rulesEngine    *rules.Engine
	filteredCount  int64
	alertCount     int64
}

// GetTotalBytesWritten returns the total bytes written to disk.
func (c *Collector) GetTotalBytesWritten() int64 {
	c.statMutex.Lock()
	defer c.statMutex.Unlock()
	return c.totalBytesWritten
}

// SetFilterExpression sets a filter expression for a specific record type.
func (c *Collector) SetFilterExpression(expression string, recordType types.Type) error {
	if c.filterPrograms == nil {
		c.filterPrograms = make(map[types.Type]*filter.CompiledFilter)
	}

	program, err := filter.CompileExpression(expression, recordType)
	if err != nil {
		return fmt.Errorf("failed to compile filter for %s: %w", recordType.String(), err)
	}

	c.filterPrograms[recordType] = &filter.CompiledFilter{
		Program:    program,
		RecordType: recordType,
		Expression: expression,
	}

	c.log.Info("compiled filter expression", zap.String("type", recordType.String()), zap.String("expression", expression))
	return nil
}

// SetRulesEngine sets the rules engine for alert generation.
func (c *Collector) SetRulesEngine(engine *rules.Engine) {
	c.rulesEngine = engine
	// Connect the performance tracker to the rules engine
	if c.perfTracker != nil {
		engine.SetPerformanceTracker(c.perfTracker)
	}
	// c.log may not be initialized yet: SetRulesEngine can be called before
	// the collector's logger is set up during Init(). Guard against a nil
	// logger to avoid a panic on the CLI `net capture -rules ...` path.
	if c.log != nil {
		c.log.Info("rules engine enabled")
	}
}

// ReloadRulesEngine reloads the rules engine configuration from disk.
// This is used when rules are updated via the webUI at runtime.
func (c *Collector) ReloadRulesEngine() error {
	if c.rulesEngine == nil {
		return nil // No rules engine to reload
	}

	// Get the rules folder path - use output directory
	rulesFolder := filepath.Join(c.config.DecoderConfig.Out, "rules")

	// Load all rule files from the rules folder
	config := &rules.Config{
		Rules: make([]*rules.Rule, 0),
	}

	entries, err := os.ReadDir(rulesFolder)
	if err != nil {
		return fmt.Errorf("failed to read rules folder: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		filePath := filepath.Join(rulesFolder, entry.Name())
		fileConfig, err := rules.LoadRulesFromFile(filePath)
		if err != nil {
			c.log.Warn("failed to load rules file", zap.String("file", entry.Name()), zap.Error(err))
			continue
		}

		// Add rules from this file to the overall config
		config.Rules = append(config.Rules, fileConfig.Rules...)
	}

	// Update the rules engine with the new config
	if err := c.rulesEngine.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to update rules engine: %w", err)
	}

	c.log.Info("rules engine reloaded", zap.Int("total_rules", len(config.Rules)))
	return nil
}

// ShouldWriteRecord checks if a record should be written based on the filter.
// Returns true if the record passes the filter (or no filter is set).
func (c *Collector) ShouldWriteRecord(record types.AuditRecord) bool {
	if c.filterPrograms == nil {
		return true
	}

	recordType := record.NetcapType()
	compiledFilter, hasFilter := c.filterPrograms[recordType]
	if !hasFilter {
		return true
	}

	match, err := filter.EvaluateExpression(compiledFilter.Program, record)
	if err != nil {
		c.log.Warn("filter evaluation error", zap.String("type", recordType.String()), zap.Error(err))
		return true // On error, allow the record through
	}

	if !match {
		atomic.AddInt64(&c.filteredCount, 1)
	}

	return match
}

// EvaluateRules evaluates all rules against a record and generates alerts if matched.
func (c *Collector) EvaluateRules(record types.AuditRecord) {
	if c.rulesEngine == nil {
		return
	}

	alertsGenerated, err := c.rulesEngine.Evaluate(record)
	if err != nil {
		c.log.Warn("rules evaluation error", zap.String("type", record.NetcapType().String()), zap.Error(err))
		return
	}

	if alertsGenerated > 0 {
		atomic.AddInt64(&c.alertCount, int64(alertsGenerated))
	}
}

// EvaluateRulesWithMetrics evaluates rules and returns the number of alerts generated.
// This is used by the FilteringWriter to track metrics.
func (c *Collector) EvaluateRulesWithMetrics(record types.AuditRecord) int {
	if c.rulesEngine == nil {
		return 0
	}

	alertsGenerated, err := c.rulesEngine.Evaluate(record)
	if err != nil {
		c.log.Warn("rules evaluation error", zap.String("type", record.NetcapType().String()), zap.Error(err))
		return 0
	}

	if alertsGenerated > 0 {
		atomic.AddInt64(&c.alertCount, int64(alertsGenerated))
	}

	return alertsGenerated
}

// WrapWritersWithFiltering wraps all decoder writers with FilteringWriters.
// This should be called after decoders are initialized and before processing starts.
func (c *Collector) WrapWritersWithFiltering() {
	// Only wrap if we have filters or rules
	if len(c.filterPrograms) == 0 && c.rulesEngine == nil {
		return
	}

	c.log.Info("wrapping decoder writers with filtering/rules support")

	// Wrap GoPacket decoders
	for _, decoderSlice := range c.goPacketDecoders {
		for _, decoder := range decoderSlice {
			originalWriter := decoder.GetWriter()
			decoder.SetWriter(NewFilteringWriter(originalWriter, c))
		}
	}

	// Wrap packet decoders
	for _, decoder := range c.packetDecoders {
		originalWriter := decoder.GetWriter()
		decoder.SetWriter(NewFilteringWriter(originalWriter, c))
	}

	// Wrap stream decoders
	for _, decoder := range c.streamDecoders {
		originalWriter := decoder.GetWriter()
		decoder.SetWriter(NewFilteringWriter(originalWriter, c))
	}

	// Wrap abstract decoders
	for _, decoder := range c.abstractDecoders {
		originalWriter := decoder.GetWriter()
		decoder.SetWriter(NewFilteringWriter(originalWriter, c))
	}
}

// GetTotalAuditRecords returns the total number of audit records generated.
func (c *Collector) GetTotalAuditRecords() int64 {
	var total int64

	// Count GoPacket decoder records
	for k, v := range c.allProtosAtomic.Snapshot() {
		if k != "Payload" {
			total += v
		}
	}

	// Count packet decoder records
	for _, d := range c.packetDecoders {
		total += d.NumRecords()
	}

	// Count stream decoder records
	for _, d := range c.streamDecoders {
		total += d.NumRecords()
	}

	// Count abstract decoder records
	for _, d := range c.abstractDecoders {
		total += d.NumRecords()
	}

	return total
}

// New returns a new Collector instance.
func New(config Config) *Collector {
	if config.OutDirPermission == 0 {
		config.OutDirPermission = defaults.DirectoryPermission
	}

	if config.Workers <= 0 {
		config.Workers = defaultWorkers()
	}

	c := &Collector{
		unknownProtosAtomic: decoderutils.NewAtomicCounterMap(),
		allProtosAtomic:     decoderutils.NewAtomicCounterMap(),
		errorMap:            decoderutils.NewAtomicCounterMap(),
		files:               map[string]string{},
		config:              &config,
		start:               time.Now(),
		numEpochs:           1,
		pps:                 map[time.Time]float64{},
		statsInterval:       5 * time.Second,
		perfTracker:         performance.NewTracker(),
	}
	c.next.Store(1)

	return c
}

// recoverFromPanic handles panic recovery, logs the panic to netcap.log, and triggers cleanup.
func (c *Collector) recoverFromPanic() {
	if r := recover(); r != nil {
		// Get the stack trace
		stackTrace := debug.Stack()

		// Log to netcap.log if available
		if c.netcapLog != nil {
			c.netcapLog.Printf("PANIC during pcap processing: %v\n", r)
			c.netcapLog.Printf("Stack trace:\n%s\n", string(stackTrace))
		}

		// Also log to collector.log if available
		if c.log != nil {
			c.log.Error("PANIC during pcap processing",
				zap.Any("panic", r),
				zap.String("stackTrace", string(stackTrace)),
			)
		}

		// Ensure all files are flushed to disk
		if c.netcapLogFile != nil {
			_ = c.netcapLogFile.Sync()
		}

		// Print to stderr for visibility
		fmt.Fprintf(os.Stderr, "\n\nPANIC during pcap processing: %v\n", r)
		fmt.Fprintf(os.Stderr, "Stack trace:\n%s\n", string(stackTrace))
		fmt.Fprintf(os.Stderr, "Panic details have been written to netcap.log\n")

		// Trigger cleanup to close and flush all files
		// Use force=true to ensure cleanup happens even if there's an error
		c.cleanup(true)

		// Exit with error code
		os.Exit(1)
	}
}

// stopWorkers halts all workers.
func (c *Collector) stopWorkers() {
	// wait until all packets have been decoded
	c.mu.Lock()
	for i, w := range c.workers {
		select {
		case w <- nil:
			c.log.Info("worker done", zap.Int("num", i))
		}
	}
	c.mu.Unlock()
}

// handleSignals catches signals and runs the cleanup
// SIGQUIT is not caught, to allow debugging by producing a stack and goroutine trace.
func (c *Collector) handleSignals() {
	c.signalChan = make(chan os.Signal, 1)
	signal.Notify(c.signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Store cleanup function to stop signal handling
	c.signalStop = func() {
		signal.Stop(c.signalChan)
		close(c.signalChan)
	}

	// start signal handler and cleanup routine
	go func() {
		sig, ok := <-c.signalChan
		if !ok {
			// Channel closed, exit goroutine
			return
		}

		c.printlnStdOut("\nreceived signal:", sig)
		c.printlnStdOut("exiting")
		c.log.Info("received signal", zap.String("sig", sig.String()))

		go func() {
			sign, ok := <-c.signalChan
			if !ok {
				// Channel closed, exit goroutine
				return
			}
			c.printlnStdOut("force quitting, signal:", sign)
			os.Exit(0)
		}()

		c.cleanup(true)
		os.Exit(0)
	}()

	if c.config.HTTPShutdownEndpoint {
		c.printlnStdOut("serving http shutdown endpoint")
		go c.serveCleanupHTTPEndpoint()
	}
}

func (c *Collector) serveCleanupHTTPEndpoint() {
	var (
		cleanupTriggered bool
		cleanupMu        sync.Mutex
	)

	http.HandleFunc("/cleanup", func(w http.ResponseWriter, r *http.Request) {
		var force bool

		// sync access
		cleanupMu.Lock()
		force = cleanupTriggered
		cleanupMu.Unlock()

		// second time cleanup request will force shutdown
		if force {
			c.log.Info("shutdown forced via local http endpoint from", zap.String("userAgent", r.UserAgent()), zap.String("addr", r.RemoteAddr))

			// triggered once already. now force shutdown
			c.printlnStdOut("force quitting")

			// reply OK
			// TODO: hold the connection open until the stream processing is going on.
			// This way the Stop command could flush the latest audit records to maltego once the netcap process exited.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))

			// do this in the background to allow the http request handler to finish cleanly
			go func() {
				time.Sleep(1 * time.Second)
				os.Exit(0)
			}()

			return
		}

		// first time shutdown triggered
		cleanupMu.Lock()
		cleanupTriggered = true
		cleanupMu.Unlock()

		c.log.Info("shutdown request received via local http endpoint from", zap.String("userAgent", r.UserAgent()), zap.String("addr", r.RemoteAddr))

		c.cleanup(true)

		// reply OK
		// TODO: hold the connection open until the stream processing is going on.
		// This way the Stop command could flush the latest audit records to maltego once the netcap process exited.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))

		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
	})

	err := http.ListenAndServe("127.0.0.1:60589", nil)
	if err != nil {
		log.Fatal(
			"failed to bind http shutdown endpoint:\n",
			err,
			"\n > This usually happens when multiple instances of NETCAP are running,",
			"\n > or another service is blocking port 60589.",
			"\n > Please quit all remaining NETCAP processes and try again.",
			"\n > Running multiple processes in parallel is currently not possible,",
			"\n > due to atomic access to the resolver bleve databases.",
		)
	}
}

// getSymmetricWorkerIndex calculates a worker index based on symmetric flow hashing.
// This ensures packets A->B and B->A are processed by the same worker.
func (c *Collector) getSymmetricWorkerIndex(p gopacket.Packet) int {
	if c.numWorkers <= 1 {
		return 0
	}

	var hash uint64
	hasFlow := false

	// Network Layer
	if nl := p.NetworkLayer(); nl != nil {
		hash = nl.NetworkFlow().FastHash()
		hasFlow = true
	}

	// Match ReassemblePacket's TCP selection, including encapsulated TCP.
	if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		hash ^= tcpLayer.(*layers.TCP).TransportFlow().FastHash()
		hasFlow = true
	} else if tl := p.TransportLayer(); tl != nil {
		hash ^= tl.TransportFlow().FastHash()
		hasFlow = true
	}

	// A zero hash is valid; fall back only when no flow was identified.
	if !hasFlow {
		// Use Link Layer if available
		if ll := p.LinkLayer(); ll != nil {
			hash = ll.LinkFlow().FastHash()
		} else {
			// Round robin fallback (atomic to avoid races)
			idx := c.next.Add(1) - 1
			return int(idx % int64(c.numWorkers))
		}
	}

	return int(hash % uint64(c.numWorkers))
}

// to decode incoming packets in parallel
// they are passed to several worker goroutines using flow sharding.
func (c *Collector) handlePacket(p gopacket.Packet) {
	// make it work for 1 worker only, can be used for debugging
	if c.numWorkers == 1 {
		c.workers[0] <- p

		return
	}

	idx := c.getSymmetricWorkerIndex(p)
	c.workers[idx] <- p
}

// to decode incoming packets in parallel
// they are passed to several worker goroutines using flow sharding.
func (c *Collector) handlePacketTimeout(p gopacket.Packet) {
	idx := c.getSymmetricWorkerIndex(p)

	select {
	// send the packetInfo to the decoder routine
	case c.workers[idx] <- p:
	case <-time.After(3 * time.Second):
		pkt := gopacket.NewPacket(p.Data(), c.config.BaseLayer, gopacket.Default)

		var (
			nf gopacket.Flow
			tf gopacket.Flow
		)

		if nl := pkt.NetworkLayer(); nl != nil {
			nf = nl.NetworkFlow()
		}

		if tl := pkt.TransportLayer(); tl != nil {
			tf = tl.TransportFlow()
		}

		fmt.Println("handle packet timeout", nf, tf)

		// Dispose of the temporary packet if it's pooled
		if pooledPkt, ok := pkt.(gopacket.PooledPacket); ok {
			pooledPkt.Dispose()
		}
	}
}

// print errors to stdout in red.
func (c *Collector) printErrors() {
	if c.config.DecoderConfig.Quiet {
		_, _ = fmt.Fprintln(c.netcapLogFile, c.getErrorSummary(), ansi.Reset)
	} else {
		_, _ = fmt.Println(ansi.Red, c.getErrorSummary(), ansi.Reset)
	}
}

// closes the logfile for errors.
func (c *Collector) closeErrorLogFile() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if error log file is already closed
	if c.errorLogFile == nil {
		return
	}

	summary := c.getErrorSummary()

	_, err := c.errorLogFile.WriteString(summary)
	if err != nil {
		c.log.Error("failed to write stats into error log", zap.Error(err))
		return
	}

	// Get file info before closing to check if empty
	info, err := c.errorLogFile.Stat()
	if err != nil {
		c.log.Error("failed to stat error log", zap.Error(err))
	}

	fileName := c.errorLogFile.Name()

	// sync
	err = c.errorLogFile.Sync()
	if err != nil {
		c.log.Error("failed to sync error log", zap.Error(err))
		return
	}

	// close file handle
	err = c.errorLogFile.Close()
	if err != nil {
		c.log.Error("failed to close error log", zap.Error(err))
		return
	}

	// Nil out the file handle to prevent double-close
	c.errorLogFile = nil

	// Remove error log file if it's empty (similar to how audit record files are handled)
	if info != nil && info.Size() == 0 {
		err = os.Remove(fileName)
		if err != nil {
			c.log.Error("failed to remove empty error log file", zap.String("file", fileName), zap.Error(err))
		}
	}
}

// stats prints collector statistics.
func (c *Collector) stats() {
	// Check if log file is still open
	if c.netcapLogFile == nil {
		return
	}

	var target io.Writer
	if c.config.DecoderConfig.Quiet {
		target = c.netcapLogFile
	} else {
		target = io.MultiWriter(os.Stderr, c.netcapLogFile)
	}

	var rows [][]string

	allProtos := c.allProtosAtomic.Snapshot()
	unknownProtos := c.unknownProtosAtomic.Snapshot()

	for k, v := range allProtos {
		// Skip records with 0 count
		if v == 0 {
			continue
		}

		if k == "Payload" {
			rows = append(rows, []string{k, fmt.Sprint(v), share(v, c.numPackets)})

			continue
		}

		if _, ok := unknownProtos[k]; ok {
			rows = append(rows, []string{"*" + k, fmt.Sprint(v), share(v, c.numPackets)})
		} else {
			rows = append(rows, []string{k, fmt.Sprint(v), share(v, c.numPackets)})
		}
	}

	numUnknown := len(unknownProtos)

	table.Render(target, []string{"GoPacketDecoder", "NumRecords", "Share"}, rows)

	// print legend if there are unknown protos
	// -1 for "Payload" layer
	if numUnknown-1 > 0 {
		if !c.config.DecoderConfig.Quiet {
			fmt.Println("* protocol supported by gopacket, but not implemented in netcap")
		}
	}

	if len(c.packetDecoders) > 0 {
		rows = [][]string{}
		for _, d := range c.packetDecoders {
			// Skip records with 0 count
			if d.NumRecords() > 0 {
				rows = append(rows, []string{d.GetName(), strconv.FormatInt(d.NumRecords(), 10), share(d.NumRecords(), c.numPackets)})
			}
		}

		if len(rows) > 0 {
			table.Render(target, []string{"PacketDecoder", "NumRecords", "Share"}, rows)
		}
	}

	if len(c.streamDecoders) > 0 {
		rows = [][]string{}
		for _, d := range c.streamDecoders {
			// Skip records with 0 count
			if d.NumRecords() > 0 {
				rows = append(rows, []string{d.GetName(), strconv.FormatInt(d.NumRecords(), 10), share(d.NumRecords(), c.numPackets)})
			}
		}

		if len(rows) > 0 {
			table.Render(target, []string{"StreamDecoder", "NumRecords", "Share"}, rows)
		}
	}

	if len(c.abstractDecoders) > 0 {
		rows = [][]string{}
		for _, d := range c.abstractDecoders {
			// Skip records with 0 count
			if d.NumRecords() > 0 {
				rows = append(rows, []string{d.GetName(), strconv.FormatInt(d.NumRecords(), 10), share(d.NumRecords(), c.numPackets)})
			}
		}

		if len(rows) > 0 {
			table.Render(target, []string{"AbstractDecoder", "NumRecords", "Share"}, rows)
		}
	}

	res := "-> total bytes of audit record data written to disk: " + humanize.Bytes(uint64(c.totalBytesWritten)) + "\n"

	if c.unkownPcapWriterAtomic != nil {
		if c.unkownPcapWriterAtomic.count > 0 {
			res += "-> " + share(c.unkownPcapWriterAtomic.count, c.numPackets) + " of packets (" + strconv.FormatInt(c.unkownPcapWriterAtomic.count, 10) + ") written to unknown.pcap\n"
		}
	}

	if c.errorsPcapWriterAtomic != nil {
		if c.errorsPcapWriterAtomic.count > 0 {
			res += "-> " + share(c.errorsPcapWriterAtomic.count, c.numPackets) + " of packets (" + strconv.FormatInt(c.errorsPcapWriterAtomic.count, 10) + ") written to errors.pcap\n"
		}
	}

	if _, err := fmt.Fprintln(target, res); err != nil {
		fmt.Println("failed to print stats:", err)
	}

	if c.config.DecoderConfig.SaveConns {
		_, _ = fmt.Fprintln(target, "saved TCP connections:", tcp.NumSavedTCPConns())
		_, _ = fmt.Fprintln(target, "saved UDP conversations:", udp.NumSavedUDPConns())
	}

	// dump label manager stats table if configured
	manager.Stats(target)

	// print tree view of encountered audit records
	c.printTreeView(target)
}

// printTreeView prints a hierarchical tree view of all encountered audit record types
// organized by their correct encapsulation level (Link -> Network -> Transport -> Application)
func (c *Collector) printTreeView(target io.Writer) {
	if c.config.DecoderConfig.Quiet {
		return
	}

	fmt.Fprintln(target, "\n========================================")
	fmt.Fprintln(target, "Encountered Audit Records (Tree View)")
	fmt.Fprintln(target, "========================================")

	// Organize encountered decoders by layer
	decodersByLayer := make(map[string][]string)

	// Collect GoPacket decoders with count > 0
	for k, v := range c.allProtosAtomic.Snapshot() {
		if v > 0 && k != "Payload" {
			layer := determineLayerForDecoder(k)
			decodersByLayer[layer] = append(decodersByLayer[layer], k)
		}
	}

	// Collect PacketDecoders with count > 0
	for _, d := range c.packetDecoders {
		if d.NumRecords() > 0 {
			name := d.GetName()
			layer := determineLayerForDecoder(name)
			decodersByLayer[layer] = append(decodersByLayer[layer], name)
		}
	}

	// Collect StreamDecoders with count > 0
	for _, d := range c.streamDecoders {
		if d.NumRecords() > 0 {
			decodersByLayer["Stream Decoders"] = append(decodersByLayer["Stream Decoders"], d.GetName())
		}
	}

	// Collect AbstractDecoders with count > 0
	for _, d := range c.abstractDecoders {
		if d.NumRecords() > 0 {
			decodersByLayer["Abstract Decoders"] = append(decodersByLayer["Abstract Decoders"], d.GetName())
		}
	}

	// Print hierarchical tree
	printEncapsulationTree(target, decodersByLayer)

	fmt.Fprintln(target)
}

// determineLayerForDecoder determines the OSI layer for a decoder based on its name
func determineLayerForDecoder(name string) string {
	nameLower := strings.ToLower(name)

	// Link Layer protocols
	linkLayerProtocols := []string{"ethernet", "arp", "dot1q", "dot11", "llc", "snap",
		"linklayerdiscovery", "ethernetctp", "fddi", "usb", "cisco", "nortel", "vlan"}
	for _, proto := range linkLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Link Layer"
		}
	}

	// Network Layer protocols
	networkLayerProtocols := []string{"ipv4", "ipv6", "icmp", "ipsec", "igmp", "mpls", "gre"}
	for _, proto := range networkLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Network Layer"
		}
	}

	// Transport Layer protocols
	transportLayerProtocols := []string{"tcp", "udp", "sctp"}
	for _, proto := range transportLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Transport Layer"
		}
	}

	// Application Layer protocols
	applicationLayerProtocols := []string{"dns", "dhcp", "http", "tls", "ntp", "sip",
		"smtp", "pop3", "ssh", "lcm", "modbus", "ospf", "bfd", "eap", "cip", "enip",
		"geneve", "vxlan", "vrrp", "diameter", "connection", "deviceprofile", "ipprofile"}
	for _, proto := range applicationLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Application Layer"
		}
	}

	return "Application Layer"
}

// printEncapsulationTree prints layers in a hierarchical tree structure
// matching the exact layout from net util -decoders
func printEncapsulationTree(target io.Writer, decodersByLayer map[string][]string) {
	// Print Link Layer at root
	fmt.Fprintln(target, "├── Link Layer")
	if decoders, ok := decodersByLayer["Link Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│   ", false, true) // hasChildLayer=true because Network Layer follows
	}

	// Print Network Layer as child of Link Layer
	fmt.Fprintln(target, "│   └── Network Layer")
	if decoders, ok := decodersByLayer["Network Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│       ", false, true) // hasChildLayer=true because Transport Layer follows
	}

	// Print Transport Layer as child of Network Layer
	fmt.Fprintln(target, "│       └── Transport Layer")
	if decoders, ok := decodersByLayer["Transport Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│           ", false, true) // hasChildLayer=true because Application Layer follows
	}

	// Print Application Layer as child of Transport Layer
	fmt.Fprintln(target, "│           └── Application Layer")
	if decoders, ok := decodersByLayer["Application Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│               ", true, false) // hasChildLayer=false, this is the end
	}

	// Print Stream Decoders at root level (if any exist)
	if decoders, ok := decodersByLayer["Stream Decoders"]; ok && len(decoders) > 0 {
		fmt.Fprintln(target, "│")
		fmt.Fprintln(target, "├── Stream Decoders")
		printDecoderList(target, decoders, "│   ", false, false) // hasChildLayer=false
	}

	// Print Abstract Decoders at root level (last one, if any exist)
	if decoders, ok := decodersByLayer["Abstract Decoders"]; ok && len(decoders) > 0 {
		fmt.Fprintln(target, "│")
		fmt.Fprintln(target, "└── Abstract Decoders")
		printDecoderList(target, decoders, "    ", true, false) // hasChildLayer=false
	}
}

// printDecoderList prints a list of decoders with the given indent
// hasChildLayer indicates if a child layer follows the decoder list
func printDecoderList(target io.Writer, decoders []string, indent string, isLast bool, hasChildLayer bool) {
	for i, decoder := range decoders {
		isLastDecoder := i == len(decoders)-1
		prefix := indent + "├──"
		// Only use └── if it's the last decoder AND there's no child layer following
		if isLastDecoder && !hasChildLayer {
			prefix = indent + "└──"
		}

		fmt.Fprintf(target, "%s %s\n", prefix, decoder)
	}
}

// updates the progress indicator and writes to stdout.
//func (c *Collector) printProgress() {
//	// increment atomic packet counter
//	atomic.AddInt64(&c.current, 1)
//
//	// must be locked, otherwise a race occurs when sending a SIGINT
//	//  and triggering wg.Wait() in another goroutine...
//	c.statMutex.Lock()
//
//	// increment wait group for packet processing
//	c.wg.Add(1)
//
//	// dont print message when collector is about to shutdown
//	if c.shutdown {
//		c.statMutex.Unlock()
//
//		return
//	}
//	c.statMutex.Unlock()
//
//	if c.current%1000 == 0 {
//		if !c.config.DecoderConfig.Quiet {
//			// using a strings.Builder for assembling string for performance
//			// TODO: could be refactored to use a byte slice with a fixed length instead
//			// TODO: add Builder to collector and flush it every cycle to reduce allocations
//			// also only print flows and collections when the corresponding decoders are active
//			var b strings.Builder
//
//			b.Grow(65)
//			b.WriteString("decoding packets... (")
//			b.WriteString(utils.Progress(c.current, c.numPackets))
//			b.WriteString(")")
//			// b.WriteString(strconv.Itoa(decoder.Flows.Size()))
//			// b.WriteString(" connections: ")
//			// b.WriteString(strconv.Itoa(decoder.Connections.Size()))
//			b.WriteString(" profiles: ")
//			b.WriteString(strconv.Itoa(decoder.DeviceProfiles.Size()))
//			b.WriteString(" packets: ")
//			b.WriteString(strconv.Itoa(int(c.current)))
//
//			// print
//			clearLine()
//
//			_, _ = os.Stdout.WriteString(b.String())
//		}
//	}
//}

// updates the progress indicator and writes to stdout periodically.
func (c *Collector) printProgressInterval() chan struct{} {
	stop := make(chan struct{})

	// Create separate ticker for quiet mode netcap.log progress updates
	var quietProgressTicker *time.Ticker
	if c.config.DecoderConfig.Quiet && !c.config.DecoderConfig.PrintProgress {
		quietProgressTicker = time.NewTicker(5 * time.Second)
	}

	go func() {
		// Clean up ticker on exit
		defer func() {
			if quietProgressTicker != nil {
				quietProgressTicker.Stop()
			}
		}()

		statsTicker := time.NewTicker(c.statsInterval)
		defer statsTicker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-statsTicker.C:
				// must be locked, otherwise a race occurs when sending a SIGINT
				// and triggering wg.Wait() in another goroutine...
				c.statMutex.Lock()

				// dont print message when collector is about to shutdown
				if c.shutdown {
					c.statMutex.Unlock()
					return
				}
				c.statMutex.Unlock()

				var (
					curr = atomic.LoadInt64(&c.current)
					num  = atomic.LoadInt64(&c.numPackets)
					last = atomic.LoadInt64(&c.numPacketsLast)
					pps  = (curr - last) / int64(c.statsInterval.Seconds())
				)

				// update prometheus metric
				newPacketsPerSecond.WithLabelValues().Set(float64(pps))

				// track value for charting
				c.pps[time.Now()] = float64(pps)

				// update internal stats
				atomic.StoreInt64(&c.numPacketsLast, curr)

				// print to stderr
				if !c.config.DecoderConfig.Quiet || c.config.DecoderConfig.PrintProgress { // print
					c.clearLine()
					_, _ = fmt.Fprintf(os.Stderr,
						c.progressString,
						utils.Progress(curr, num),
						// decoder.Flows.Size(), // TODO: fetch this info from stats?
						// decoder.Connections.Size(), // TODO: fetch this info from stats?
						packet.DeviceProfiles.Size(),
						service.Store.Size(),
						int(curr),
						pps,
					)
					c.log.Sugar().Infof(c.progressString,
						utils.Progress(curr, num),
						// decoder.Flows.Size(), // TODO: fetch this info from stats?
						// decoder.Connections.Size(), // TODO: fetch this info from stats?
						packet.DeviceProfiles.Size(),
						service.Store.Size(),
						int(curr),
						pps)
				}
			case <-func() <-chan time.Time {
				if quietProgressTicker != nil {
					return quietProgressTicker.C
				}
				// Return a channel that never receives if ticker is nil
				return make(<-chan time.Time)
			}():
				// Log progress to netcap.log in quiet mode every minute
				c.statMutex.Lock()
				if c.shutdown {
					c.statMutex.Unlock()
					return
				}
				c.statMutex.Unlock()

				var (
					curr = atomic.LoadInt64(&c.current)
					num  = atomic.LoadInt64(&c.numPackets)
				)

				if c.netcapLog != nil {
					c.netcapLog.Printf("progress: %s", utils.Progress(curr, num))
				}
			}
		}
	}()

	return stop
}

// assemble the progress string once, to reduce recurring allocations.
func (c *Collector) buildProgressString() {
	c.progressString = "decoding packets... (%s) profiles: %d services: %d total packets: %d pkts/sec %d"
}

// GetNumPackets returns the current number of processed packets.
func (c *Collector) GetNumPackets() int64 {
	return atomic.LoadInt64(&c.current)
}

// FreeOSMemory forces freeing memory periodically until context is cancelled.
func (c *Collector) freeOSMemory(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(c.config.FreeOSMem) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			debug.FreeOSMemory()
		case <-ctx.Done():
			// Context cancelled, terminate goroutine
			return
		}
	}
}

// ResetHeaderPrinted resets the flag that tracks whether the netcap header has been printed.
// This is useful when starting a new batch of processing or in testing scenarios.
func ResetHeaderPrinted() {
	headerPrintedLock.Lock()
	headerPrinted = false
	headerPrintedLock.Unlock()
}

// PrintConfiguration dumps the current collector config to stdout.
func (c *Collector) PrintConfiguration() {
	// ensure the logfile handle gets opened
	err := c.initLogging()
	if err != nil {
		log.Fatal("failed to open logfile:", err)
	}

	var target io.Writer
	if c.config.DecoderConfig.Quiet {
		target = c.netcapLogFile
	} else {
		target = io.MultiWriter(os.Stdout, c.netcapLogFile)
	}

	cdata, err := json.MarshalIndent(c.config, " ", "  ")
	if err != nil {
		log.Fatal(err)
	}
	// always write the entire configuration into the logfile
	_, _ = c.netcapLogFile.Write(cdata)

	// Print header only once when processing multiple files
	headerPrintedLock.Lock()
	shouldPrintHeader := !headerPrinted
	if !headerPrinted {
		headerPrinted = true
	}
	headerPrintedLock.Unlock()

	if shouldPrintHeader {
		netio.FPrintLogo(target)
	}

	if c.config.DecoderConfig.Debug && !c.config.DecoderConfig.Quiet {
		// in debug mode and when not silencing stdout via quiet mode: dump config to stdout
		target = io.MultiWriter(os.Stdout, c.netcapLogFile)
	} else {
		// default: write configuration into netcap.log
		target = c.netcapLogFile
		if !c.config.DecoderConfig.Quiet && shouldPrintHeader {
			fmt.Println() // add newline
		}
	}

	if shouldPrintHeader {
		netio.FPrintBuildInfo(target)
	}

	// print build information
	_, _ = fmt.Fprintln(target, "> PID:", os.Getpid())

	// print configuration as table
	table.Render(target, []string{"Setting", "Value"}, [][]string{
		{"Workers", strconv.Itoa(c.config.Workers)},
		{"MemBuffer", strconv.FormatBool(c.config.DecoderConfig.Buffer)},
		{"MemBufferSize", strconv.Itoa(c.config.DecoderConfig.MemBufferSize) + " bytes"},
		{"Compression", strconv.FormatBool(c.config.DecoderConfig.Compression)},
		{"PacketBuffer", strconv.Itoa(c.config.PacketBufferSize) + " packets"},
		{"PacketContext", strconv.FormatBool(c.config.DecoderConfig.AddContext)},
		{"Payloads", strconv.FormatBool(c.config.DecoderConfig.IncludePayloads)},
		{"FileStorage", c.config.DecoderConfig.FileStorage},
	})

	_, _ = fmt.Fprintln(target) // add a newline
}

// Stop will halt packet collection and wait for all processing to finish.
func (c *Collector) Stop() {
	c.cleanup(false)
}

// forceStop will halt packet collection immediately without waiting for processing to finish.
func (c *Collector) forceStop() {
	c.cleanup(true)
}

// SetLogLevel updates the log level for all zap loggers at runtime.
// This allows enabling/disabling debug logging without restarting.
func (c *Collector) SetLogLevel(debug bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update the config
	c.config.DecoderConfig.Debug = debug

	// Update all atomic log levels
	for _, level := range c.atomicLogLevels {
		if level != nil {
			if debug {
				level.SetLevel(zap.DebugLevel)
			} else {
				level.SetLevel(zap.InfoLevel)
			}
		}
	}

	if c.log != nil {
		if debug {
			c.log.Info("Debug logging enabled at runtime")
		} else {
			c.log.Info("Debug logging disabled at runtime")
		}
	}
}

// GetCurrentPacketCount returns the current packet count (for live statistics)
func (c *Collector) GetCurrentPacketCount() int64 {
	return atomic.LoadInt64(&c.current)
}

// GetTotalPacketCount returns the total packet count (for live statistics)
func (c *Collector) GetTotalPacketCount() int64 {
	return atomic.LoadInt64(&c.numPackets)
}

// GetPacketsPerSecond returns the current packets per second rate (for live statistics)
func (c *Collector) GetPacketsPerSecond() int64 {
	curr := atomic.LoadInt64(&c.current)
	last := atomic.LoadInt64(&c.numPacketsLast)
	return (curr - last) / int64(c.statsInterval.Seconds())
}

// GetProfilesCount returns the current number of device profiles (for live statistics)
func (c *Collector) GetProfilesCount() int {
	return packet.DeviceProfiles.Size()
}

// GetServicesCount returns the current number of services (for live statistics)
func (c *Collector) GetServicesCount() int {
	return service.Store.Size()
}
