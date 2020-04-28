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

package encoder

import (
	"github.com/dreadl0ck/netcap"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/dreadl0ck/gopacket/reassembly"
)

var (
	c   Config
	cMu sync.Mutex

	reassemblyLog           = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)
	reassemblyLogFileHandle *os.File

	debugLog           = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)
	debugLogFileHandle *os.File
)

const (
	directoryPermission = 0755
	logFilePermission   = 0755
)

// SetConfig can be used to set a configuration for the package
func SetConfig(cfg Config) {

	cMu.Lock()
	c = cfg
	cMu.Unlock()

	fsmOptions = reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: c.AllowMissingInit,
	}

	// setup loggers
	if c.Debug {
		var err error
		debugLogFileHandle, err = os.OpenFile("debug.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
		if err != nil {
			log.Fatal(err)
		}
		debugLog.SetOutput(debugLogFileHandle)

		reassemblyLogFileHandle, err = os.OpenFile("reassembly.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
		if err != nil {
			log.Fatal(err)
		}
		reassemblyLog.SetOutput(reassemblyLogFileHandle)

		pop3Debug = true
	}
}

// DefaultConfig is a sane example configuration for the encoder package
var DefaultConfig = Config{
	Buffer:               true,
	Compression:          true,
	CSV:                  false,
	IncludeEncoders:      "",
	ExcludeEncoders:      "",
	IncludePayloads:      false,
	Export:               false,
	AddContext:           true,
	MemBufferSize:        netcap.DefaultBufferSize,
	FlushEvery:           100,
	NoDefrag:             false,
	Checksum:             false,
	NoOptCheck:           false,
	IgnoreFSMerr:         false,
	AllowMissingInit:     false,
	Debug:                false,
	HexDump:              false,
	WaitForConnections:   true,
	WriteIncomplete:      false,
	MemProfile:           "",
	ConnFlushInterval:    10000,
	ConnTimeOut:          10 * time.Second,
	FlowFlushInterval:    2000,
	FlowTimeOut:          10 * time.Second,
	CloseInactiveTimeOut: 24 * time.Hour,
	ClosePendingTimeOut:  5 * time.Second,
}

// Config contains configuration parameters
// for the encoders
type Config struct {

	// Buffer data before writing it to disk
	Buffer bool

	// Size of buffer used for writing audit records to disk
	MemBufferSize int

	// Compress data before writing it to disk with gzip
	Compression bool

	// Generate CSV instead of audit records
	CSV bool

	// Comma separated list of encoders to include
	IncludeEncoders string

	// Comma separated list of encoders to exclude
	ExcludeEncoders string

	// Output path
	Out string

	// Write into channel (used for distributed collection)
	WriteChan bool

	// Source of the audit records (pcap, live etc)
	Source string

	// Add payload data to supported audit records
	IncludePayloads bool

	// Export metrics
	Export bool

	// Add context to supported audit records
	AddContext bool

	// Interval to apply connection flushes
	FlushEvery int

	// Do not use IPv4 defragger
	NoDefrag bool

	// Dont verify the packet checksums
	Checksum bool

	// Dont check TCP options
	NoOptCheck bool

	// Ignore TCP state machine errors
	IgnoreFSMerr bool

	// TCP state machine allow missing init in three way handshake
	AllowMissingInit bool

	// Toggle debug mode
	Debug bool

	// Dump packet contents as hex for debugging
	HexDump bool

	// Wait until all connections finished processing when receiving shutdown signal
	WaitForConnections bool

	// Write incomplete HTTP responses to disk when extracting files
	WriteIncomplete bool

	// Will create a memory dump at the specified path for debugging and profiling
	MemProfile string

	// Number of packets to arrive until the connections are checked for timeouts
	ConnFlushInterval int

	// Used to flush connections to disk whose last timestamp is connTimeOut older than current packet
	ConnTimeOut time.Duration

	// Number of packets to arrive until the flows are checked for timeouts
	FlowFlushInterval int

	// Used to flush flows to disk whose last timestamp is flowTimeOut older than current packet
	FlowTimeOut time.Duration

	// Close inactive connections after
	CloseInactiveTimeOut time.Duration

	// Close connections with pending bytes after
	ClosePendingTimeOut time.Duration
}
