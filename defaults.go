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

package netcap

import (
	"compress/flate"
	"time"
)

const (
	// DefaultBufferSize is the size for memory buffering before feeding data into compressor.
	DefaultBufferSize = 1024 * 1024 * 12 // 12 MB

	// DefaultPacketBuffer is the size of the channel for feeding packets into workers.
	DefaultPacketBuffer = 100

	// DefaultSnapLen is the default length for an ethernet frame:
	// 1500 Ethernet MTU + 14 bytes Ethernet header.
	DefaultSnapLen = 1514

	// DefaultConnFlushInterval configures how often the connections are flushed for Flow and Connection audit record generation.
	// TODO: refactor to flush periodically, instead of every n packets?
	DefaultConnFlushInterval = 0

	// DefaultFlowFlushInterval configures how often the connections are flushed for Flow and Connection audit record generation.
	// TODO: refactor to flush periodically, instead of every n packets?
	DefaultFlowFlushInterval = 0

	// DefaultConnTimeOut will be used to set age threshold if the corresponding FlushInterval > 0.
	DefaultConnTimeOut = 0 * time.Second

	// DefaultFlowTimeOut will be used to set age threshold if the corresponding FlushInterval > 0.
	DefaultFlowTimeOut = 0 * time.Second

	// DefaultCompressionBlockSize will determine the block size used for parallel compression.
	DefaultCompressionBlockSize = 1024 * 1024 * 1 // 1 MB

	// DefaultCompressionLevel will determine the compression level to use by default.
	DefaultCompressionLevel = flate.BestSpeed

	// TCP Stream Reassembly:
	// default settings are meant to be forgiving in terms of TCP state machine correctness
	// in order to capture as much information as possible.

	// DefaultReassemblyTimeout How long to wait for remaining open streams to close, before initiating teardown.
	DefaultReassemblyTimeout = 5 * time.Second

	// DefaultFlushEvery TODO: refactor to flush periodically, instead of every n packets?
	// controls how often collected reassembly data is flushed to consumers.
	DefaultFlushEvery = 100

	// DefaultClosePendingTimeout Close streams with pending bytes after.
	DefaultClosePendingTimeout = 1 * time.Hour

	// DefaultCloseInactiveTimeout Close inactive streams after.
	DefaultCloseInactiveTimeout = 1 * time.Hour

	// DefaultAllowMissingInit TCP State Machine.
	DefaultAllowMissingInit = true

	// DefaultDefragIPv4 controls defragmentation for IPv4.
	DefaultDefragIPv4 = true

	// DefaultNoOptCheck controls TCP option checking for the reassembly state machine.
	DefaultNoOptCheck = true

	// DefaultChecksum controls whether the TCP checksum shall be validated.
	DefaultChecksum = false

	// DefaultIgnoreFSMErr controls if TCP state machine errors should be ignored.
	DefaultIgnoreFSMErr = true

	// DefaultFileStorage is the default location for storing extracted files.
	DefaultFileStorage = "files"
)
