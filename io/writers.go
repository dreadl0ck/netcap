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

package io

import (
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// WriterConfig contains config parameters for a audit record writer.
type WriterConfig struct {

	// Writer Types:
	// Comma Separated Values writer
	CSV bool

	// Protobuf writer
	Proto bool

	// JSON writer
	JSON bool

	// Channel writer
	Chan bool

	// ChanSize is the size of chunks sent through the channel
	ChanSize int

	// Elastic db writer
	Elastic bool

	// UnixSocket writer
	UnixSocket bool

	// ElasticConfig allows to overwrite elastic defaults
	ElasticConfig

	// The Null writer will write nothing to disk and discard all data.
	Null bool

	// Netcap header information
	Name          string
	Type          types.Type
	Buffer        bool
	Compress      bool
	Out           string
	MemBufferSize int

	// Netcap header information
	Source           string
	Version          string
	IncludesPayloads bool
	StartTime        time.Time

	// compression
	CompressionBlockSize int
	CompressionLevel     int

	// Encode data on the fly
	Encode bool

	// Label data on the fly
	Label bool
}
