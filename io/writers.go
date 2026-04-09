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

package io

import (
	"time"

	"github.com/dreadl0ck/netcap/internal/performance"
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

	// Performance tracker for measuring disk I/O
	PerfTracker *performance.Tracker
}
