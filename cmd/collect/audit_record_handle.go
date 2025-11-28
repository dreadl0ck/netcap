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

package collect

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	gzip "github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/delimited"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// auditRecordHandle wraps a file handle of a netcap audit record file
// contains the original file handle and writers to compress and buffer the data.
type auditRecordHandle struct {
	gWriter *gzip.Writer
	bWriter *bufio.Writer
	f       *os.File
}

// newAuditRecordHandle creates a new netcap audit record file.
func newAuditRecordHandle(b *types.Batch, path string) *auditRecordHandle {
	err := os.MkdirAll(b.ClientID, defaults.DirectoryPermission)
	if err != nil {
		panic(err)
	}

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}

	fmt.Println("new audit record handle", path)

	conf := config.DefaultConfig
	conf.Source = b.ClientID
	conf.IncludePayloads = b.ContainsPayloads
	conf.MemBufferSize = currentMemBufferSize

	var (
		// create buffered writer that writes into the file handle
		bWriter = bufio.NewWriter(f)
		// create gzip writer that writes into the buffered writer
		gWriter, errGzipWriter = gzip.NewWriterLevel(bWriter, defaults.CompressionLevel)
	)

	if errGzipWriter != nil {
		panic(errGzipWriter)
	}

	// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
	// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
	// you would like to utilize, but about twice the number of blocks would be the best.
	if err = gWriter.SetConcurrency(defaults.CompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
		log.Fatal("failed to configure compression package: ", err)
	}

	// add file header
	err = delimited.NewWriter(gWriter).PutProto(io.NewHeader(b.MessageType, conf.Source, netcap.Version, conf.IncludePayloads, time.Now()))
	if err != nil {
		fmt.Println("failed to write header")
		panic(err)
	}

	return &auditRecordHandle{
		bWriter: bWriter,
		gWriter: gWriter,
		f:       f,
	}
}
