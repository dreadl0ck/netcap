/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"bufio"
	"fmt"
	"os"

	gzip "github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/delimited"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
)

// AuditRecordHandle wraps a file handle of a netcap audit record file
// contains the original file handle and writers to compress and buffer the data
type AuditRecordHandle struct {
	gWriter *gzip.Writer
	bWriter *bufio.Writer
	f       *os.File
}

// NewAuditRecordHandle creates a new netcap audit record file
func NewAuditRecordHandle(b *types.Batch, path string) *AuditRecordHandle {

	err := os.MkdirAll(b.ClientID, 0755)
	if err != nil {
		panic(err)
	}
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	fmt.Println("new audit record handle", path)

	conf := encoder.Config{
		Source:          b.ClientID,
		Version:         netcap.Version,
		IncludePayloads: b.ContainsPayloads,
		MemBufferSize:   *flagMemBufferSize,
	}

	var (
		// create buffered writer that writes into the file handle
		bWriter = bufio.NewWriter(f)
		// create gzip writer that writes into the buffered writer
		gWriter = gzip.NewWriter(bWriter)
	)

	// add file header
	err = delimited.NewWriter(gWriter).PutProto(netcap.NewHeader(b.MessageType, conf.Source, conf.Version, conf.IncludePayloads))
	if err != nil {
		fmt.Println("failed to write header")
		panic(err)
	}

	return &AuditRecordHandle{
		bWriter: bWriter,
		gWriter: gWriter,
		f:       f,
	}
}
