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
	conf.MemBufferSize = *flagMemBufferSize

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
