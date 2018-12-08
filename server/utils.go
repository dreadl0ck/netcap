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
	"compress/gzip"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
	"github.com/google/kythe/kythe/go/platform/delimited"
)

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
		Source:  b.ClientID,
		Version: netcap.Version,
	}

	var (
		// create buffered writer that writes into the file handle
		bWriter = bufio.NewWriter(f)
		// create gzip writer that writes into the buffered writer
		gWriter = gzip.NewWriter(bWriter)
	)

	// add file header
	err = delimited.NewWriter(gWriter).PutProto(encoder.NewHeader(b.MessageType, conf))
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

func cleanup() {

	fmt.Println("cleanup")

	// cleanup
	for p, a := range files {

		// flush and close gzip writer
		err := a.gWriter.Flush()
		if err != nil {
			panic(err)
		}

		err = a.gWriter.Close()
		if err != nil {
			panic(err)
		}

		// flush buffered writer
		err = a.bWriter.Flush()
		if err != nil {
			panic(err)
		}

		// sync and close file handle
		fmt.Println("closing file", p)
		err = a.f.Sync()
		if err != nil {
			panic(err)
		}
		err = a.f.Close()
		if err != nil {
			panic(err)
		}
	}
}

func handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// start signal handler and cleanup routine
	go func() {
		_ = <-sigs

		cleanup()
		os.Exit(0)
	}()
}
