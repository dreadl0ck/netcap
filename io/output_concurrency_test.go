package io

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
	"github.com/klauspost/pgzip"
)

func TestOutputConcurrentWriteFlush(t *testing.T) {
	for _, socket := range []bool{false, true} {
		for _, buffered := range []bool{false, true} {
			for _, compressed := range []bool{false, true} {
				t.Run(fmt.Sprintf("socket=%t/buffer=%t/compress=%t", socket, buffered, compressed), func(t *testing.T) {
					wc := &WriterConfig{
						Name: "TCP", Out: t.TempDir(), Type: types.Type_NC_TCP,
						Buffer: buffered, Compress: compressed, MemBufferSize: 4096,
						CompressionLevel: gzip.BestSpeed, CompressionBlockSize: defaults.CompressionBlockSize,
					}
					var w AuditRecordWriter
					var output func() []byte
					if socket {
						// Use a stream socket so EOF confirms all output, including the gzip trailer.
						dir, err := os.MkdirTemp("/tmp", "netcap-io-")
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = os.RemoveAll(dir) })
						addr := &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"}
						listener, err := net.ListenUnix("unix", addr)
						if err != nil {
							t.Fatal(err)
						}
						defer listener.Close()
						conn, err := net.DialUnix("unix", nil, addr)
						if err != nil {
							t.Fatal(err)
						}
						defer conn.Close()
						peer, err := listener.AcceptUnix()
						if err != nil {
							t.Fatal(err)
						}
						defer peer.Close()
						if err := peer.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
							t.Fatal(err)
						}
						result := make(chan []byte, 1)
						go func() {
							data, err := io.ReadAll(peer)
							if err != nil {
								t.Error(err)
							}
							result <- data
						}()
						sw := &unixSocketWriter{wc: wc, conn: conn}
						var dest io.Writer = conn
						if buffered {
							sw.bWriter = bufio.NewWriterSize(dest, wc.MemBufferSize)
							dest = sw.bWriter
						}
						if compressed {
							sw.gWriter = pgzip.NewWriter(dest)
							dest = sw.gWriter
						}
						sw.unixSocketWriter = newCSVProtoWriter(dest, false, false, nil)
						w = sw
						output = func() []byte { return <-result }
					} else {
						jw := newJSONWriter(wc)
						w = jw
						output = func() []byte {
							data, err := os.ReadFile(jw.file.Name())
							if err != nil {
								t.Fatal(err)
							}
							return data
						}
					}
					defer w.Close(1)
					if err := w.WriteHeader(types.Type_NC_TCP); err != nil {
						t.Fatal(err)
					}

					const producers, records = 4, 100
					start, stop, flushed := make(chan struct{}), make(chan struct{}), make(chan struct{})
					go func() {
						defer close(flushed)
						<-start
						for {
							if err := w.Flush(); err != nil {
								t.Error(err)
								return
							}
							select {
							case <-stop:
								return
							case <-time.After(time.Millisecond):
							}
						}
					}()
					var wg sync.WaitGroup
					for range producers {
						wg.Add(1)
						go func() {
							defer wg.Done()
							<-start
							for range records {
								if err := w.Write(&types.TCP{SrcPort: 1234}); err != nil {
									t.Error(err)
									return
								}
							}
						}()
					}
					close(start)
					wg.Wait()
					w.Close(producers * records)
					close(stop)
					<-flushed
					if err := w.Write(&types.TCP{SrcPort: 9999}); err != nil {
						t.Fatalf("write after close: %v", err)
					}
					if err := w.WriteHeader(types.Type_NC_TCP); err != nil {
						t.Fatalf("header after close: %v", err)
					}
					if err := w.Flush(); err != nil {
						t.Fatalf("flush after close: %v", err)
					}
					if name, size := w.Close(producers * records); name != "" || size != 0 {
						t.Fatalf("repeated close returned %q, %d", name, size)
					}

					data := output()
					if compressed {
						reader, err := gzip.NewReader(bytes.NewReader(data))
						if err != nil {
							t.Fatal(err)
						}
						defer reader.Close()
						data, err = io.ReadAll(reader)
						if err != nil {
							t.Fatalf("incomplete gzip output: %v", err)
						}
					}
					lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
					if len(lines) != 1+producers*records {
						t.Fatalf("got %d lines, want %d", len(lines), 1+producers*records)
					}
					record := &types.TCP{SrcPort: 1234}
					want, err := record.JSON()
					if err != nil {
						t.Fatal(err)
					}
					if socket {
						want = strings.Join(record.CSVRecord(), ",")
					}
					for i, line := range lines[1:] {
						if line != want {
							t.Fatalf("record %d corrupted: %q", i, line)
						}
					}
				})
			}
		}
	}
}
