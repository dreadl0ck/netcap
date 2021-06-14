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
	"fmt"
	"go.uber.org/zap"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/defaults"
)

/*
 *	Utils
 */

type flushableWriter interface {
	Flush() error
}

func flushWriters(writers ...flushableWriter) {
	for _, w := range writers {
		err := w.Flush()
		if err != nil {
			panic(err)
		}
	}
}

func closeGzipWriters(writers ...*pgzip.Writer) {
	for _, w := range writers {
		err := w.Flush()
		if err != nil {
			panic(err)
		}

		err = w.Close()
		if err != nil {
			panic(err)
		}
	}
}

// closeFile closes the netcap file handle
// and removes files that do only contain a header but no audit records.
func closeFile(outDir string, file *os.File, typ string, numRecords int64) (name string, size int64) {
	i, err := file.Stat()
	if err != nil {
		fmt.Println("[ERROR] failed to stat file:", err, "type", typ)

		return "", 0
	}

	var (
		errSync  = file.Sync()
		errClose = file.Close()
	)

	if errSync != nil || errClose != nil {
		fmt.Println("error while closing", i.Name(), "errSync", errSync, "errClose", errClose)
	}

	return i.Name(), removeAuditRecordFileIfEmpty(filepath.Join(outDir, i.Name()), numRecords)
}

// removeAuditRecordFileIfEmpty removes the audit record file if it does not contain audit records.
func removeAuditRecordFileIfEmpty(name string, numRecords int64) (size int64) {

	ioLog.Info("remove if empty", zap.String("name", name), zap.Bool("isCSV", isCSV(name)), zap.Int64("numRecords", numRecords))

	if numRecords == 0 && (isCSV(name) || isJSON(name)) {
		return removeEmptyNewlineDelimitedFile(name)
	}

	if numRecords == 0 {
		// remove file
		err := os.Remove(name)
		if err != nil {
			fmt.Println("failed to remove file", err)
		}
		return 0
	}

	// don't remove file, it contains audit records
	// return final file size
	s, err := os.Stat(name)
	if err != nil {
		fmt.Println("failed to stat file:", name, err)

		return
	}

	return s.Size()
}

func isCSV(name string) bool {
	return strings.HasSuffix(name, ".csv") || strings.HasSuffix(name, ".csv.gz")
}

func isJSON(name string) bool {
	return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz")
}

func removeEmptyNewlineDelimitedFile(name string) (size int64) {
	ioLog.Info("removing empty file", zap.String("name", name))

	// remove file
	err := os.Remove(name)
	if err != nil {
		fmt.Println("failed to remove file", err)
	}

	// return file size of zero
	return 0
}

// createFile is a wrapper to create new audit record file.
func createFile(name, ext string) *os.File {
	f, err := os.OpenFile(name+ext, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, defaults.FilePermission)
	if err != nil {
		panic(err)
	}

	return f
}

const (
	networkTypeUnix       = "unix"
	networkTypeUnixgram   = "unixgram"
	networkTypeUnixpacket = "unixpacket"
)

// createFile is a wrapper to create new audit record file.
func createUnixSocket(name string) *net.UnixConn {

	path := filepath.Join("/tmp/" + name + ".sock")

	//if err := os.RemoveAll(path); err != nil {
	//	log.Fatal(err)
	//}

	// Create unix socket
	raddr, err := net.ResolveUnixAddr(networkTypeUnixgram, path)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUnix(networkTypeUnixgram, nil, raddr)
	if err != nil {
		log.Fatal(err)
	}

	return conn
}
