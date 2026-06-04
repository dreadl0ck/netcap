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
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

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
		if w == nil {
			continue
		}

		err := w.Flush()
		if err != nil {
			// Log error but don't panic - writer might already be closed
			ioLog.Error("failed to flush writer", zap.Error(err))
		}
	}
}

func closeGzipWriters(writers ...*pgzip.Writer) {
	for _, w := range writers {
		if w == nil {
			continue
		}

		err := w.Flush()
		if err != nil {
			// Log error but don't panic - writer might already be closed
			ioLog.Error("failed to flush gzip writer", zap.Error(err))
		}

		err = w.Close()
		if err != nil {
			// Log error but don't panic - writer might already be closed
			ioLog.Error("failed to close gzip writer", zap.Error(err))
		}
	}
}

// closeFile closes the netcap file handle
// and removes files that do only contain a header but no audit records.
func closeFile(outDir string, file *os.File, typ string, numRecords int64) (name string, size int64) {
	i, err := file.Stat()
	if err != nil {
		ioLog.Error("failed to stat file", zap.Error(err), zap.String("type", typ))

		return "", 0
	}

	var (
		errSync  = file.Sync()
		errClose = file.Close()
	)

	if errSync != nil || errClose != nil {
		ioLog.Error("error while closing file", zap.String("name", i.Name()), zap.NamedError("errSync", errSync), zap.NamedError("errClose", errClose))
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
			ioLog.Error("failed to remove file", zap.String("name", name), zap.Error(err))
		}
		return 0
	}

	// don't remove file, it contains audit records
	// return final file size
	s, err := os.Stat(name)
	if err != nil {
		ioLog.Error("failed to stat file", zap.String("name", name), zap.Error(err))

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
		ioLog.Error("failed to remove empty file", zap.String("name", name), zap.Error(err))
	}

	// return file size of zero
	return 0
}

// createFile is a wrapper to create new audit record file.
//
// It panics on failure: this runs at writer-construction (capture startup)
// time, where an inability to create the output file (bad path, permissions,
// full disk) is an unrecoverable configuration error rather than a per-record
// condition. The per-record write paths return errors instead of panicking.
func createFile(name, ext string) *os.File {
	f, err := os.OpenFile(name+ext, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, defaults.FilePermission)
	if err != nil {
		panic(fmt.Errorf("io: failed to create audit record file %q: %w", name+ext, err))
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
