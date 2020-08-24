package io

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
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
func closeFile(outDir string, file *os.File, typ string) (name string, size int64) {
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

	return i.Name(), removeAuditRecordFileIfEmpty(filepath.Join(outDir, i.Name()))
}

// removeAuditRecordFileIfEmpty removes the audit record file if it does not contain audit records.
func removeAuditRecordFileIfEmpty(name string) (size int64) {
	if isCSV(name) || isJSON(name) {
		return removeEmptyNewlineDelimitedFile(name)
	}

	// Check if audit record file contains records
	// Open, read header and the first audit record and return
	r, err := Open(name, defaults.BufferSize)
	if err != nil { // TODO: cleanup
		// suppress errors for OSPF because the file handle will be closed twice
		// since both v2 and v3 have the same gopacket.LayerType == "OSPF"
		if !strings.HasPrefix(name, "OSPF") {
			fmt.Println("unable to open file:", name, "error", err)
		}

		return 0
	}

	defer func() {
		errClose := r.Close()
		if errClose != nil {
			fmt.Println("failed to close netcap.Reader:", errClose)
		}
	}()

	var (
		header, errFileHeader = r.ReadHeader()
		record                = InitRecord(header.Type)
	)

	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}

	err = r.Next(record)
	if err != nil {
		// remove file
		err = os.Remove(name)
		if err != nil {
			fmt.Println("failed to remove file", err)

			// return file size of zero
			return 0
		}

		return
	}

	// dont remove file, it contains audit records
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
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	var r *bufio.Reader

	if strings.HasSuffix(name, ".gz") {
		var gr *gzip.Reader

		gr, err = gzip.NewReader(f)
		if err != nil {
			panic(err)
		}

		r = bufio.NewReader(gr)
	} else {
		r = bufio.NewReader(f)
	}

	count := 0

	for {
		_, _, err = r.ReadLine()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}
		count++

		if count > 1 {
			break
		}
	}

	if count < 2 {
		// remove file
		err = os.Remove(name)
		if err != nil {
			fmt.Println("failed to remove file", err)
		}

		// return file size of zero
		return 0
	}

	// dont remove file
	// return final file size
	s, err := os.Stat(name)
	if err != nil {
		fmt.Println("failed to stat file:", name, err)

		return
	}

	return s.Size()
}

// createFile is a wrapper to create new audit record file.
func createFile(name, ext string) *os.File {
	f, err := os.Create(name + ext)
	if err != nil {
		panic(err)
	}

	return f
}
