package stream

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/blevesearch/bleve"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

const (
	protoTCP      = "TCP"
	protoUDP      = "UDP"
	servicePOP3   = "POP3"
	serviceTelnet = "Telnet"
	serviceFTP    = "FTP"
	serviceHTTP   = "HTTP"
	serviceSSH    = "SSH"

	typeTCP             = "tcp"
	binaryFileExtension = ".bin"
)

// OpenBleve is a simple wrapper for the bleve open call
// it's used to log any open operations.
func openBleve(path string) (bleve.Index, error) {
	streamLog.Info("opening bleve db", zap.String("path", path))

	return bleve.Open(path)
}

// CloseBleve is a simple wrapper for the bleve close call
// it's used to log any close operations.
func closeBleve(index io.Closer) {
	if index == nil {
		return
	}

	streamLog.Info("closing bleve db", zap.String("index", fmt.Sprint(index)))

	err := index.Close()
	if err != nil {
		fmt.Println(err)
	}
}

func printProgress(current, total int64) {
	if current%5 == 0 {
		utils.ClearLine()
		print("flushing... (" + progress(current, total) + ")")
	}
}

func progress(current, total int64) string {
	percent := (float64(current) / float64(total)) * 100
	return strconv.Itoa(int(percent)) + "%"
}

func logReassemblyError(task string, msg string, err error) {
	stats.Lock()
	stats.numErrors++
	stats.Unlock()

	errorsMapMutex.Lock()
	nb := errorsMap[task]
	errorsMap[task] = nb + 1
	errorsMapMutex.Unlock()

	reassemblyLog.Error(msg, zap.Error(err))
}

// keep track which paths for content types of extracted files have already been created.
var (
	contentTypeMap   = make(map[string]struct{})
	contentTypeMapMu sync.Mutex
)

// createContentTypePathIfRequired will create the passed in filesystem path once
// it is safe for concurrent access and will block until the path has been created on disk.
func createContentTypePathIfRequired(fsPath string) {
	contentTypeMapMu.Lock()
	if _, ok := contentTypeMap[fsPath]; !ok { // the path has not been created yet
		// add to map
		contentTypeMap[fsPath] = struct{}{}

		// create path
		err := os.MkdirAll(fsPath, defaults.DirectoryPermission)
		if err != nil {
			logReassemblyError("HTTP-create-path", fmt.Sprintf("cannot create folder %s", fsPath), err)
		}
	}
	// free lock again
	contentTypeMapMu.Unlock()
}

func trimEncoding(ctype string) string {
	parts := strings.Split(ctype, ";")
	if len(parts) > 1 {
		return parts[0]
	}
	return ctype
}

// func decodeTCPConversation(parent *tcpConnection, client func(buf *bufio.Reader) error, server func(buf *bufio.Reader) error) {
func decodeConversation(ident string, data dataFragments, client func(buf *bufio.Reader) error, server func(buf *bufio.Reader) error) {
	var (
		buf         bytes.Buffer
		previousDir reassembly.TCPFlowDirection
	)

	if len(data) > 0 {
		previousDir = data[0].direction()
	}

	// parse conversation
	for _, d := range data {
		if d.direction() == previousDir {
			buf.Write(d.raw())
		} else {
			var (
				err error
				b   = bufio.NewReader(&buf)
			)

			if previousDir == reassembly.TCPDirClientToServer {
				for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					err = client(b)
				}
			} else {
				for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					err = server(b)
				}
			}
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				streamLog.Error("error reading stream",
					zap.Error(err),
					zap.String("ident", ident),
				)
			}
			buf.Reset()
			previousDir = d.direction()

			buf.Write(d.raw())

			continue
		}
	}

	var (
		err error
		b   = bufio.NewReader(&buf)
	)

	if previousDir == reassembly.TCPDirClientToServer {
		for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			err = client(b)
		}
	} else {
		for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			err = server(b)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		streamLog.Error("error reading stream",
			zap.Error(err),
			zap.String("ident", ident),
		)
	}
}
