package utils

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
)

// DecodeConversation is a Transport layer agnostic util to decode client / server data streams.
func DecodeConversation(
	ident string,
	data core.DataFragments,
	client func(buf *bufio.Reader) error,
	server func(buf *bufio.Reader) error,
) {
	var (
		buf         bytes.Buffer
		previousDir reassembly.TCPFlowDirection
	)

	if len(data) > 0 {
		previousDir = data[0].Direction()
	}

	// parse conversation
	for _, d := range data {
		if d.Direction() == previousDir {
			buf.Write(d.Raw())
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
				reassemblyLog.Error("error reading stream",
					zap.Error(err),
					zap.String("ident", ident),
				)
			}
			buf.Reset()
			previousDir = d.Direction()

			buf.Write(d.Raw())

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
		reassemblyLog.Error("error reading stream",
			zap.Error(err),
			zap.String("ident", ident),
		)
	}
}
