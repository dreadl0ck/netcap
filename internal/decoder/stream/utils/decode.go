package utils

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

// ReadPosition reports where in the capture a line-oriented reader currently
// is.
//
// Readers driven through a bufio.Reader used to have nothing to timestamp a
// record with except ConversationInfo.FirstClientPacket, so every FTP command,
// IMAP response and IRC message in a session carried the time the session
// opened. A conversation held open for hours collapsed to one instant.
//
// The offset is exact rather than approximate: bytes handed to the buffer,
// minus what the buffer still holds, minus what bufio has read ahead and not
// yet returned.
type ReadPosition struct {
	index *core.FragmentIndex
	buf   *bytes.Buffer
	rd    *bufio.Reader

	written int
	server  bool
}

// Offset returns how many bytes of the current direction the reader has
// consumed.
func (p *ReadPosition) Offset() int {
	if p == nil {
		return 0
	}

	consumed := p.written - p.buf.Len() - p.rd.Buffered()
	if consumed < 0 {
		return 0
	}

	return consumed
}

// Timestamp returns the capture time of the packet carrying the byte the reader
// is positioned at, in Unix nanoseconds.
func (p *ReadPosition) Timestamp() int64 {
	if p == nil || p.index == nil {
		return 0
	}

	ts, _ := p.index.At(p.Offset())

	return ts
}

// FromServer reports whether the current direction is the server's.
func (p *ReadPosition) FromServer() bool {
	return p != nil && p.server
}

// DecodeConversation is a Transport layer agnostic util to decode client / server data streams.
func DecodeConversation(
	ident string,
	data core.DataFragments,
	client func(buf *bufio.Reader) error,
	server func(buf *bufio.Reader) error,
) {
	DecodeConversationAt(ident, data,
		func(b *bufio.Reader, _ *ReadPosition) error { return client(b) },
		func(b *bufio.Reader, _ *ReadPosition) error { return server(b) },
	)
}

// DecodeConversationAt is DecodeConversation with the read position exposed, so
// a reader can timestamp each message from the packet that carried it.
func DecodeConversationAt(
	ident string,
	data core.DataFragments,
	client func(buf *bufio.Reader, pos *ReadPosition) error,
	server func(buf *bufio.Reader, pos *ReadPosition) error,
) {
	var (
		buf         bytes.Buffer
		run         core.DataFragments
		previousDir reassembly.TCPFlowDirection
	)

	if len(data) > 0 {
		previousDir = data[0].Direction()
	}

	// A run is the consecutive fragments traveling the same way. Each is
	// drained through its own bufio.Reader, so the position is scoped to it.
	drain := func() {
		var (
			err error
			rd  = bufio.NewReader(&buf)
		)

		_, index := core.Flatten(run)

		pos := &ReadPosition{
			index:   index,
			buf:     &buf,
			rd:      rd,
			written: buf.Len(),
			server:  previousDir == reassembly.TCPDirServerToClient,
		}

		handle := client
		if pos.server {
			handle = server
		}

		for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			err = handle(rd, pos)
		}

		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			reassemblyLog.Error("error reading stream",
				zap.Error(err),
				zap.String("ident", ident),
			)
		}
	}

	for _, d := range data {
		if d.Direction() == previousDir {
			buf.Write(d.Raw())
			run = append(run, d)

			continue
		}

		drain()

		buf.Reset()
		run = core.DataFragments{d}
		previousDir = d.Direction()

		buf.Write(d.Raw())
	}

	drain()
}
