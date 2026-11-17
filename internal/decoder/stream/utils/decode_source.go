package utils

import (
	"bufio"
	"errors"
	"io"
	"iter"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"go.uber.org/zap"
)

const (
	sourceReaderBufferBytes   = 4096
	sourceReaderFixedBytes    = sourceReaderBufferBytes + 512
	sourcePositionCreditBytes = 32
)

type sourceConversationCursor struct {
	next         func() (core.DataFragment, bool)
	pending      core.DataFragment
	started      [2]bool
	stopped      bool
	conversation *core.ConversationInfo
}

func (c *sourceConversationCursor) take() (core.DataFragment, bool) {
	if c.pending != nil {
		fragment := c.pending
		c.pending = nil
		return fragment, true
	}
	for !c.stopped {
		fragment, ok := c.next()
		if !ok {
			c.stopped = true
			return nil, false
		}
		if fragment == nil {
			continue
		}
		side := 0
		if core.FromServer(fragment) {
			side = 1
		}
		if data, ok := fragment.(*core.StreamData); ok && data.HasGap(c.started[side]) {
			c.stopped = true
			return nil, false
		}
		if len(fragment.Raw()) == 0 {
			continue
		}
		c.started[side] = true
		return fragment, true
	}
	return nil, false
}

func fragmentObservation(fragment core.DataFragment) string {
	if data, ok := fragment.(*core.StreamData); ok {
		return data.TCPObservation
	}
	return ""
}

type sourcePositionSpan struct {
	offset    int
	timestamp int64
}
type sourceRunReader struct {
	cursor      *sourceConversationCursor
	position    *ReadPosition
	data        []byte
	direction   reassembly.TCPFlowDirection
	observation string
	spans       []sourcePositionSpan
	head, read  int
	budget      *core.StateBudget
	credit      int64
	failure     error
}

func (r *sourceRunReader) timestamp(offset int) int64 {
	if len(r.spans) == 0 {
		return 0
	}
	index := r.head
	for index+1 < len(r.spans) && r.spans[index+1].offset <= offset {
		index++
	}
	return r.spans[index].timestamp
}

func (r *sourceRunReader) start(fragment core.DataFragment) error {
	if r.position != nil {
		consumed := r.position.Offset()
		for r.head+1 < len(r.spans) && r.spans[r.head+1].offset <= consumed {
			r.head++
		}
		if r.head > len(r.spans)/2 {
			copy(r.spans, r.spans[r.head:])
			r.spans = r.spans[:len(r.spans)-r.head]
			r.head = 0
		}
	}
	if len(r.spans) == cap(r.spans) {
		capacity := max(4, 2*cap(r.spans))
		amount := int64(capacity-cap(r.spans)) * sourcePositionCreditBytes
		if err := r.budget.Reserve(amount); err != nil {
			return err
		}
		r.credit += amount
		spans := make([]sourcePositionSpan, len(r.spans), capacity)
		copy(spans, r.spans)
		r.spans = spans
	}
	r.spans = append(r.spans, sourcePositionSpan{r.read, core.FragmentTime(fragment)})
	r.data = fragment.Raw()
	return nil
}

func (r *sourceRunReader) close() {
	r.budget.Release(r.credit)
	r.credit = 0
	r.spans = nil
	r.data = nil
}

func (r *sourceRunReader) Read(target []byte) (int, error) {
	if len(target) == 0 {
		return 0, nil
	}
	if r.failure != nil {
		return 0, r.failure
	}
	if len(r.data) == 0 {
		fragment, ok := r.cursor.take()
		if !ok {
			if err := r.cursor.conversation.FragmentError; err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		if fragment.Direction() != r.direction || fragmentObservation(fragment) != r.observation {
			r.cursor.pending = fragment
			return 0, io.EOF
		}
		if err := r.start(fragment); err != nil {
			r.failure = err
			return 0, err
		}
	}
	count := copy(target, r.data)
	r.data = r.data[count:]
	r.read += count
	return count, nil
}

func DecodeSourceConversation(conversation *core.ConversationInfo, client, server func(*bufio.Reader) error) error {
	return DecodeSourceConversationAt(conversation, func(reader *bufio.Reader, _ *ReadPosition) error { return client(reader) }, func(reader *bufio.Reader, _ *ReadPosition) error { return server(reader) })
}

// Each contiguous directional run is pulled on demand; parser state outlives reads.
func DecodeSourceConversationAt(conversation *core.ConversationInfo, client, server func(*bufio.Reader, *ReadPosition) error) (resultErr error) {
	defer func() {
		if resultErr != nil && conversation.FragmentError == nil {
			conversation.FragmentError = resultErr
		}
	}()
	next, stop := iter.Pull(conversation.Fragments())
	defer stop()
	cursor := &sourceConversationCursor{next: next, conversation: conversation}
	for {
		first, ok := cursor.take()
		if !ok {
			return conversation.FragmentError
		}
		if err := decodeSourceRun(conversation, cursor, first, client, server); err != nil {
			return err
		}
	}
}

func decodeSourceRun(conversation *core.ConversationInfo, cursor *sourceConversationCursor, first core.DataFragment, client, server func(*bufio.Reader, *ReadPosition) error) error {
	if err := conversation.StateBudget.Reserve(sourceReaderFixedBytes); err != nil {
		return err
	}
	run := &sourceRunReader{cursor: cursor, direction: first.Direction(), observation: fragmentObservation(first), budget: conversation.StateBudget, credit: sourceReaderFixedBytes}
	defer run.close()
	if err := run.start(first); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(run, sourceReaderBufferBytes)
	position := &ReadPosition{rd: reader, source: run, server: core.FromServer(first), observation: run.observation}
	run.position = position
	handle := client
	if position.server {
		handle = server
	}
	for {
		before := position.Offset()
		err := handle(reader, position)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			reassemblyLog.Error("error reading stream", zap.Error(err), zap.String("ident", conversation.Ident))
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || position.Offset() == before {
			break
		}
	}
	_, err := io.Copy(io.Discard, reader)
	return err
}
