package utils

import (
	"bufio"
	"iter"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

// The caller supplies one directional, loss-bounded range and qualifies its initial loss.
func WithSourceReader(c *core.ConversationInfo, source core.FragmentSource, server bool, bufferSize int, consume func(*bufio.Reader, *ReadPosition) error) error {
	var sourceErr error
	next, stop := iter.Pull(core.SourceFragments(source, &sourceErr))
	defer stop()
	cursor := &sourceConversationCursor{next: next, conversation: c, allowInitialLoss: true}
	first, ok := cursor.take()
	if !ok {
		if sourceErr != nil {
			c.FragmentError = sourceErr
		}
		return sourceErr
	}
	bufferSize = max(sourceReaderBufferBytes, min(65536, bufferSize))
	credit := int64(bufferSize + 512)
	if err := c.StateBudget.Reserve(credit); err != nil {
		c.FragmentError = err
		return err
	}
	run := &sourceRunReader{cursor: cursor, direction: first.Direction(), observation: fragmentObservation(first), budget: c.StateBudget, credit: credit}
	defer run.close()
	if err := run.start(first); err != nil {
		c.FragmentError = err
		return err
	}
	reader := bufio.NewReaderSize(run, bufferSize)
	position := &ReadPosition{rd: reader, source: run, server: server, observation: run.observation}
	run.position = position
	err := consume(reader, position)
	if run.failure != nil {
		c.FragmentError = run.failure
		return run.failure
	}
	if sourceErr != nil {
		c.FragmentError = sourceErr
		return sourceErr
	}
	return err
}

func WalkSourceGapRuns(source core.RangedFragmentSource, consume func(core.RangedFragmentSource, bool, bool) error) error {
	if marks, ok := core.SourceMarks(source); ok {
		return markedGapRuns(source, marks, consume)
	}
	var index, start int64
	lost, unknown, seen := false, false, false
	var consumeErr error
	err := source.Walk(func(fragment core.DataFragment) bool {
		if data, ok := fragment.(*core.StreamData); ok && (data.SkippedBytes != 0 || data.DiscardedBytes > 0) {
			if data.SkippedBytes == -1 && !seen && data.DiscardedBytes == 0 {
				unknown = true
			} else {
				if index > start {
					consumeErr = consume(core.FragmentRange(source, start, index-start), lost, unknown)
					if consumeErr != nil {
						return false
					}
				}
				start = index
				lost = true
			}
		}
		seen = seen || len(fragment.Raw()) > 0
		index++
		return true
	})
	if err != nil {
		return err
	}
	if consumeErr != nil {
		return consumeErr
	}
	if index > start {
		return consume(core.FragmentRange(source, start, index-start), lost, unknown)
	}
	return nil
}

// Same runs as the walk above, read from the boundary index alone.
func markedGapRuns(source core.RangedFragmentSource, marks []core.FragmentMark, consume func(core.RangedFragmentSource, bool, bool) error) error {
	var start int64
	lost, unknown := false, false
	for _, mark := range marks {
		data, err := core.MarkedFragment(source, mark.Index)
		if err != nil {
			return err
		}
		if data == nil || data.SkippedBytes == 0 && data.DiscardedBytes <= 0 {
			continue
		}
		if data.SkippedBytes == -1 && mark.PayloadEnd == 0 && data.DiscardedBytes == 0 {
			unknown = true
			continue
		}
		if mark.Index > start {
			if err := consume(core.FragmentRange(source, start, mark.Index-start), lost, unknown); err != nil {
				return err
			}
		}
		start, lost = mark.Index, true
	}
	if count := source.Count(); count > start {
		return consume(core.FragmentRange(source, start, count-start), lost, unknown)
	}
	return nil
}
