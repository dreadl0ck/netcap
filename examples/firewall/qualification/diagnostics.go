//go:build coraza && http3

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// Never persist an arbitrary error string: HTTP errors can contain credentials.
type wireError struct {
	Stage    string
	Category string
	Header   string
	Read     int
	Want     int
	Cause    error
}

func (e *wireError) Error() string {
	return fmt.Sprintf("%s: %s header=%s read=%d want=%d", e.Stage, e.Category, e.Header, e.Read, e.Want)
}
func (e *wireError) Unwrap() error { return e.Cause }

func errorCategory(err error) string {
	var timeout net.Error
	switch {
	case err == nil:
		return "unexpected-status"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "partial-eof"
	case errors.Is(err, io.EOF):
		return "eof"
	default:
		return "transport"
	}
}

func wireStage(stage string, err error) error {
	var inner *wireError
	if errors.As(err, &inner) {
		stage += "/" + inner.Stage
	}
	return &wireError{Stage: stage, Category: errorCategory(err), Cause: err}
}

type requestFailure struct {
	Sequence                                   uint64
	Attack                                     bool
	Status                                     int
	Stage, Category, Header                    string
	Read, Want                                 int
	ElapsedSeconds, ScheduleDelayMS, RequestMS float64
	FaultAtStart, FaultAtEnd                   int64
}

func describeFailure(err error) requestFailure {
	f := requestFailure{Category: "unexpected-status"}
	if err == nil {
		return f
	}
	f.Category = errorCategory(err)
	var wire *wireError
	if errors.As(err, &wire) {
		f.Stage, f.Category, f.Header, f.Read, f.Want = wire.Stage, wire.Category, wire.Header, wire.Read, wire.Want
	}
	return f
}
