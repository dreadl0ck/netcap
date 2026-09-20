package protobuf

import (
	"bufio"
	"bytes"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
)

type protobufTestWriter struct {
	err error
}

func (w *protobufTestWriter) Write(proto.Message) error { return w.err }
func (w *protobufTestWriter) WriteHeader(types.Type) error {
	return nil
}
func (w *protobufTestWriter) Close(int64) (string, int64) { return "", 0 }
func (w *protobufTestWriter) Flush() error                { return nil }

func setupProcessDataTest(t *testing.T, writeErr error, errorMap *decoderutils.AtomicCounterMap) (*protobufReader, *observer.ObservedLogs) {
	t.Helper()

	oldWriter := Decoder.Writer
	oldCount := atomic.LoadInt64(&Decoder.NumRecordsWritten)
	oldLog := pbLog
	oldErrorMap := decoderutils.ErrorMap
	oldConfig := decoderconfig.Instance
	t.Cleanup(func() {
		Decoder.Writer = oldWriter
		atomic.StoreInt64(&Decoder.NumRecordsWritten, oldCount)
		pbLog = oldLog
		decoderutils.ErrorMap = oldErrorMap
		decoderconfig.Instance = oldConfig
	})

	observedCore, logs := observer.New(zapcore.DebugLevel)
	pbLog = zap.New(observedCore)
	Decoder.Writer = &protobufTestWriter{err: writeErr}
	atomic.StoreInt64(&Decoder.NumRecordsWritten, 0)
	decoderutils.ErrorMap = errorMap
	decoderconfig.Instance = &decoderconfig.Config{}

	return &protobufReader{conversation: &core.ConversationInfo{}}, logs
}

func TestProcessDataWriteFailureIsVisible(t *testing.T) {
	errorMap := decoderutils.NewAtomicCounterMap()
	reader, logs := setupProcessDataTest(t, errors.New("disk full"), errorMap)

	for range 2 {
		if err := reader.processData(bufio.NewReader(bytes.NewReader(validProtobufData)), true); err != nil {
			t.Fatalf("processData() error = %v, want nil", err)
		}
	}

	entries := logs.FilterMessage(protobufWriteError).All()
	if len(entries) != 2 {
		t.Fatalf("error log count = %d, want 2", len(entries))
	}
	if entries[0].Level != zapcore.ErrorLevel {
		t.Errorf("log level = %s, want error", entries[0].Level)
	}
	if got := entries[0].ContextMap()["error"]; got != "disk full" {
		t.Errorf("logged error = %v, want %q", got, "disk full")
	}
	if got := errorMap.Snapshot()[protobufWriteError]; got != 2 {
		t.Errorf("ErrorMap count = %d, want 2", got)
	}
	if got := atomic.LoadInt64(&Decoder.NumRecordsWritten); got != 0 {
		t.Errorf("NumRecordsWritten = %d, want 0", got)
	}
}

func TestProcessDataWriteSuccessIncrementsRecordCount(t *testing.T) {
	reader, _ := setupProcessDataTest(t, nil, decoderutils.NewAtomicCounterMap())

	if err := reader.processData(bufio.NewReader(bytes.NewReader(validProtobufData)), true); err != nil {
		t.Fatalf("processData() error = %v, want nil", err)
	}
	if got := atomic.LoadInt64(&Decoder.NumRecordsWritten); got != 1 {
		t.Errorf("NumRecordsWritten = %d, want 1", got)
	}
}

func TestProcessDataWriteFailureWithNilErrorMap(t *testing.T) {
	reader, logs := setupProcessDataTest(t, errors.New("writer unavailable"), nil)

	if err := reader.processData(bufio.NewReader(bytes.NewReader(validProtobufData)), false); err != nil {
		t.Fatalf("processData() error = %v, want nil", err)
	}
	if got := logs.FilterMessage(protobufWriteError).Len(); got != 1 {
		t.Errorf("error log count = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&Decoder.NumRecordsWritten); got != 0 {
		t.Errorf("NumRecordsWritten = %d, want 0", got)
	}
}
