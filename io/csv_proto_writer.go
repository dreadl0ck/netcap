package io

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/netcap/label/manager"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"
	"io"
	"strings"
	"sync"
	"time"
)

// csvProtoWriter implements writing audit records to disk in the CSV format.
type csvProtoWriter struct {

	// locking
	sync.Mutex

	// writer
	w io.Writer

	// config
	encode  bool
	analyze bool
	label   bool

	// avoid allocations by reusing these variables
	values []string
	out    []byte
	record types.AuditRecord
	ok     bool
}

// newCSVProtoWriter returns a new CSV writer instance.
func newCSVProtoWriter(w io.Writer, encode bool, label bool) *csvProtoWriter {
	return &csvProtoWriter{
		w:      w,
		encode: encode,
		label:  label,
	}
}

// writeHeader writes the CSV header to the underlying file.
func (w *csvProtoWriter) writeHeader(h *types.Header, msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	n, err := w.w.Write([]byte(fmt.Sprintf("# Type: %s, Created: %s, Source: %s, ContainsPayloads: %t\n", h.Type.String(), utils.UnixTimeToUTC(h.Created), h.InputSource, h.ContainsPayloads)))
	if err != nil {
		return n, err
	}

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVHeader(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("protocol buffer does not implement the types.AuditRecord interface")
}

// TODO: make configurable
var labelManager = manager.NewLabelManager(false, true, false)

// InitLabelManager can be invoked to configure the labels
func InitLabelManager(pathMappingInfo string) {
	labelManager.Init(pathMappingInfo)
}

// writeRecord writes a protocol buffer into the CSV writer.
func (w *csvProtoWriter) writeRecord(msg proto.Message) (int, error) {

	w.Lock()

	// TODO: we have two options:
	// 1) lock while encoding and normalizing the record, but reuse variable on writer to reduce allocs
	// 	  - less memory usage but every write blocks until worker is done
	// 2) avoid lock during processing and only lock for write, but alloc temp variables for record, values, out etc
	//    - likely better, since invoking analyzers and / or encoding takes time..
	if w.record, w.ok = msg.(types.AuditRecord); w.ok {

		// pass audit record to analyzer
		if w.analyze {
			// TODO: change Encode() signature so that it returns a []float64 vector
			// and calculate it only once, passing it to analyze when configured.
			w.record.Analyze()
		}

		if w.encode {
			// encode values to numeric format and normalize
			w.values = w.record.Encode()
			if w.label {
				// TODO: encode label
				w.values = append(w.values, labelManager.Label(w.record))
			}
			w.out = []byte(strings.Join(w.values, ","))
		} else {
			// use raw values
			w.values = w.record.CSVRecord()
			if w.label {
				w.values = append(w.values, labelManager.Label(w.record))
			}
			w.out = []byte(strings.Join(w.values, ",") + "\n")
		}

	again:

		n, err := w.w.Write(w.out)
		if err != nil {
			ioLog.Error("failed to write into unix socket, back off and retry", zap.Error(err))
			time.Sleep(5 * time.Millisecond)
			goto again
		}
		w.Unlock()

		return n, err
	}

	spew.Dump(msg)
	panic("can not write as CSV")
}
