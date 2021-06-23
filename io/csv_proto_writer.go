package io

import (
	"io"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/label/manager"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
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
	//values []string
	//out    []byte
	//record types.AuditRecord
	//ok     bool
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

	// TODO: make configurable and disable by default.
	// if !w.encode {
	// 	n, err := w.w.Write([]byte(fmt.Sprintf("# Type: %s, Created: %s, Source: %s, ContainsPayloads: %t\n", h.Type.String(), utils.UnixTimeToUTC(h.Created), h.InputSource, h.ContainsPayloads)))
	// 	if err != nil {
	// 		return n, err
	// 	}
	// }

	if csv, ok := msg.(types.AuditRecord); ok {

		if w.label {
			// TODO: make label column name configurable
			return w.w.Write([]byte(strings.Join(append(csv.CSVHeader(), "Category"), ",") + "\n"))
		}

		return w.w.Write([]byte(strings.Join(csv.CSVHeader(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("protocol buffer does not implement the types.AuditRecord interface")
}

var labelManager *manager.LabelManager

// InitLabelManager can be invoked to configure the labels
func InitLabelManager(pathMappingInfo string, debug bool, scatter bool, scatterDuration time.Duration) {
	labelManager = manager.NewLabelManager(false, false, false, scatter, scatterDuration)
	labelManager.Init(pathMappingInfo)
	labelManager.Debug = debug
}

var labelEncoder = encoder.NewValueEncoder()

// writeRecord writes a protocol buffer into the CSV writer.
func (w *csvProtoWriter) writeRecord(msg proto.Message) (int, error) {

	// TODO: we have two options:
	// 1) lock while encoding and normalizing the record, but reuse variable on writer to reduce allocs
	// 	  - less memory usage but every write blocks until worker is done
	// 2) avoid lock during processing and only lock for write, but alloc temp variables for record, values, out etc
	//    - likely better, since invoking analyzers and / or encoding takes time..
	if record, ok := msg.(types.AuditRecord); ok {

		// pass audit record to analyzer
		if w.analyze {
			// TODO: change Encode() signature so that it returns a []float64 vector
			// and calculate it only once, passing it to analyze when configured.
			record.Analyze()
		}

		var (
			values []string
			out    []byte
		)
		if w.encode {
			// encode values to numeric format and normalize
			values = record.Encode()
			if w.label {
				values = append(values, labelManager.Label(record))
			}
			out = []byte(strings.Join(values, ",") + "\n")
		} else {
			// use raw values
			values = record.CSVRecord()
			if w.label {
				values = append(values, labelManager.Label(record))
			}
			out = []byte(strings.Join(values, ",") + "\n")
		}

		fails := 0
	again:

		w.Lock()
		n, err := w.w.Write(out)
		w.Unlock()

		if err != nil {
			fails++

			// TODO: add configurable limit for number of allowed fails before stopping
			ioLog.Error("failed to write into unix socket, back off and retry", zap.Error(err), zap.Int("fails", fails))

			// TODO: make configurable
			time.Sleep(15 * time.Millisecond)
			goto again
		}

		return n, err
	}

	spew.Dump(msg)
	panic("can not write as CSV")
}
