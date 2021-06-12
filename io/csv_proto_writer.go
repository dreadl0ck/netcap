package io

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/netcap/label/manager"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
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
var labelManager = manager.NewLabelManager(false, false, false)

// InitLabelManager can be invoked to configure the labels
func InitLabelManager(pathMappingInfo string) {
	labelManager.Init(pathMappingInfo)
}

// writeRecord writes a protocol buffer into the CSV writer.
func (w *csvProtoWriter) writeRecord(msg proto.Message) (int, error) {

	if w.record, w.ok = msg.(types.AuditRecord); w.ok {

		// pass audit record to analyzer
		// TODO: invoke this in a different place?
		if w.analyze {
			w.record.Analyze()
		}

		if w.encode {
			// encode values to numeric format and normalize
			w.values = w.record.Encode()
			if w.label {
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

		w.Lock()
		n, err := w.w.Write(w.out)
		w.Unlock()

		if err != nil {
			//log.Println(err)
			time.Sleep(10 * time.Millisecond)
			goto again
		}

		return n, err
	}

	spew.Dump(msg)
	panic("can not write as CSV")
}
