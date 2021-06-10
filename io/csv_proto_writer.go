package io

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
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
	sync.Mutex
	w      io.Writer
	encode bool
}

// newCSVProtoWriter returns a new CSV writer instance.
func newCSVProtoWriter(w io.Writer, encode bool) *csvProtoWriter {
	return &csvProtoWriter{
		w:      w,
		encode: encode,
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

// writeRecord writes a protocol buffer into the CSV writer.
func (w *csvProtoWriter) writeRecord(msg proto.Message) (int, error) {

	if csv, ok := msg.(types.AuditRecord); ok {
		var out []byte
		if w.encode {
			out = []byte(strings.Join(csv.Encode(), ",") + "\n")
		} else {
			out = []byte(strings.Join(csv.CSVRecord(), ",") + "\n")
		}

	again:

		w.Lock()
		n, err := w.w.Write(out)
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
