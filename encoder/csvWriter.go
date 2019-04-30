/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"io"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

type csvWriter struct {
	w io.Writer
	sync.Mutex
}

func NewCSVWriter(w io.Writer) *csvWriter {
	return &csvWriter{
		w: w,
	}
}

func (w *csvWriter) WriteHeader(msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVHeader(), ",") + "\n"))
	}

	panic("can not write as CSV" + msg.String())
}

func (w *csvWriter) WriteRecord(msg proto.Message) (int, error) {

	w.Lock()
	defer w.Unlock()

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVRecord(), ",") + "\n"))
	}

	panic("can not write as CSV" + msg.String())
}

func (w *csvWriter) Close() error {
	return nil
}
