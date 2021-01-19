/*
 * NETCAP - Network Capture Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package delimited

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

const testData = "\x00\x01N\x02ET\x03CAP"

/*
 *	WRITER
 */

func TestCorruptedWriter(t *testing.T) {
	var (
		bad    = errors.New("BAD")
		buffer = &errWriter{
			nc:  1,
			err: bad,
		}
		wr = NewWriter(buffer)
	)

	err := wr.Put([]byte("NOTBAD"))
	if err == nil {
		t.Fatalf("Put: returned error nil, want error %v", bad)
	}
	t.Logf("Put record returned expected error: %v", err)
}

func TestGoodWriter(t *testing.T) {
	var (
		buffer bytes.Buffer
		wr     = NewWriter(&buffer)
	)

	// iterate over records
	for _, record := range []string{"", "N", "ET", "CAP"} {
		if err := wr.Put([]byte(record)); err != nil {
			t.Errorf("Put %q: unexpected error: %v", record, err)
		}
	}

	// convert buffer to string
	if got := buffer.String(); got != testData {
		t.Errorf("Writer result: got %q, want %q", got, testData)
	}
}

/*
 *	READER
 */

func TestCorruptedReader(t *testing.T) {
	const corrupt = "\x05NETC" // n = 5, only 4 bytes of data

	var (
		r  = strings.NewReader(corrupt)
		rd = NewReader(r)
	)

	// fetch next record
	got, err := rd.Next()
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("Next record: got %q [%v], but want %v", string(got), err, io.ErrUnexpectedEOF)
	}
	t.Logf("Next record returned expected error: %v", err)
}

func TestGoodReader(t *testing.T) {
	var (
		r  = strings.NewReader(testData)
		rd = NewReader(r)
	)

	// iterate over records
	for _, want := range []string{"", "N", "ET", "CAP"} {

		// fetch next
		got, err := rd.Next()
		if err != nil {
			t.Errorf("Unexpected read error: %v", err)
		} else if s := string(got); s != want {
			t.Errorf("Next record: got %q, want %q", s, want)
		}
	}

	// the stream should have been fully consumed
	if got, err := rd.Next(); err != io.EOF {
		t.Errorf("Next record returned %q [%v], but want EOF", string(got), err)
	}
}

/*
 *	ROUND TRIP
 */

func TestRoundTrip(t *testing.T) {
	const input = "Some of what a fool thinks often remains."

	// write all the words in the input as records to a delimited writer
	var (
		words  = strings.Fields(input)
		buffer bytes.Buffer
		wr     = NewWriter(&buffer)
	)

	// iterate over words
	for _, word := range words {
		if err := wr.Put([]byte(word)); err != nil {
			t.Errorf("Put %q: encountered an unexpected error: %v", word, err)
		}
	}
	t.Logf("After writing: buffer=%q len=%d", buffer.Bytes(), buffer.Len())

	// read all the records back from the buffer with a delimited reader
	var (
		got []string
		rd  = NewReader(&buffer)
	)

	for {
		// fetch next record
		rec, err := rd.Next()
		if err != nil {
			if err != io.EOF {
				t.Errorf("Next encountered an unexpected error: %v", err)
			}
			break
		}
		got = append(got, string(rec))
	}

	// verify that we got the original words back
	if !reflect.DeepEqual(got, words) {
		t.Errorf("Round trip of %q: got %+q, but want %+q", input, got, words)
	}
}

/*
 *	UTILS
 */

type errWriter struct {
	nc  int
	err error
}

func (w *errWriter) Write(data []byte) (int, error) {
	if w.err != nil && w.nc == 0 {
		return 0, w.err
	}
	w.nc--
	return len(data), nil
}
