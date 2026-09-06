package tcp

import (
	"bytes"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/core"
)

func TestTCPStreamReaderRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sizes  []int
		nilEOF bool
	}{
		{name: "closed empty channel"},
		{name: "nil EOF", sizes: []int{17, 8193}, nilEOF: true},
		{name: "buffered fragments", sizes: []int{17, 4096, 8193}},
		{name: "empty fragments", sizes: []int{0, 0, 17, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &tcpConnection{}
			reader := &tcpStreamReader{
				parent:   conn,
				dataChan: make(chan *core.StreamData, len(tc.sizes)+1),
			}
			wantBytes := 0
			fragments := make([]*core.StreamData, 0, len(tc.sizes))
			for _, size := range tc.sizes {
				fragment := &core.StreamData{RawData: bytes.Repeat([]byte{'x'}, size)}
				fragments = append(fragments, fragment)
				reader.StoreData(fragment)
				reader.DataChan() <- fragment
				wantBytes += size
			}
			if tc.nilEOF {
				if got := reader.NumBytes(); got != wantBytes {
					t.Fatalf("bytes before reader starts = %d, want %d", got, wantBytes)
				}
				reader.DataChan() <- nil
				defer close(reader.DataChan())
			} else {
				close(reader.DataChan())
			}

			factory := &connectionFactory{numActive: 1}
			factory.wg.Add(1)
			done := make(chan struct{})
			go func() {
				reader.Run(factory)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("reader did not stop at EOF")
			}
			factory.wg.Wait()
			if factory.numActive != 0 {
				t.Errorf("active readers = %d, want 0", factory.numActive)
			}
			if got := reader.NumBytes(); got != wantBytes {
				t.Errorf("processed bytes = %d, want %d", got, wantBytes)
			}
			if got := reader.DataSlice(); len(got) != len(fragments) {
				t.Fatalf("stored fragments = %d, want %d", len(got), len(fragments))
			}
			for i, fragment := range reader.DataSlice() {
				if fragment != fragments[i] || !bytes.Equal(fragment.Raw(), bytes.Repeat([]byte{'x'}, tc.sizes[i])) {
					t.Errorf("stored fragment %d changed", i)
				}
			}
		})
	}
}
