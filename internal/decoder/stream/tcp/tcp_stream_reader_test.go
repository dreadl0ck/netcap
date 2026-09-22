package tcp

import (
	"bytes"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func TestTCPStreamReaderRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sizes  []int
		nilEOF bool
	}{
		{name: "closed empty channel"},
		{name: "nil fragment", sizes: []int{17, 8193}, nilEOF: true},
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
			}
			close(reader.DataChan())

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

func TestTCPStreamReaderStoreDataCountsSynchronously(t *testing.T) {
	reader := &tcpStreamReader{parent: &tcpConnection{}}

	reader.StoreData(&core.StreamData{RawData: []byte("final fragment")})

	if got, want := reader.NumBytes(), len("final fragment"); got != want {
		t.Fatalf("NumBytes() = %d, want %d before reader runs", got, want)
	}
}

func TestCleanupReassemblyClosesAndDrainsReadersWhenFlushDisabled(t *testing.T) {
	conn := &tcpConnection{}
	reader := &tcpStreamReader{
		parent:   conn,
		dataChan: make(chan *core.StreamData, 3),
		saved:    true,
	}
	reader.DataChan() <- &core.StreamData{RawData: []byte("first")}
	reader.DataChan() <- nil
	reader.DataChan() <- &core.StreamData{RawData: []byte("final")}

	factory := &connectionFactory{
		streamReaders: []streamReader{reader},
		numActive:     1,
	}
	factory.wg.Add(1)
	go reader.Run(factory)

	originalFactory := StreamFactory
	originalWait := decoderconfig.Instance.WaitForConnections
	originalQuiet := decoderconfig.Instance.Quiet
	StreamFactory = factory
	decoderconfig.Instance.WaitForConnections = false
	decoderconfig.Instance.Quiet = true
	t.Cleanup(func() {
		StreamFactory = originalFactory
		decoderconfig.Instance.WaitForConnections = originalWait
		decoderconfig.Instance.Quiet = originalQuiet
	})

	CleanupReassembly(false, nil)

	if got := len(reader.DataChan()); got != 0 {
		t.Fatalf("queued fragments after close = %d, want 0", got)
	}
	if _, ok := <-reader.DataChan(); ok {
		t.Fatal("reader channel remains open")
	}
	if factory.numActive != 0 {
		t.Fatalf("active readers = %d, want 0", factory.numActive)
	}
}

func TestCleanupReassemblyClosesReadersWithoutTimeout(t *testing.T) {
	conn := &tcpConnection{}
	reader := &tcpStreamReader{
		parent:   conn,
		dataChan: make(chan *core.StreamData, 1),
		saved:    true,
	}
	reader.DataChan() <- &core.StreamData{RawData: []byte("final")}

	factory := &connectionFactory{
		streamReaders: []streamReader{reader},
		numActive:     1,
	}
	factory.wg.Add(1)
	go reader.Run(factory)

	originalFactory := StreamFactory
	originalWait := decoderconfig.Instance.WaitForConnections
	originalQuiet := decoderconfig.Instance.Quiet
	originalWorkers := decoderconfig.Instance.NumStreamWorkers
	StreamFactory = factory
	decoderconfig.Instance.WaitForConnections = true
	decoderconfig.Instance.Quiet = true
	decoderconfig.Instance.NumStreamWorkers = 1
	t.Cleanup(func() {
		StreamFactory = originalFactory
		decoderconfig.Instance.WaitForConnections = originalWait
		decoderconfig.Instance.Quiet = originalQuiet
		decoderconfig.Instance.NumStreamWorkers = originalWorkers
	})

	started := time.Now()
	CleanupReassembly(false, nil)
	if elapsed := time.Since(started); elapsed >= 750*time.Millisecond {
		t.Fatal("CleanupReassembly waited for the former teardown timeout")
	}
	if _, ok := <-reader.DataChan(); ok {
		t.Fatal("reader channel remains open after cleanup")
	}
}
