package netio

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
)

type closeProbeWriter struct {
	AuditRecordWriter
	entered chan struct{}
	release chan struct{}
	writes  atomic.Int64
	closes  atomic.Int64
}

func (w *closeProbeWriter) Write(proto.Message) error { w.writes.Add(1); return nil }
func (w *closeProbeWriter) Close(int64) (string, int64) {
	w.closes.Add(1)
	if w.entered != nil {
		close(w.entered)
		<-w.release
	}
	return "probe", 1
}

func TestSharedWriterCloseDoesNotBlockOtherProtocols(t *testing.T) {
	old := globalWriterRegistry
	globalWriterRegistry = &writerRegistry{writers: map[string]*sharedWriterEntry{}}
	t.Cleanup(func() { globalWriterRegistry = old })
	slow := &closeProbeWriter{entered: make(chan struct{}), release: make(chan struct{})}
	a := globalWriterRegistry.getOrCreateWriter("slow", func() AuditRecordWriter { return slow })
	done := make(chan struct{})
	go func() { a.Close(1); close(done) }()
	<-slow.entered
	fast := &closeProbeWriter{}
	progress := make(chan struct{})
	go func() {
		b := globalWriterRegistry.getOrCreateWriter("fast", func() AuditRecordWriter { return fast })
		_ = b.Write(nil)
		b.Close(1)
		close(progress)
	}()
	select {
	case <-progress:
	case <-time.After(time.Second):
		close(slow.release)
		<-done
		t.Fatal("a closing protocol held the global registry lock")
	}
	if fast.writes.Load() != 1 || fast.closes.Load() != 1 {
		t.Fatal("independent writer did not drain")
	}
	next := &closeProbeWriter{}
	reopened := make(chan *sharedWriter, 1)
	go func() {
		reopened <- globalWriterRegistry.getOrCreateWriter("slow", func() AuditRecordWriter { return next })
	}()
	select {
	case <-reopened:
		close(slow.release)
		<-done
		t.Fatal("same output reopened before old close completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(slow.release)
	<-done
	b := <-reopened
	_ = b.Write(nil)
	_ = a.Write(nil)
	a.Close(100)
	_ = b.Write(nil)
	b.Close(2)
	if next.writes.Load() != 2 || next.closes.Load() != 1 || slow.closes.Load() != 1 {
		t.Fatal("stale reference reached the new writer generation")
	}
}
