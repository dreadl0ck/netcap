package netio

import "github.com/gogo/protobuf/proto"

type observedWriter struct {
	AuditRecordWriter
	observe func(proto.Message)
}

func (w *observedWriter) Write(m proto.Message) error {
	w.observe(m)
	return w.AuditRecordWriter.Write(m)
}

func (w *observedWriter) WriteScoped(m proto.Message, scope string) error {
	w.observe(m)
	if scoped, ok := w.AuditRecordWriter.(interface {
		WriteScoped(proto.Message, string) error
	}); ok {
		return scoped.WriteScoped(m, scope)
	}
	return w.AuditRecordWriter.Write(m)
}
func ObserveWriter(w AuditRecordWriter, observe func(proto.Message)) AuditRecordWriter {
	if observe == nil || w == nil {
		return w
	}
	return &observedWriter{w, observe}
}
