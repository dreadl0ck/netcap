package netio

import "sync"

type writerStatus struct {
	mu  sync.Mutex
	err error
}

func (s *writerStatus) record(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

func (s *writerStatus) Error() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

// WriterError retains write/finalization failures after Close and wrapper teardown.
func WriterError(w AuditRecordWriter) error {
	if reporter, ok := w.(interface{ Error() error }); ok {
		return reporter.Error()
	}
	return nil
}
