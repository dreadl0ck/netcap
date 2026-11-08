package delivery

import (
	"errors"

	"github.com/dreadl0ck/netcap/types"
)

type AlertWriter interface {
	WriteAlert(*types.Alert) error
	Close() error
}

// Writer retains the audit first, then commits a redacted delivery notice. A
// failed enqueue returns an error; the durable audit can be re-enqueued later.
// Close does not deliver or discard pending notices and does not own the outbox.
type Writer struct {
	Audit  AlertWriter
	Outbox *Outbox
	Scope  string
}

func (w *Writer) WriteAlert(a *types.Alert) error {
	if w.Audit == nil || w.Outbox == nil || w.Scope == "" {
		return errors.New("delivery writer requires audit, outbox and scope")
	}
	if err := w.Audit.WriteAlert(a); err != nil {
		return err
	}
	_, err := w.Outbox.Enqueue(w.Scope, a)
	return err
}

func (w *Writer) Close() error {
	if w.Audit == nil {
		return nil
	}
	return w.Audit.Close()
}
