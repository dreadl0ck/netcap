package rules

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

type sharedAlertAuditWriter struct{ writer *FileAlertWriter }

// SharedAlertAuditWriter joins an already-enabled incremental alert store.
// Ordinary captures retain their configured output writer.
func SharedAlertAuditWriter(output string, header *types.Header) (netio.AuditRecordWriter, bool) {
	if output == "" {
		output = "."
	}
	dir, err := filepath.Abs(output)
	if err != nil {
		return nil, false
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, false
	}
	path := filepath.Join(dir, "Alert.ncap.gz")
	alertStores.Lock()
	defer alertStores.Unlock()
	store := alertStores.files[path]
	if store == nil {
		return nil, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.refs++
	if store.size == 0 && header != nil {
		store.header = proto.Clone(header).(*types.Header)
	}
	return &sharedAlertAuditWriter{writer: &FileAlertWriter{store: store}}, true
}

func (w *sharedAlertAuditWriter) Write(message proto.Message) error {
	alert, ok := message.(*types.Alert)
	if !ok {
		return fmt.Errorf("expected Alert, got %T", message)
	}
	return w.writer.WriteAlert(alert)
}

func (w *sharedAlertAuditWriter) WriteHeader(typ types.Type) error {
	if typ != types.Type_NC_Alert {
		return errors.New("shared alert writer requires Alert header")
	}
	return w.Flush()
}

func (w *sharedAlertAuditWriter) Flush() error {
	w.writer.mu.Lock()
	defer w.writer.mu.Unlock()
	if w.writer.closed {
		return os.ErrClosed
	}
	w.writer.store.mu.Lock()
	defer w.writer.store.mu.Unlock()
	return w.writer.store.err
}

func (w *sharedAlertAuditWriter) Close(_ int64) (string, int64) {
	if err := w.writer.Close(); err != nil {
		log.Printf("failed to close shared Alert audit writer: %v", err)
	}
	path := w.writer.store.path
	info, err := os.Stat(path)
	if err != nil {
		return filepath.Base(path), 0
	}
	return filepath.Base(path), info.Size()
}
