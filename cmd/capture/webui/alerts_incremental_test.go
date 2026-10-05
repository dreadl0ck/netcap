package webui

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func TestAuditRecordReaderLiveAlerts(t *testing.T) {
	dir := t.TempDir()
	w, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, name := range []string{"first", "second"} {
		if err := w.WriteAlert(&types.Alert{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewAuditRecordReader(filepath.Join(dir, "Alert.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h, err := r.ReadHeader()
	if err != nil || h.Type != types.Type_NC_Alert {
		t.Fatalf("header = %v, error = %v", h, err)
	}
	for _, name := range []string{"first", "second"} {
		record, err := r.NextRecord()
		if err != nil {
			t.Fatal(err)
		}
		alert, ok := record.(*types.Alert)
		if !ok || alert.Name != name {
			t.Fatalf("record = %v, want %s", record, name)
		}
	}
	if _, err := r.NextRecord(); err != io.EOF {
		t.Fatalf("end of live snapshot = %v", err)
	}
}

func TestExecuteRuleRejectsCorruptAlertHistory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Alert.ncap.gz"), []byte("broken history"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	count, _, err := s.executeRuleOnCapture(&rules.Rule{
		Name: "ssh", Type: "TCP", Expression: "DstPort == 22", Enabled: true,
	}, dir)
	if err == nil || count != 0 {
		t.Fatalf("corrupt history returned success: count=%d, error=%v", count, err)
	}
}
