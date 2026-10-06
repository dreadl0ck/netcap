package stream

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/alert"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func TestIncrementalAndProtocolAlertsShareAuditFile(t *testing.T) {
	dir := t.TempDir()
	writer, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.WriteAlert(&types.Alert{Name: "before-decoder-init"}); err != nil {
		t.Fatal(err)
	}
	c := config.DefaultConfig.Clone()
	c.Out, c.IncludeDecoders, c.Compression = dir, "Alert", true
	decoders, err := InitAbstractDecoders(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoders) != 1 {
		t.Fatalf("decoders = %d", len(decoders))
	}
	defer func() { alert.Decoder.Writer = nil }()
	alert.WriteAlert(&types.Alert{Name: "protocol"})
	alert.Decoder.Writer.Close(1)
	if err := writer.WriteAlert(&types.Alert{Name: "after-decoder-close"}); err != nil {
		t.Fatal(err)
	}
	r, err := netio.Open(filepath.Join(dir, "Alert.ncap.gz"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"before-decoder-init", "protocol", "after-decoder-close"} {
		var record types.Alert
		if err := r.Next(&record); err != nil || record.Name != name {
			t.Fatalf("record = %q, want %q, error = %v", record.Name, name, err)
		}
	}
	if err := r.Next(new(types.Alert)); err != io.EOF {
		t.Fatalf("duplicate header/record: %v", err)
	}
}
