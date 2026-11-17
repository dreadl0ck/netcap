package webui

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestManualRuleBatchPreservesPerRuleResults(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Method: "GET"}, &types.HTTP{Method: "POST"},
	})
	selected := []*rules.Rule{
		{Name: "get", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true},
		{Name: "invalid", Type: "HTTP", Expression: `Method ==`, Enabled: true},
		{Name: "post", Type: "HTTP", Expression: `Method == "POST"`, Enabled: true},
		{Name: "missing", Type: "DNS", Expression: `true`, Enabled: true},
	}
	results, err := (&Server{}).replayManualRules(dir, selected, nil)
	if err != nil || len(results) != 4 {
		t.Fatal(results, err)
	}
	for _, i := range []int{0, 2} {
		if r := results[i]; !r.Success || r.AlertsCount != 1 || r.RecordsRead != 2 {
			t.Fatalf("unexpected rule result: %+v", r)
		}
	}
	if results[1].Success || results[1].Error == "" || !results[3].Success || results[3].RecordsRead != 0 {
		t.Fatal(results)
	}
}

func TestRuleAuditRejectsMissingRecordBody(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte{8})
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	count, err := scanRuleAudit(dir, "HTTP", nil, func(types.AuditRecord) error { return nil })
	if count != 1 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(count, err)
	}
}
