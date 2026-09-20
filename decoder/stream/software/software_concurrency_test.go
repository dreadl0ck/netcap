package software

import (
	"testing"

	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/document"
	"github.com/blevesearch/bleve/search"
	"github.com/dreadl0ck/netcap/decoder/db"
	"github.com/dreadl0ck/netcap/decoder/stream/vulnerability"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type embeddedIndex = bleve.Index
type snapshotIndex struct{ embeddedIndex }

func (snapshotIndex) Search(*bleve.SearchRequest) (*bleve.SearchResult, error) {
	return &bleve.SearchResult{Hits: search.DocumentMatchCollection{&search.DocumentMatch{ID: "snapshot-cve", Score: 1000000}}}, nil
}

func (snapshotIndex) Document(id string) (*document.Document, error) {
	doc := document.NewDocument(id)
	for _, value := range []string{id, "description", "high"} {
		doc.AddField(document.NewTextField("field", nil, []byte(value)))
	}
	return doc, nil
}

type snapshotWriter struct {
	netio.AuditRecordWriter
	write func(*types.Vulnerability)
}

func (w snapshotWriter) Write(msg proto.Message) error {
	w.write(msg.(*types.Vulnerability))
	return nil
}

func TestWriteSoftwareLookupSnapshot(t *testing.T) {
	oldItems := Store.Items
	oldIndex, oldExploitIndex := db.VulnerabilitiesIndex, db.ExploitsIndex
	oldWriter, oldCount := vulnerability.Decoder.Writer, vulnerability.Decoder.NumRecordsWritten
	Store.Items = make(map[string]*AtomicSoftware)
	db.VulnerabilitiesIndex = snapshotIndex{}
	db.ExploitsIndex = nil
	vulnerability.ResetVulnStore()
	t.Cleanup(func() {
		Store.Items = oldItems
		db.VulnerabilitiesIndex, db.ExploitsIndex = oldIndex, oldExploitIndex
		vulnerability.Decoder.Writer, vulnerability.Decoder.NumRecordsWritten = oldWriter, oldCount
		vulnerability.ResetVulnStore()
	})
	item := &AtomicSoftware{Software: &types.Software{Product: "snapshot", Version: "1", Flows: []string{"first"}, CommunityIDs: []string{"cid-first"}}}
	called := false
	vulnerability.Decoder.Writer = snapshotWriter{write: func(record *types.Vulnerability) {
		called = true
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 100 {
				WriteSoftware([]*AtomicSoftware{item}, func(s *AtomicSoftware) {
					s.Lock()
					defer s.Unlock()
					s.Flows[0] = "changed"
					s.CommunityIDs[0] = "changed"
					s.Flows = append(s.Flows, "next")
					s.CommunityIDs = append(s.CommunityIDs, "cid-next")
				})
			}
		}()
		for range 100 {
			if _, err := proto.Marshal(record); err != nil {
				t.Error(err)
			}
		}
		<-done
		if record.Software == item.Software || len(record.Software.Flows) != 1 || record.Software.Flows[0] != "first" || record.CommunityIDs[0] != "cid-first" || record.Software.CommunityIDs[0] != "cid-first" {
			t.Error("lookup record aliases the live software")
		}
	}}
	WriteSoftware([]*AtomicSoftware{item}, nil)
	if !called {
		t.Fatal("vulnerability writer was not called")
	}
	if !item.HasKnownVulnerabilities {
		t.Error("lookup result was not merged into live software")
	}
}
