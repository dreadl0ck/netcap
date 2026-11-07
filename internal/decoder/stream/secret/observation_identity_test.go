package secret

import (
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"sync"
	"testing"
)

type observationWriter struct {
	netio.AuditRecordWriter
	sync.Mutex
	records []*types.Secret
}

func (w *observationWriter) Write(m proto.Message) error {
	w.Lock()
	defer w.Unlock()
	w.records = append(w.records, proto.Clone(m).(*types.Secret))
	return nil
}

func TestCredentialDedupPreservesFlowEvidence(t *testing.T) {
	old, oldCount, oldConfig := Decoder.Writer, Decoder.NumRecordsWritten, decoderconfig.Instance
	credStoreMu.Lock()
	saved := credStore
	credStore = map[string]string{}
	credStoreMu.Unlock()
	defer func() {
		Decoder.Writer, Decoder.NumRecordsWritten, decoderconfig.Instance = old, oldCount, oldConfig
		credStoreMu.Lock()
		credStore = saved
		credStoreMu.Unlock()
	}()
	w := &observationWriter{}
	Decoder.Writer = w
	decoderconfig.Instance = &decoderconfig.Config{}
	var wg sync.WaitGroup
	for _, flow := range []string{"a", "b", "a", "b"} {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			WriteSecret(&types.Secret{Service: "HTTP", User: "owned", Password: "fixture", Flow: f})
		}(flow)
	}
	wg.Wait()
	if len(w.records) != 2 {
		t.Fatalf("cross-flow evidence lost or exact duplicates retained: %d", len(w.records))
	}
	WriteSecret(&types.Secret{Service: "ab", User: "c", Password: "d", Flow: "same"})
	WriteSecret(&types.Secret{Service: "a", User: "bc", Password: "d", Flow: "same"})
	if len(w.records) != 4 {
		t.Fatal("concatenated credential fields collided")
	}
}
