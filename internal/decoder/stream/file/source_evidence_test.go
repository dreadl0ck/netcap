package file

import (
	"errors"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

type countedEvidenceSource struct {
	core.FragmentSource
	walks int
	err   error
}

func (s *countedEvidenceSource) Walk(yield func(core.DataFragment) bool) error {
	s.walks++
	if err := s.FragmentSource.Walk(yield); err != nil {
		return err
	}
	return s.err
}

func TestSourceFileEvidenceDoesNotReplayPerArtifact(t *testing.T) {
	source := &countedEvidenceSource{FragmentSource: core.SliceSource{&core.StreamData{SkippedBytes: -1}, &core.StreamData{SkippedBytes: 7, TCPObservation: "close"}, &core.StreamData{TCPObservation: "close"}}}
	conv := &core.ConversationInfo{Source: source}
	if err := PrepareSourceEvidence(conv); err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		if err := PrepareSourceEvidence(conv); err != nil {
			t.Fatal(err)
		}
		missing, unknown := conversationLoss(conv)
		if missing != 7 || !unknown {
			t.Fatal("loss evidence changed", missing, unknown)
		}
		if !reflect.DeepEqual(transportQualifications(conv), []string{"transport-close"}) {
			t.Fatal("transport qualification changed")
		}
	}
	if source.walks != 1 {
		t.Fatal("file observations replayed the transport run", source.walks)
	}
	failure := errors.New("evidence backing failure")
	source = &countedEvidenceSource{FragmentSource: core.SliceSource{}, err: failure}
	conv = &core.ConversationInfo{Source: source}
	if err := PrepareSourceEvidence(conv); !errors.Is(err, failure) || conv.Source != source {
		t.Fatal("failed evidence was cached", err)
	}
}
