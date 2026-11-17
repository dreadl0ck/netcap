package stream

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/protobuf"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

type countedClassifierSource struct {
	fragments core.DataFragments
	walks     int
	err       error
}

func (s *countedClassifierSource) Count() int64 { return int64(len(s.fragments)) }
func (s *countedClassifierSource) Walk(yield func(core.DataFragment) bool) error {
	s.walks++
	for _, f := range s.fragments {
		if !yield(f) {
			break
		}
	}
	return s.err
}

func TestSmallUDPClassifierSourceIsReadOnceAndDetached(t *testing.T) {
	matchingEnv(t)
	source := &countedClassifierSource{fragments: core.DataFragments{&core.StreamData{RawData: []byte("unrecognized first")}, &core.StreamData{RawData: []byte("unrecognized reply"), Dir: reassembly.TCPDirServerToClient}}}
	in := &SelectionInput{Transport: core.UDP, Conversation: &core.ConversationInfo{Source: source}}
	for range 10 {
		matchScore(protobuf.Decoder, in, false)
	}
	if source.walks != 1 || len(in.Datagrams) != 2 || !in.Datagrams[0].Client || in.Datagrams[1].Client {
		t.Fatalf("walks=%d cached=%+v", source.walks, in.Datagrams)
	}
	source.fragments[0].Raw()[0] = 'X'
	if in.Datagrams[0].Data[0] == 'X' {
		t.Fatal("classifier cache aliases source buffers")
	}
	for _, fragments := range []core.DataFragments{make(core.DataFragments, 33), {&core.StreamData{RawData: bytes.Repeat([]byte{1}, (256<<10)+1)}}} {
		for i := range fragments {
			if fragments[i] == nil {
				fragments[i] = &core.StreamData{}
			}
		}
		large := &SelectionInput{Transport: core.UDP, Conversation: &core.ConversationInfo{Source: &countedClassifierSource{fragments: fragments}}}
		large.cacheUDPClassifierBytes()
		if len(large.Datagrams) != 0 {
			t.Fatal("large conversation retained by classifier")
		}
	}
	failure := errors.New("backing failure")
	broken := &SelectionInput{Conversation: &core.ConversationInfo{Source: &countedClassifierSource{fragments: core.DataFragments{&core.StreamData{}}, err: failure}}}
	broken.cacheUDPClassifierBytes()
	if !errors.Is(broken.Conversation.FragmentError, failure) {
		t.Fatal("backing error lost")
	}
}
