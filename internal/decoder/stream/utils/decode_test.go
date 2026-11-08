package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

func TestConversationUnknownStartAndInternalLoss(t *testing.T) {
	for _, loss := range []int{0, -1, 3, 99} {
		t.Run(fmt.Sprint(loss), func(t *testing.T) {
			data := core.DataFragments{
				&core.StreamData{SkippedBytes: -1, Dir: reassembly.TCPDirClientToServer},
				&core.StreamData{RawData: []byte("A1 CAPABILITY\r\n"), Dir: reassembly.TCPDirClientToServer},
				&core.StreamData{SkippedBytes: -1, Dir: reassembly.TCPDirServerToClient},
				&core.StreamData{RawData: []byte("* OK ready\r\n"), Dir: reassembly.TCPDirServerToClient},
				&core.StreamData{RawData: []byte("A2 SEL"), Dir: reassembly.TCPDirClientToServer},
			}
			marker := &core.StreamData{SkippedBytes: loss, Dir: reassembly.TCPDirClientToServer}
			if loss == 99 {
				marker.SkippedBytes, marker.DiscardedBytes = 0, 9
			}
			data = append(data, marker, &core.StreamData{RawData: []byte("ECT INBOX\r\n"), Dir: reassembly.TCPDirClientToServer})
			var got []string
			read := func(b *bufio.Reader) error {
				line, err := b.ReadString('\n')
				if err == nil {
					got = append(got, line)
				}
				return err
			}
			DecodeConversation("test", data, read, read)
			want := []string{"A1 CAPABILITY\r\n", "* OK ready\r\n"}
			if loss == 0 {
				want = append(want, "A2 SELECT INBOX\r\n")
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("loss=%d: got %q, want %q", loss, got, want)
			}
		})
	}
}

func TestConversationPostCloseBoundary(t *testing.T) {
	data := core.DataFragments{
		&core.StreamData{RawData: []byte("A1 SEL")},
		&core.StreamData{RawData: []byte("ECT INBOX\r\nA2 CAPABILITY\r\n"), TCPObservation: "after-rst"},
	}
	var lines, notes []string
	read := func(b *bufio.Reader, pos *ReadPosition) error {
		line, err := b.ReadString('\n')
		if err == nil {
			lines = append(lines, line)
			notes = append(notes, pos.TCPObservation())
		}
		return err
	}
	DecodeConversationAt("test", data, read, read)
	if !reflect.DeepEqual(lines, []string{"ECT INBOX\r\n", "A2 CAPABILITY\r\n"}) || !reflect.DeepEqual(notes, []string{"after-rst", "after-rst"}) {
		t.Fatalf("joined across a close or lost qualification: %q / %q", lines, notes)
	}
}

func TestConversationReaderMustMakeProgress(t *testing.T) {
	for _, err := range []error{nil, errors.New("malformed frame")} {
		calls := 0
		read := func(*bufio.Reader) error {
			calls++
			if calls == 3 { // Bound the baseline failure instead of hanging the test.
				return io.EOF
			}
			return err
		}
		DecodeConversation("test", core.DataFragments{&core.StreamData{RawData: []byte("bad")}}, read, read)
		if calls != 1 {
			t.Fatalf("reader retried without consuming bytes: %d calls", calls)
		}
	}
}
