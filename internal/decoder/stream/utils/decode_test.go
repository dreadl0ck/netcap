package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"

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
			legacy := append([]string(nil), got...)
			got = nil
			if err := DecodeSourceConversation(&core.ConversationInfo{Source: core.SliceSource(data)}, read, read); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, legacy) {
				t.Fatal("source changed gap handling", got, legacy)
			}
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
	legacyLines, legacyNotes := append([]string(nil), lines...), append([]string(nil), notes...)
	lines, notes = nil, nil
	if err := DecodeSourceConversationAt(&core.ConversationInfo{Source: core.SliceSource(data)}, read, read); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lines, legacyLines) || !reflect.DeepEqual(notes, legacyNotes) {
		t.Fatal("source changed close boundaries", lines, notes)
	}
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
		calls = 0
		if err := DecodeSourceConversation(&core.ConversationInfo{Source: core.SliceSource{&core.StreamData{RawData: []byte("bad")}}}, read, read); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatal("source reader retried without progress", calls)
		}
	}
}

func TestSourceConversationPositionsAcrossReadAheadAndFragmentBoundaries(t *testing.T) {
	data := core.DataFragments{}
	for index, text := range []string{"first\n", "sec", "ond\nthird\n"} {
		data = append(data, &core.StreamData{RawData: []byte(text), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, int64(index))}})
	}
	var times []int64
	var offsets []int
	read := func(reader *bufio.Reader, pos *ReadPosition) error {
		at := pos.Timestamp()
		offset := pos.Offset()
		_, err := reader.ReadString('\n')
		if err == nil {
			times = append(times, at)
			offsets = append(offsets, offset)
		}
		return err
	}
	if err := DecodeSourceConversationAt(&core.ConversationInfo{Source: core.SliceSource(data)}, read, read); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(offsets, []int{0, 6, 13}) || !reflect.DeepEqual(times, []int64{1000000000, 1000000001, 1000000002}) {
		t.Fatal("source positions changed", times, offsets)
	}
}

func TestSourceConversationDoesNotRetainEveryPosition(t *testing.T) {
	read := func(reader *bufio.Reader, pos *ReadPosition) error {
		count, err := io.Copy(io.Discard, reader)
		if err != nil {
			return err
		}
		if count != 50000*1024 || len(pos.source.spans) > 16 || cap(pos.source.spans) > 32 {
			t.Fatal("source retained run metadata", count, len(pos.source.spans), cap(pos.source.spans))
		}
		return io.EOF
	}
	if err := DecodeSourceConversationAt(&core.ConversationInfo{Source: generatedEvidence{count: 50000}}, read, read); err != nil {
		t.Fatal(err)
	}
}
