package ssh

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

type partialWriter struct {
	netio.AuditRecordWriter
	records []*types.SSH
}

func TestSSHInitialKexBounds(t *testing.T) {
	payload := Marshal(&KexInitMsg{KexAlgos: []string{"curve25519-sha256"}, ServerHostKeyAlgos: []string{"ssh-ed25519"}})
	padding := 8 - (5+len(payload))%8
	if padding < 4 {
		padding += 8
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(payload)+padding+1))
	packet = append(packet, byte(padding))
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, padding)...)
	for n := 0; n < len(packet); n++ {
		if _, ok := initialKex(packet[:n]); ok {
			t.Fatalf("accepted truncated KEX at %d", n)
		}
	}
	kex, ok := initialKex(packet)
	if !ok || len(kex.KexAlgos) != 1 || kex.KexAlgos[0] != "curve25519-sha256" {
		t.Fatal("lost validated KEX algorithms")
	}
	packet[4] = 255
	if _, ok := initialKex(packet); ok {
		t.Fatal("accepted excessive padding")
	}
}

func FuzzSSHInitialFraming(f *testing.F) {
	f.Add([]byte("SSH-2.0-example_1.0\r\n"))
	f.Add([]byte{0, 0, 0, 1, 255, 20})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, end := sshIdentification(data)
		if end < 0 || end > min(len(data), maxSSHPrefix) {
			t.Fatal("identification escaped bounded prefix")
		}
		initialKex(data)
	})
}

func (w *partialWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.SSH))
	return nil
}

func TestPartialSSHFraming(t *testing.T) {
	for _, mode := range []string{"initial", "split", "hole", "budget", "post-close", "post-close-prefix", "post-close-split", "unterminated", "preamble"} {
		t.Run(mode, func(t *testing.T) {
			writer, count := Decoder.Writer, Decoder.NumRecordsWritten
			w := &partialWriter{}
			Decoder.Writer = w
			t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = writer, count })
			first := &core.StreamData{RawData: []byte("SSH-2.0-"), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(9, 123)}}
			last := &core.StreamData{RawData: []byte("example_1.0\r\n")}
			marker := &core.StreamData{}
			data := core.DataFragments{first, marker, last}
			switch mode {
			case "initial":
				marker.SkippedBytes = -1
				data = core.DataFragments{marker, first, last}
			case "hole":
				marker.SkippedBytes = 5
			case "budget":
				marker.DiscardedBytes = 5
			case "post-close":
				last.TCPObservation = "after-rst"
			case "post-close-prefix":
				first.TCPObservation = "after-rst"
			case "post-close-split":
				first.TCPObservation, last.TCPObservation = "after-rst", "after-rst"
			case "unterminated":
				last.RawData = []byte("example_1.0")
			case "preamble":
				first.RawData = []byte("Authorized use only\r\nSSH-2.0-")
			}
			conv := &core.ConversationInfo{Data: data, ClientData: data, Ident: "192.0.2.1:40000->192.0.2.2:22", TCPRoleSource: "syn"}
			Decoder.Factory.New(conv).Decode()
			want := 1
			if mode == "hole" || mode == "budget" || mode == "post-close" || mode == "post-close-prefix" || mode == "unterminated" {
				want = 0
			}
			if len(w.records) != want {
				t.Fatalf("got %d records, want %d", len(w.records), want)
			}
			if want == 1 {
				r := w.records[0]
				if r.Ident != "SSH-2.0-example_1.0" || !r.IsClient || r.Timestamp != time.Unix(9, 123).UnixNano() || !strings.Contains(r.Notes, "peer not observed") {
					t.Fatalf("partial observation lost: %v", r)
				}
				if mode == "post-close-split" && !strings.Contains(r.Notes, "after-rst; endpoint delivery unconfirmed") {
					t.Fatalf("post-close qualification lost: %v", r)
				}
			}
		})
	}
}

func TestSSHPrefixLimitAndIndependentDirections(t *testing.T) {
	writer, count := Decoder.Writer, Decoder.NumRecordsWritten
	w := &partialWriter{}
	Decoder.Writer = w
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = writer, count })
	data := core.DataFragments{
		&core.StreamData{RawData: []byte(strings.Repeat("x", 65536) + "\nSSH-2.0-hidden_1.0\r\n")},
		&core.StreamData{RawData: []byte("SSH-2.0-visible_1.0\r\n"), Dir: reassembly.TCPDirServerToClient},
	}
	Decoder.Factory.New(&core.ConversationInfo{Data: data}).Decode()
	if len(w.records) != 1 || w.records[0].Ident != "SSH-2.0-visible_1.0" {
		t.Fatalf("unbounded prefix or lost independent direction: %v", w.records)
	}
}
