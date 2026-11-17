package tls

import (
	"errors"
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gogo/protobuf/proto"
)

func sourceConversation(c *core.ConversationInfo, data core.DataFragments) *core.ConversationInfo {
	copy := *c
	var client, server core.DataFragments
	for _, fragment := range data {
		if core.FromServer(fragment) {
			server = append(server, fragment)
		} else {
			client = append(client, fragment)
		}
	}
	copy.Data, copy.ClientData, copy.ServerData = nil, nil, nil
	copy.ClientSource, copy.ServerSource = core.SliceSource(client), core.SliceSource(server)
	copy.Source = core.MergedSource{Client: copy.ClientSource, Server: copy.ServerSource}
	return &copy
}

type failingSourceRecordWriter struct {
	netio.AuditRecordWriter
	err        error
	calls      int
	panicWrite bool
}

func (w *failingSourceRecordWriter) Write(proto.Message) error {
	w.calls++
	if w.panicWrite {
		panic("control")
	}
	return w.err
}

func TestTLSSourceWriterFailureAndPanicReleaseCredits(t *testing.T) {
	h, _ := recordTestSetup(t)
	cause := errors.New("record output unavailable")
	for _, panicWrite := range []bool{false, true} {
		writer := &failingSourceRecordWriter{err: cause, panicWrite: panicWrite}
		RecordDecoder.Writer = writer
		wire := append(recordWire(23, []byte("first")), recordWire(23, []byte("second"))...)
		c := sourceConversation(h.conversation, core.DataFragments{fragment(wire, false, 1)})
		budget, _ := core.NewStateBudget(8192, nil)
		c.StateBudget = budget
		func() {
			if panicWrite {
				defer func() {
					if recover() == nil {
						t.Fatal("writer panic disappeared")
					}
				}()
			}
			(&tlsReader{conversation: c}).Decode()
		}()
		if !panicWrite && !errors.Is(c.FragmentError, cause) {
			t.Fatal("writer error was hidden", c.FragmentError)
		}
		if writer.calls != 1 || budget.Health().RetainedBytes != 0 {
			t.Fatal("writer failure retained framing state or continued writing", writer.calls, budget.Health())
		}
	}
}

func TestTLSSourcePreservesRecordsAcrossSplitsLossAndClose(t *testing.T) {
	h, writer := recordTestSetup(t)
	old := ClientHelloDecoder.Writer
	t.Cleanup(func() { ClientHelloDecoder.Writer = old })
	ClientHelloDecoder.Writer = &helloWriter{}
	wire := append(recordHello(1), recordWire(23, []byte("opaque"))...)
	for _, loss := range []int{0, -1, 3} {
		for _, note := range []string{"", "after-rst", "after-fin"} {
			for split := 1; split < len(wire); split++ {
				data := core.DataFragments{fragment(wire[:split], false, 1), &core.StreamData{SkippedBytes: loss, Dir: reassembly.TCPDirClientToServer}, fragment(wire[split:], false, 3), fragment(recordHello(2), true, 4)}
				data[2].(*core.StreamData).TCPObservation = note
				legacy := *h.conversation
				legacy.Data = data
				writer.records = nil
				(&tlsReader{conversation: &legacy}).Decode()
				want := writer.records
				writer.records = nil
				c := sourceConversation(h.conversation, data)
				budget, _ := core.NewStateBudget(65536, nil)
				c.StateBudget = budget
				(&tlsReader{conversation: c}).Decode()
				if c.FragmentError != nil || !reflect.DeepEqual(want, writer.records) || budget.Health().RetainedBytes != 0 {
					t.Fatalf("split=%d loss=%d note=%s: records changed: %v / %v error=%v budget=%+v", split, loss, note, want, writer.records, c.FragmentError, budget.Health())
				}
			}
		}
	}
}

func TestTLSRangedUpgradeDoesNotMaterialize(t *testing.T) {
	h, writer, _ := helloTestWriters(t)
	for _, protocol := range []string{"SMTP", "POP3", "IMAP", "FTP"} {
		commands := map[string][2]string{"SMTP": {"STARTTLS\r\n", "220 ready\r\n"}, "POP3": {"STLS\r\n", "+OK ready\r\n"}, "IMAP": {"A1 STARTTLS\r\n", "A1 OK ready\r\n"}, "FTP": {"AUTH TLS\r\n", "234 ready\r\n"}}
		pair := commands[protocol]
		for _, closeBoundary := range []bool{false, true} {
			data := core.DataFragments{fragment([]byte(pair[0]), false, 1), fragment([]byte(pair[1]), true, 2), fragment(upgradeHello(), false, 3)}
			if closeBoundary {
				data[2] = fragment(upgradeHello()[:20], false, 3)
				after := fragment(upgradeHello()[20:], false, 4)
				after.TCPObservation = "after-rst"
				data = append(data, after)
			}
			c := sourceConversation(h.conversation, data)
			c.LoadData = func() error { t.Fatal("ranged upgrade loaded whole conversation"); return nil }
			writer.messages = nil
			ObserveUpgrade(c, protocol)
			want := 1
			if closeBoundary {
				want = 0
			}
			if c.FragmentError != nil || len(writer.messages) != want {
				t.Fatal(protocol, closeBoundary, c.FragmentError, len(writer.messages))
			}
		}
	}
}

func TestTLSSourceFramingCreditsFailAndRelease(t *testing.T) {
	h, _ := recordTestSetup(t)
	old := ClientHelloDecoder.Writer
	t.Cleanup(func() { ClientHelloDecoder.Writer = old })
	ClientHelloDecoder.Writer = &helloWriter{}
	for _, limit := range []int64{1, 2048, 4096} {
		c := sourceConversation(h.conversation, core.DataFragments{fragment(upgradeHello(), false, 1)})
		budget, _ := core.NewStateBudget(limit, nil)
		c.StateBudget = budget
		(&tlsReader{conversation: c}).Decode()
		if limit <= 2048 && !errors.Is(c.FragmentError, core.ErrStreamStateBudget) {
			t.Fatal("TLS framing did not reserve working memory", limit, c.FragmentError)
		}
		if limit == 4096 && c.FragmentError != nil {
			t.Fatal(c.FragmentError)
		}
		if budget.Health().RetainedBytes != 0 {
			t.Fatal("TLS framing retained credits", budget.Health())
		}
	}
}
