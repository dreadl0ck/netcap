/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package distributed

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// syncBuffer collects log output from goroutines that may outlive a test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

type collectorUnderTest struct {
	srv  *Server
	addr string
	out  string
	logs *syncBuffer
	done chan error
}

func startCollector(t *testing.T, addr, out string, id testIdentity, allow Allowlist) *collectorUnderTest {
	t.Helper()

	sink, err := NewSink(out)
	if err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}

	srv, err := NewServer(ServerConfig{
		Identity:  id.cert,
		Allowlist: allow,
		Sink:      sink,
		Logger:    log.New(logs, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}

	var ln net.Listener
	// Rebinding the same port right after a shutdown can briefly fail.
	for i := 0; ; i++ {
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		if i == 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	c := &collectorUnderTest{srv: srv, addr: ln.Addr().String(), out: out, logs: logs, done: make(chan error, 1)}
	go func() { c.done <- srv.Serve(ln) }()

	return c
}

func (c *collectorUnderTest) stop(t *testing.T) []SinkFileInfo {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	infos, err := c.srv.Shutdown(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-c.done; !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve returned %v", err)
	}

	return infos
}

func newTestClient(t *testing.T, addr string, id testIdentity, serverFP string, logs *syncBuffer) *Client {
	t.Helper()

	c, err := NewClient(ClientConfig{
		Addr:              addr,
		Identity:          id.cert,
		ServerFingerprint: serverFP,
		Hello:             types.AgentHello{Source: "test0", Version: "test"},
		MinBackoff:        10 * time.Millisecond,
		MaxBackoff:        100 * time.Millisecond,
		Logger:            log.New(logs, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func waitDelivered(t *testing.T, c *Client, logs ...*syncBuffer) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if st := c.Stats(); st.Pending == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	for _, l := range logs {
		t.Log(l.String())
	}
	t.Fatalf("batches not delivered: %+v", c.Stats())
}

func chanWriter(t *testing.T, typ types.Type) netio.ChannelAuditRecordWriter {
	t.Helper()

	w, ok := netio.NewAuditRecordWriter(&netio.WriterConfig{
		Chan: true, ChanSize: 16, Type: typ, Name: typ.String(),
	}).(netio.ChannelAuditRecordWriter)
	if !ok {
		t.Fatal("not a channel writer")
	}

	return w
}

// countByType reads every file under dir with netcap's reader and sums
// records per type. Several files per type exist after a collector restart.
func countByType(t *testing.T, dir string) (map[types.Type]int, []proto.Message) {
	t.Helper()

	var (
		counts = map[types.Type]int{}
		udp    []proto.Message
	)

	paths, err := filepath.Glob(filepath.Join(dir, "*.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range paths {
		r, err := netio.Open(p, 0)
		if err != nil {
			t.Fatal(err)
		}

		hdr, err := r.ReadHeader()
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}

		for {
			rec := netio.InitRecord(hdr.Type)
			if err = r.Next(rec); err != nil {
				break
			}
			counts[hdr.Type]++
			if hdr.Type == types.Type_NC_UDP {
				udp = append(udp, rec)
			}
		}
		if !errors.Is(err, io.EOF) {
			t.Fatalf("%s: read ended with %v", p, err)
		}
		_ = r.Close()
	}

	return counts, udp
}

// TestDistributedEndToEnd drives the real pipeline: channel writers →
// batchers → client → TLS → server → sink, across a collector restart, and
// reads the result back with netcap's normal reader.
func TestDistributedEndToEnd(t *testing.T) {
	var (
		srvID   = newIdentity(t, "collector")
		agentID = newIdentity(t, "agent")
		allow   = Allowlist{agentID.fp: "sensor-1"}
		out     = t.TempDir()
		logs    = &syncBuffer{}
	)

	col := startCollector(t, "127.0.0.1:0", out, srvID, allow)
	client := newTestClient(t, col.addr, agentID, srvID.fp, logs)

	tcpW, dnsW, udpW := chanWriter(t, types.Type_NC_TCP), chanWriter(t, types.Type_NC_DNS), chanWriter(t, types.Type_NC_UDP)

	var batchers sync.WaitGroup
	for _, w := range []struct {
		typ types.Type
		ch  <-chan []byte
	}{{types.Type_NC_TCP, tcpW.GetChan()}, {types.Type_NC_DNS, dnsW.GetChan()}, {types.Type_NC_UDP, udpW.GetChan()}} {
		batchers.Add(1)
		go func() {
			defer batchers.Done()
			RunBatcher(w.ch, BatcherConfig{
				Type:          w.typ,
				MaxBytes:      4096, // many TCP batches
				FlushInterval: 50 * time.Millisecond,
				Emit: func(b *types.Batch) {
					if err := client.Enqueue(b); err != nil {
						t.Error(err)
					}
				},
			})
		}()
	}

	writeTCP := func(from, n int) {
		for i := from; i < from+n; i++ {
			if err := tcpW.Write(&types.TCP{SrcPort: int32(i), SrcIP: "10.0.0.1"}); err != nil {
				t.Fatal(err)
			}
		}
	}

	big := make([]byte, 3<<20)
	_, _ = rand.Read(big)

	// Phase 1: a rare type that only the flush interval sends, and a record
	// far over both MaxBytes and v0.9.15's 10 KiB datagram buffer.
	writeTCP(0, 500)
	if err := dnsW.Write(&types.DNS{ID: 42}); err != nil {
		t.Fatal(err)
	}
	if err := udpW.Write(&types.UDP{Payload: big}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond) // let the interval flush fire
	waitDelivered(t, client, logs, col.logs)

	// Phase 2: the collector goes away; records keep coming and are queued.
	col.stop(t)
	writeTCP(500, 300)
	time.Sleep(200 * time.Millisecond)

	if st := client.Stats(); st.Pending == 0 {
		t.Fatalf("nothing queued while the collector was down: %+v", st)
	}

	col = startCollector(t, col.addr, out, srvID, allow)

	// Shutdown: closing the writers closes the channels; batchers flush.
	tcpW.Close(0)
	dnsW.Close(0)
	udpW.Close(0)
	batchers.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st, err := client.Close(ctx)
	if err != nil || st.Pending != 0 || st.Dropped != 0 || st.Rejected != 0 {
		t.Log(logs.String(), col.logs.String())
		t.Fatalf("client close: %v %+v", err, st)
	}

	col.stop(t)

	// Output lives only under <out>/<allowlist name>.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "sensor-1" {
		t.Fatalf("output dir entries: %v", entries)
	}

	counts, udp := countByType(t, filepath.Join(out, "sensor-1"))
	want := map[types.Type]int{types.Type_NC_TCP: 800, types.Type_NC_DNS: 1, types.Type_NC_UDP: 1}
	for typ, n := range want {
		if counts[typ] != n {
			t.Errorf("%s: %d records, want %d", typ, counts[typ], n)
		}
	}
	if len(udp) == 1 && !bytes.Equal(udp[0].(*types.UDP).Payload, big) {
		t.Error("3 MiB payload corrupted")
	}
}

func TestUnknownAgentIsRefused(t *testing.T) {
	var (
		srvID    = newIdentity(t, "collector")
		agentID  = newIdentity(t, "agent")
		stranger = newIdentity(t, "stranger")
		out      = t.TempDir()
		logs     = &syncBuffer{}
	)

	col := startCollector(t, "127.0.0.1:0", out, srvID, Allowlist{agentID.fp: "agent"})
	defer col.stop(t)

	c := newTestClient(t, col.addr, stranger, srvID.fp, logs)
	if err := c.Enqueue(&types.Batch{MessageType: types.Type_NC_TCP, Data: delimitedTCP(t, 1)}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if st, err := c.Close(ctx); err == nil || st.Pending != 1 || st.Acked != 0 {
		t.Fatalf("stranger delivered: %v %+v", err, st)
	}

	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Fatalf("stranger created %v", entries)
	}
	if !strings.Contains(col.logs.String(), "not in the allowlist") {
		t.Fatalf("no rejection logged: %s", col.logs.String())
	}
}

// A bad batch is rejected and dropped by the agent; the collector survives
// and the next batch goes through.
func TestRejectedBatchIsDroppedAndCollectorSurvives(t *testing.T) {
	var (
		srvID   = newIdentity(t, "collector")
		agentID = newIdentity(t, "agent")
		out     = t.TempDir()
		logs    = &syncBuffer{}
	)

	col := startCollector(t, "127.0.0.1:0", out, srvID, Allowlist{agentID.fp: "agent"})

	c := newTestClient(t, col.addr, agentID, srvID.fp, logs)

	// The v0.9.15 framing: records without length prefixes.
	undelimited := delimitedTCP(t, 3)[1:]
	for _, b := range []*types.Batch{
		{MessageType: types.Type_NC_TCP, Data: undelimited},
		{MessageType: types.Type_NC_TCP, Data: delimitedTCP(t, 4)},
	} {
		if err := c.Enqueue(b); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := c.Close(ctx)
	if err != nil || st.Rejected != 1 || st.Acked != 1 {
		t.Fatalf("%v %+v\n%s", err, st, logs.String())
	}

	col.stop(t) // finalizes the gzip streams

	if counts, _ := countByType(t, filepath.Join(out, "agent")); counts[types.Type_NC_TCP] != 4 {
		t.Fatalf("counts %v", counts)
	}
}

// Raw garbage, before and after the handshake, must not take the collector down.
func TestGarbageDoesNotCrashCollector(t *testing.T) {
	var (
		srvID   = newIdentity(t, "collector")
		agentID = newIdentity(t, "agent")
		out     = t.TempDir()
	)

	col := startCollector(t, "127.0.0.1:0", out, srvID, Allowlist{agentID.fp: "agent"})
	defer col.stop(t)

	// Not TLS at all; a short message crashed v0.9.15 with a slice bound panic.
	for _, junk := range [][]byte{{1}, bytes.Repeat([]byte{0xff}, 70000)} {
		conn, err := net.Dial("tcp", col.addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write(junk)
		_ = conn.Close()
	}

	// Authenticated, but sending frames that are wrong in every way.
	tlsConf, err := ClientTLSConfig(agentID.cert, srvID.fp)
	if err != nil {
		t.Fatal(err)
	}

	hello, _ := proto.Marshal(&types.AgentHello{ProtocolVersion: ProtocolVersion})
	for _, frames := range [][][]byte{
		{{FrameBatch, 0, 0, 0, 0}},                                        // batch before hello
		{{FrameHello, 0, 0, 0, 2, 0xff, 0xff}},                            // undecodable hello
		{frame(FrameHello, hello), {99, 0, 0, 0, 0}},                      // unknown frame type
		{frame(FrameHello, hello), {FrameBatch, 0xff, 0xff, 0xff, 0xff}},  // 4 GiB frame
		{frame(FrameHello, hello), frame(FrameBatch, []byte{0xff, 0xff})}, // undecodable batch
		{frame(FrameHello, hello), frame(FrameBatch, mustMarshal(t, &types.Batch{Seq: 1, MessageType: types.Type(99999), Data: []byte{1, 0}}))},
	} {
		conn, err := tls.Dial("tcp", col.addr, tlsConf)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		for _, f := range frames {
			_, _ = conn.Write(f)
		}
		// Drain until the collector closes the connection.
		for {
			if _, _, err = ReadFrame(conn, DefaultMaxFrame); err != nil {
				break
			}
		}
		_ = conn.Close()
	}

	// Still serving.
	c := newTestClient(t, col.addr, agentID, srvID.fp, &syncBuffer{})
	if err = c.Enqueue(&types.Batch{MessageType: types.Type_NC_TCP, Data: delimitedTCP(t, 2)}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if st, err := c.Close(ctx); err != nil || st.Acked != 1 {
		t.Fatalf("collector no longer serving: %v %+v\n%s", err, st, col.logs.String())
	}
}

// A batch resent after a lost ack is acknowledged but written once; a new
// agent process (new session) starts its sequence over and is not deduplicated.
func TestResentBatchIsWrittenOnce(t *testing.T) {
	var (
		srvID   = newIdentity(t, "collector")
		agentID = newIdentity(t, "agent")
		out     = t.TempDir()
	)

	sink, err := NewSink(out)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(ServerConfig{Identity: srvID.cert, Allowlist: Allowlist{agentID.fp: "agent"}, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}

	payload := mustMarshal(t, &types.Batch{Seq: 1, MessageType: types.Type_NC_TCP, Data: delimitedTCP(t, 3)})
	hello := &types.AgentHello{}

	for _, session := range []uint64{7, 7, 8} {
		seq, reject, err := srv.writeBatch("agent", hello, srv.session("agent", session), payload)
		if err != nil || reject != "" || seq != 1 {
			t.Fatalf("seq %d reject %q err %v", seq, reject, err)
		}
	}

	if _, err = sink.Close(); err != nil {
		t.Fatal(err)
	}

	if counts, _ := countByType(t, filepath.Join(out, "agent")); counts[types.Type_NC_TCP] != 6 {
		t.Fatalf("want 6 records (session 7 once, session 8 once), got %v", counts)
	}
}

func frame(t byte, p []byte) []byte {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, t, p)

	return buf.Bytes()
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()

	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	return b
}
