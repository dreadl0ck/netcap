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

package tcp

import (
	"bytes"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
)

// These tests cover sortAndMergeFragments, which merges the client and server
// fragment slices of a connection into t.merged.
//
// The merge used to be written as
//
//	t.merged = append(t.client.DataSlice(), t.server.DataSlice()...)
//
// Appending to a slice that has spare capacity writes in place, and the client
// slice is grown by repeated append in StoreData, so cap > len is the normal
// case. t.merged therefore shared the client reader's backing array,
// which caused two distinct defects:
//
//   - A data race. The race detector reported a write in tcpStreamReader.Read
//     and a read in DataFragments.Size at the SAME address, which is only
//     possible if the two slices are one array. ReassemblyComplete reads the
//     fragments while the connection's reader goroutine is still draining its
//     buffered dataChan and appending.
//
//   - Silent corruption of the client stream. sort.Sort(t.merged) permutes the
//     shared array, and indices below len(client) are the client's live
//     elements, so sorting interleaved server fragments into t.client.data.
//     decode() then selects a protocol decoder from t.client.DataSlice(), so a
//     scrambled client buffer changes which decoder is chosen.

// mergeTestContext is a minimal reassembly.AssemblerContext carrying a timestamp,
// which is what DataFragments.Less sorts on.
type mergeTestContext struct {
	ts time.Time
}

func (c *mergeTestContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: c.ts}
}

// newMergeTestConn builds a connection whose client and server readers hold the
// given payloads, timestamped so that the two sides interleave.
//
// The client slice is grown with append, exactly as StoreData does,
// so that it ends up with the spare capacity that made the original merge alias.
func newMergeTestConn(clientPayloads, serverPayloads []string, base time.Time) *tcpConnection {
	conn := &tcpConnection{ident: "merge-test"}
	conn.client = conn.newTCPStreamReader(true)
	conn.server = conn.newTCPStreamReader(false)

	client, _ := conn.client.(*tcpStreamReader)
	server, _ := conn.server.(*tcpStreamReader)

	// Server speaks first, then the sides alternate. This mirrors a server-first
	// protocol such as SMTP, which is the shape that exposed the bug.
	for i, p := range serverPayloads {
		server.data = append(server.data, &core.StreamData{
			RawData:          []byte(p),
			AssemblerContext: &mergeTestContext{ts: base.Add(time.Duration(i*2) * time.Millisecond)},
			Dir:              reassembly.TCPDirServerToClient,
		})
	}

	for i, p := range clientPayloads {
		client.data = append(client.data, &core.StreamData{
			RawData:          []byte(p),
			AssemblerContext: &mergeTestContext{ts: base.Add(time.Duration(i*2+1) * time.Millisecond)},
			Dir:              reassembly.TCPDirClientToServer,
		})
	}

	return conn
}

// Sized so that the client slice ends up with spare capacity large enough to
// hold the server fragments: appending five elements one at a time yields
// cap 8, len 5, spare 3 >= len(serverPayloads). Without that headroom the
// original append allocated a fresh array and the defect did not reproduce --
// a two-and-two fixture silently passed against the buggy code.
var (
	clientPayloads = []string{"EHLO client", "MAIL FROM", "DATA", "body", "QUIT"}
	serverPayloads = []string{"220 server ready", "250 OK", "354 go ahead"}
)

func payloads(d core.DataFragments) []string {
	out := make([]string, 0, len(d))
	for _, f := range d {
		out = append(out, string(f.Raw()))
	}

	return out
}

// TestSortAndMergeFragmentsDoesNotAliasClientData pins the invariant that
// actually matters. Asserting on the symptom (a race, or a scrambled slice)
// makes for a flaky test; asserting that the two slices do not share memory
// tests the cause directly and deterministically.
func TestSortAndMergeFragmentsDoesNotAliasClientData(t *testing.T) {
	conn := newMergeTestConn(
		clientPayloads,
		serverPayloads,
		time.Now(),
	)

	client, _ := conn.client.(*tcpStreamReader)

	// Precondition: the client slice must have spare capacity, or the original
	// append would have allocated and the bug would not reproduce.
	if spare := cap(client.data) - len(client.data); spare < len(serverPayloads) {
		t.Fatalf("test setup is not exercising the bug: client has %d spare slots, server needs %d",
			spare, len(serverPayloads))
	}

	conn.sortAndMergeFragments()

	if len(conn.merged) != len(clientPayloads)+len(serverPayloads) {
		t.Fatalf("merged has %d fragments, want %d",
			len(conn.merged), len(clientPayloads)+len(serverPayloads))
	}

	// The merged slice must own its memory. If it shares the client's backing
	// array, writing through one is visible through the other.
	if &conn.merged[0] == &client.data[0] {
		t.Fatal("merged shares its backing array with the client fragments; " +
			"sorting it will corrupt the client stream and it races with " +
			"tcpStreamReader.Read appending")
	}
}

// TestSortAndMergeFragmentsLeavesClientStreamIntact covers the consequence that
// the aliasing had on decoding: sorting the merged slice reordered the client's
// own fragments, so decode() picked a decoder from a buffer that began with the
// server's greeting.
func TestSortAndMergeFragmentsLeavesClientStreamIntact(t *testing.T) {
	conn := newMergeTestConn(
		clientPayloads,
		serverPayloads,
		time.Now(),
	)

	conn.sortAndMergeFragments()

	// The client reader must still hold exactly its own fragments, in arrival
	// order. Before the fix this returned the server greeting first, because the
	// server sent the earliest timestamp and the sort moved it into the client's
	// array.
	gotClient := payloads(conn.client.DataSlice())
	wantClient := clientPayloads

	if len(gotClient) != len(wantClient) {
		t.Fatalf("client fragments = %v, want %v", gotClient, wantClient)
	}

	for i := range wantClient {
		if gotClient[i] != wantClient[i] {
			t.Errorf("client fragment %d = %q, want %q", i, gotClient[i], wantClient[i])
		}
	}

	// decode() selects a decoder from the first client fragment, so this is the
	// value that actually drove the misclassification.
	if first := string(conn.client.DataSlice().First()); first != "EHLO client" {
		t.Errorf("client.First() = %q, want %q -- decoder selection reads this", first, "EHLO client")
	}

	// The server side is read-only during the merge and must be untouched too.
	gotServer := payloads(conn.server.DataSlice())
	wantServer := serverPayloads

	for i := range wantServer {
		if gotServer[i] != wantServer[i] {
			t.Errorf("server fragment %d = %q, want %q", i, gotServer[i], wantServer[i])
		}
	}
}

// TestSortAndMergeFragmentsSortsByTimestamp guards the behaviour the merge is
// actually for, so that fixing the aliasing does not silently drop the ordering.
func TestSortAndMergeFragmentsSortsByTimestamp(t *testing.T) {
	conn := newMergeTestConn(
		clientPayloads,
		serverPayloads,
		time.Now(),
	)

	conn.sortAndMergeFragments()

	// Interleaved by timestamp: the helper gives server fragments even
	// millisecond offsets and client fragments odd ones, so the sides alternate
	// until the server runs out and the remaining client fragments follow.
	want := []string{
		"220 server ready", "EHLO client",
		"250 OK", "MAIL FROM",
		"354 go ahead", "DATA",
		"body", "QUIT",
	}
	got := payloads(conn.merged)

	if len(got) != len(want) {
		t.Fatalf("merged = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("merged fragment %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestSortAndMergeFragmentsKeepsPerDirectionByteOrder covers the delivery shape
// reassembly produces once a hole is closed: the packet that closed it comes
// first, followed by the packets it had queued, which were captured earlier.
// The fragments of one direction are therefore not in timestamp order, and
// ordering the merged slice by timestamp rewrites the byte stream that
// conversation.Data is parsed as.
func TestSortAndMergeFragmentsKeepsPerDirectionByteOrder(t *testing.T) {
	base := time.Now()
	conn := &tcpConnection{ident: "stream-order-test"}
	conn.client = conn.newTCPStreamReader(true)
	conn.server = conn.newTCPStreamReader(false)

	frag := func(payload string, offset time.Duration, dir reassembly.TCPFlowDirection) *core.StreamData {
		return &core.StreamData{
			RawData:          []byte(payload),
			AssemblerContext: &mergeTestContext{ts: base.Add(offset * time.Millisecond)},
			Dir:              dir,
		}
	}

	client, _ := conn.client.(*tcpStreamReader)
	server, _ := conn.server.(*tcpStreamReader)

	// c2 closed the hole that c3, captured earlier, was queued behind.
	client.data = core.DataFragments{
		frag("c1", 10, reassembly.TCPDirClientToServer),
		frag("c2", 50, reassembly.TCPDirClientToServer),
		frag("c3", 30, reassembly.TCPDirClientToServer),
	}
	server.data = core.DataFragments{
		frag("s1", 20, reassembly.TCPDirServerToClient),
		frag("s2", 40, reassembly.TCPDirServerToClient),
	}

	conn.sortAndMergeFragments()

	// Directions still interleave by time, but neither is reordered. Sorting by
	// timestamp would have produced c1 s1 c3 s2 c2, swapping c2 and c3.
	want := []string{"c1", "s1", "s2", "c2", "c3"}
	got := payloads(conn.merged)

	if len(got) != len(want) {
		t.Fatalf("merged = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merged = %v, want %v", got, want)
		}
	}

	// The invariant behind that expectation: each direction read out of the
	// conversation buffer must be byte-identical to the direction's own stream.
	for _, dir := range []reassembly.TCPFlowDirection{reassembly.TCPDirClientToServer, reassembly.TCPDirServerToClient} {
		var side core.DataFragments

		for _, f := range conn.merged {
			if f.Direction() == dir {
				side = append(side, f)
			}
		}

		wantSide := conn.client.DataSlice()
		if dir == reassembly.TCPDirServerToClient {
			wantSide = conn.server.DataSlice()
		}

		if !bytes.Equal(side.Bytes(), wantSide.Bytes()) {
			t.Errorf("%s bytes in merged = %q, want %q", dir, side.Bytes(), wantSide.Bytes())
		}
	}
}

// TestSortAndMergeFragmentsIsIdempotent covers the wasMerged guard: the merge is
// invoked from several places in ReassemblyComplete and must only run once.
func TestSortAndMergeFragmentsIsIdempotent(t *testing.T) {
	conn := newMergeTestConn(
		[]string{"EHLO client"},
		[]string{"220 server ready"},
		time.Now(),
	)

	conn.sortAndMergeFragments()
	first := payloads(conn.merged)

	conn.sortAndMergeFragments()
	second := payloads(conn.merged)

	if len(first) != len(second) {
		t.Fatalf("second merge changed the fragment count: %v then %v", first, second)
	}

	for i := range first {
		if first[i] != second[i] {
			t.Errorf("second merge changed fragment %d: %q then %q", i, first[i], second[i])
		}
	}
}

// TestFeedDataStoresBeforeTheReaderDrainsChannel pins the lifecycle property
// that the backing-array fix alone cannot provide. ReassemblyComplete runs on
// the assembler goroutine immediately after the last feedData call, while the
// reader goroutine may still have buffered channel items. Every delivered
// fragment must therefore be in DataSlice before feedData returns, not only
// after Read eventually consumes it.
func TestFeedDataStoresBeforeTheReaderDrainsChannel(t *testing.T) {
	conn := &tcpConnection{ident: "feed-test"}
	conn.client = conn.newTCPStreamReader(true)
	conn.server = conn.newTCPStreamReader(false)

	ctx := &mergeTestContext{ts: time.Now()}
	client, _ := conn.client.(*tcpStreamReader)
	client.dataChan = make(chan *core.StreamData, 1)

	conn.feedData(reassembly.TCPDirClientToServer, []byte("EHLO client"), ctx)

	if got := len(client.data); got != 1 {
		t.Fatalf("feedData returned with %d stored fragments, want 1; "+
			"ReassemblyComplete could snapshot an incomplete conversation", got)
	}

	if got := string(client.data[0].Raw()); got != "EHLO client" {
		t.Errorf("stored fragment = %q, want %q", got, "EHLO client")
	}

	// Prove the reader has not drained the item: storage is synchronous and
	// independent of consumption from the buffered channel.
	if got := len(client.dataChan); got != 1 {
		t.Fatalf("data channel length = %d, want 1 (test requires an undrained item)", got)
	}
}

// TestReorderSwapsReadersAndRepairsDirections covers the adjacent mutation path
// investigated with the fragment race. reorder writes each StreamData.Dir,
// while decoders later read it to split a merged conversation back into client
// and server traffic.
//
// It is not a second concurrent race: reorder and StoreData take the same
// connection lock, reader goroutines no longer mutate the fragment slice, and
// no reader goroutine inspects Direction. The important contract is ordering:
// direction repair happens before sortAndMergeFragments snapshots the fragment
// pointers, after which Direction is immutable.
func TestReorderSwapsReadersAndRepairsDirections(t *testing.T) {
	netFlow := gopacket.NewFlow(
		layers.EndpointIPv4,
		[]byte{192, 0, 2, 10},
		[]byte{198, 51, 100, 20},
	)
	transportFlow := gopacket.NewFlow(
		layers.EndpointTCPPort,
		[]byte{0xc3, 0x50}, // 50000
		[]byte{0x00, 0x19}, // 25 (SMTP)
	)

	base := time.Now()
	conn := &tcpConnection{
		ident:       "reorder-test",
		net:         netFlow,
		transport:   transportFlow,
		firstPacket: base,
	}
	conn.client = conn.newTCPStreamReader(true)
	conn.server = conn.newTCPStreamReader(false)

	originalClient := conn.client
	originalServer := conn.server

	// Data was initially assigned according to the flow direction first seen.
	// Give each side a deliberately wrong direction so reorder must repair it
	// when an older packet proves the connection was discovered backwards.
	originalClient.StoreData(&core.StreamData{
		RawData:          []byte("220 server ready"),
		AssemblerContext: &mergeTestContext{ts: base.Add(time.Millisecond)},
		Dir:              reassembly.TCPDirClientToServer,
	})
	originalServer.StoreData(&core.StreamData{
		RawData:          []byte("EHLO client"),
		AssemblerContext: &mergeTestContext{ts: base.Add(2 * time.Millisecond)},
		Dir:              reassembly.TCPDirServerToClient,
	})

	// An older packet with the reverse network flow proves the initial client
	// assignment was backwards and triggers the swap.
	conn.reorder(&mergeTestContext{ts: base.Add(-time.Second)}, netFlow.Reverse())

	if conn.client != originalServer || conn.server != originalClient {
		t.Fatal("reorder did not swap the client and server readers")
	}

	if got := conn.client.DataSlice()[0].Direction(); got != reassembly.TCPDirClientToServer {
		t.Errorf("new client direction = %s, want client-to-server", got)
	}
	if got := conn.server.DataSlice()[0].Direction(); got != reassembly.TCPDirServerToClient {
		t.Errorf("new server direction = %s, want server-to-client", got)
	}

	conn.sortAndMergeFragments()

	if got := string(conn.client.DataSlice().First()); got != "EHLO client" {
		t.Errorf("client stream changed during merge: first = %q", got)
	}
	if got := string(conn.server.DataSlice().First()); got != "220 server ready" {
		t.Errorf("server stream changed during merge: first = %q", got)
	}
}
