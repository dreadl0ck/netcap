/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package io

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// stubLabeler is a deterministic labeler used to verify that the
// csvProtoWriter invokes the injected label source instead of any
// package-level state, and that the exact record reaches the labeler.
type stubLabeler struct {
	mu      sync.Mutex
	value   string
	calls   int64
	srcSeen []string
	dstSeen []string
}

func (s *stubLabeler) Label(rec types.AuditRecord) string {
	atomic.AddInt64(&s.calls, 1)
	s.mu.Lock()
	s.srcSeen = append(s.srcSeen, rec.Src())
	s.dstSeen = append(s.dstSeen, rec.Dst())
	s.mu.Unlock()
	return s.value
}

func (s *stubLabeler) callCount() int64 { return atomic.LoadInt64(&s.calls) }

func (s *stubLabeler) snapshot() (src, dst []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src = append(src, s.srcSeen...)
	dst = append(dst, s.dstSeen...)
	return src, dst
}

// sampleTCP returns a minimal *types.TCP audit record suitable for CSV
// serialization in tests. The src/dst suffix lets tests assert that the
// labeler received exactly the records written.
func sampleTCP(suffix int) *types.TCP {
	return &types.TCP{
		Timestamp:   1700000000000000000,
		SrcPort:     1234,
		DstPort:     443,
		SeqNum:      1,
		AckNum:      2,
		DataOffset:  5,
		Window:      64,
		Checksum:    0,
		PayloadSize: 0,
		SrcIP:       srcIP(suffix),
		DstIP:       dstIP(suffix),
	}
}

func srcIP(n int) string { return "10.0.0." + itoa(n) }
func dstIP(n int) string { return "10.0.1." + itoa(n) }

// tiny local int->string to avoid pulling strconv just for tests
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestCSVProtoWriter_LabelManagerInjection proves that the writer uses the
// injected labeler instead of any package-level state. It verifies:
//   - the labeler is called exactly once per record
//   - the rendered CSV row carries the injected category as its trailing field
//   - the byte count returned matches what was written to the underlying buffer
//   - two writers with different labelers do not share state
//   - the labeler receives the exact records the caller passed in
func TestCSVProtoWriter_LabelManagerInjection(t *testing.T) {
	var buf bytes.Buffer
	lm := &stubLabeler{value: "exfil"}

	w := newCSVProtoWriter(&buf, false /* encode */, true /* label */, lm)

	rec := sampleTCP(1)
	n, err := w.writeRecord(rec)
	if err != nil {
		t.Fatalf("writeRecord returned error: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("writeRecord byte count mismatch: returned %d, buffer has %d", n, buf.Len())
	}
	if got := lm.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 call to injected labeler, got %d", got)
	}

	out := buf.String()
	if !strings.HasSuffix(out, ",exfil\n") {
		t.Fatalf("expected CSV record to end with the injected label; got %q", out)
	}

	// Confirm the labeler received the exact record we wrote.
	srcSeen, dstSeen := lm.snapshot()
	if len(srcSeen) != 1 || srcSeen[0] != rec.Src() {
		t.Fatalf("labeler received wrong Src: %v (want [%q])", srcSeen, rec.Src())
	}
	if len(dstSeen) != 1 || dstSeen[0] != rec.Dst() {
		t.Fatalf("labeler received wrong Dst: %v (want [%q])", dstSeen, rec.Dst())
	}

	// A second writer with a different labeler must produce a different
	// label, proving there is no shared package-level state.
	var buf2 bytes.Buffer
	lm2 := &stubLabeler{value: "normal"}
	w2 := newCSVProtoWriter(&buf2, false, true, lm2)
	if _, err := w2.writeRecord(sampleTCP(2)); err != nil {
		t.Fatalf("writeRecord (second writer) returned error: %v", err)
	}
	if !strings.HasSuffix(buf2.String(), ",normal\n") {
		t.Fatalf("second writer must use its own labeler; got %q", buf2.String())
	}
	// Ensure the first writer's labeler was not invoked again by the second.
	if got := lm.callCount(); got != 1 {
		t.Fatalf("first labeler must not be reused across writers; calls=%d", got)
	}
}

// TestCSVProtoWriter_NoLabelWhenDisabled ensures that when labelling is off,
// the writer does not invoke any labeler and does not append a Category
// field. A nil labeler must be safe in this configuration.
func TestCSVProtoWriter_NoLabelWhenDisabled(t *testing.T) {
	var buf bytes.Buffer

	w := newCSVProtoWriter(&buf, false /* encode */, false /* label */, nil)
	if _, err := w.writeRecord(sampleTCP(1)); err != nil {
		t.Fatalf("writeRecord returned error: %v", err)
	}

	rec := sampleTCP(1)
	expectedSuffix := "," + rec.CSVRecord()[len(rec.CSVRecord())-1] + "\n"
	if !strings.HasSuffix(buf.String(), expectedSuffix) {
		t.Fatalf("unlabeled record must end with the last CSV field; got %q", buf.String())
	}
	if strings.Contains(buf.String(), ",exfil") {
		t.Fatalf("unlabeled record must not contain a label column: %q", buf.String())
	}
}

// TestCSVProtoWriter_ConstructorDisablesLabelWhenManagerMissing verifies that
// constructing a writer with label=true and lm=nil downgrades to label=false
// rather than producing rows that disagree with the header. This locks in
// the H1 hardening: header and row column counts must match.
func TestCSVProtoWriter_ConstructorDisablesLabelWhenManagerMissing(t *testing.T) {
	var buf bytes.Buffer

	w := newCSVProtoWriter(&buf, false, true /* label */, nil)
	if w.label {
		t.Fatal("constructor must disable label when no labelManager is supplied")
	}

	// Header must not contain Category since labelling was downgraded.
	hdr := NewHeader(types.Type_NC_TCP, "unit", "v0", false, time.Unix(0, 0))
	if _, err := w.writeHeader(hdr, sampleTCP(1)); err != nil {
		t.Fatalf("writeHeader returned error: %v", err)
	}
	if strings.Contains(buf.String(), "Category") {
		t.Fatalf("downgraded writer must not emit Category in header: %q", buf.String())
	}

	// Row must also omit the label column.
	if _, err := w.writeRecord(sampleTCP(1)); err != nil {
		t.Fatalf("writeRecord returned error: %v", err)
	}
	if strings.Contains(buf.String(), ",exfil") || strings.Contains(buf.String(), ",scan") {
		t.Fatalf("downgraded writer must not emit a label column in rows: %q", buf.String())
	}
}

// TestCSVProtoWriter_LabelToggleAffectsHeaderAndRowEqually proves the
// invariant that the label flag adds exactly one column to BOTH the header
// and the row, never one without the other. This is the contract the
// constructor guard protects: a writer with label=true and no manager must
// not emit a header with Category while rows omit the label column (or vice
// versa). Note the absolute column counts of the underlying audit record
// type may already differ between CSVHeader() and CSVRecord() — that is a
// pre-existing concern of the types package and outside the scope of this
// writer. We only assert the *delta* introduced by the label flag.
func TestCSVProtoWriter_LabelToggleAffectsHeaderAndRowEqually(t *testing.T) {
	render := func(label bool, lm labeler) (hdr, row string) {
		var hb, rb bytes.Buffer
		wh := newCSVProtoWriter(&hb, false, label, lm)
		wr := newCSVProtoWriter(&rb, false, label, lm)
		h := NewHeader(types.Type_NC_TCP, "unit", "v0", false, time.Unix(0, 0))
		if _, err := wh.writeHeader(h, sampleTCP(1)); err != nil {
			t.Fatalf("writeHeader: %v", err)
		}
		if _, err := wr.writeRecord(sampleTCP(1)); err != nil {
			t.Fatalf("writeRecord: %v", err)
		}
		return hb.String(), rb.String()
	}
	cols := func(s string) int {
		return strings.Count(strings.TrimRight(s, "\n"), ",") + 1
	}

	baseHdr, baseRow := render(false, nil)
	baseHdrCols, baseRowCols := cols(baseHdr), cols(baseRow)

	t.Run("label_with_manager_adds_one_column_each", func(t *testing.T) {
		hdr, row := render(true, &stubLabeler{value: "x"})
		if got, want := cols(hdr), baseHdrCols+1; got != want {
			t.Fatalf("header columns: got %d want %d (output=%q)", got, want, hdr)
		}
		if got, want := cols(row), baseRowCols+1; got != want {
			t.Fatalf("row columns: got %d want %d (output=%q)", got, want, row)
		}
	})

	t.Run("label_requested_without_manager_matches_unlabelled", func(t *testing.T) {
		hdr, row := render(true, nil) // downgraded by constructor
		if got := cols(hdr); got != baseHdrCols {
			t.Fatalf("downgraded header columns: got %d want %d (output=%q)", got, baseHdrCols, hdr)
		}
		if got := cols(row); got != baseRowCols {
			t.Fatalf("downgraded row columns: got %d want %d (output=%q)", got, baseRowCols, row)
		}
	})
}

// TestCSVProtoWriter_HeaderWithLabelColumn locks current header behaviour so
// the refactor is provably non-breaking: when label is true and a manager is
// supplied, "Category" is appended to the CSV header line.
func TestCSVProtoWriter_HeaderWithLabelColumn(t *testing.T) {
	var buf bytes.Buffer
	w := newCSVProtoWriter(&buf, false, true, &stubLabeler{value: "ignored"})

	rec := sampleTCP(1)
	hdr := NewHeader(types.Type_NC_TCP, "unit", "v0", false, time.Unix(0, 0))
	if _, err := w.writeHeader(hdr, rec); err != nil {
		t.Fatalf("writeHeader returned error: %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, ",Category\n") {
		t.Fatalf("labeled header must end with Category column; got %q", out)
	}
}

// TestCSVProtoWriter_HeaderWithoutLabelColumn ensures the header does not
// pick up a Category column when labelling is disabled.
func TestCSVProtoWriter_HeaderWithoutLabelColumn(t *testing.T) {
	var buf bytes.Buffer
	w := newCSVProtoWriter(&buf, false, false, nil)

	rec := sampleTCP(1)
	hdr := NewHeader(types.Type_NC_TCP, "unit", "v0", false, time.Unix(0, 0))
	if _, err := w.writeHeader(hdr, rec); err != nil {
		t.Fatalf("writeHeader returned error: %v", err)
	}
	if strings.Contains(buf.String(), "Category") {
		t.Fatalf("unlabeled header must not contain Category column; got %q", buf.String())
	}
}

// countingWriter is an io.Writer that counts goroutine-safe writes and
// records the total bytes received. Used by the concurrency test to verify
// that the per-write mutex serialises access to the underlying writer.
type countingWriter struct {
	mu     sync.Mutex
	writes int
	bytes  int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.bytes += len(p)
	return len(p), nil
}

// TestCSVProtoWriter_ConcurrentWrites runs many writers concurrently to
// exercise the per-writer mutex and to give -race something to chew on.
// Asserts that exactly one Write occurs per record and the labeler is
// invoked exactly once per record.
func TestCSVProtoWriter_ConcurrentWrites(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 64

	cw := &countingWriter{}
	lm := &stubLabeler{value: "concurrent"}
	w := newCSVProtoWriter(cw, false, true, lm)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if _, err := w.writeRecord(sampleTCP(seed*perGoroutine + i)); err != nil {
					t.Errorf("writeRecord: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	expected := int64(goroutines * perGoroutine)
	if got := lm.callCount(); got != expected {
		t.Fatalf("labeler call count: got %d want %d", got, expected)
	}
	if cw.writes != int(expected) {
		t.Fatalf("underlying writer call count: got %d want %d", cw.writes, expected)
	}
	if cw.bytes == 0 {
		t.Fatal("underlying writer received zero bytes")
	}
}
