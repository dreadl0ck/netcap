/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package io

import (
	"bytes"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// stubLabeler is a deterministic labeler used to verify that csvProtoWriter
// invokes the injected label source instead of any package-level state.
type stubLabeler struct {
	value string
	calls int64
}

func (s *stubLabeler) Label(_ types.AuditRecord) string {
	atomic.AddInt64(&s.calls, 1)
	return s.value
}

func (s *stubLabeler) callCount() int64 { return atomic.LoadInt64(&s.calls) }

// sampleTCP returns a minimal *types.TCP audit record suitable for CSV
// serialization in tests.
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
		SrcIP:       "10.0.0." + strconv.Itoa(suffix),
		DstIP:       "10.0.1." + strconv.Itoa(suffix),
	}
}

// TestCSVProtoWriter_LabelManagerInjection verifies that the writer uses the
// injected labeler and emits its value as the trailing CSV field.
func TestCSVProtoWriter_LabelManagerInjection(t *testing.T) {
	var buf bytes.Buffer
	lm := &stubLabeler{value: "exfil"}

	w := newCSVProtoWriter(&buf, false /* encode */, true /* label */, lm)

	if _, err := w.writeRecord(sampleTCP(1)); err != nil {
		t.Fatalf("writeRecord returned error: %v", err)
	}
	if got := lm.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 call to injected labeler, got %d", got)
	}
	if got := buf.String(); !strings.HasSuffix(got, ",exfil\n") {
		t.Fatalf("expected CSV record to end with the injected label; got %q", got)
	}
}

// TestCSVProtoWriter_LabelToggleAffectsHeaderAndRowEqually proves the
// invariant that the label flag adds exactly one column to BOTH the header
// and the row, across all four (label, lm) combinations. Header and rows
// must never disagree on column count.
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
