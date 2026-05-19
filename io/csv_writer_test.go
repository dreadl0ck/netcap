/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package io

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/label/manager"
	"github.com/dreadl0ck/netcap/types"
)

// TestLabelerFromManager_TypedNilBecomesUntypedNil locks in the fix for the
// real correctness bug noted in the PR review: passing a typed-nil
// *manager.LabelManager directly into a labeler interface parameter produces
// a non-nil interface value, defeating the nil guard in newCSVProtoWriter.
// labelerFromManager must convert a nil *manager.LabelManager into an untyped
// nil interface so the downstream guard fires.
func TestLabelerFromManager_TypedNilBecomesUntypedNil(t *testing.T) {
	var typedNil *manager.LabelManager
	if got := labelerFromManager(typedNil); got != nil {
		t.Fatalf("labelerFromManager(typed-nil) must be untyped nil, got %T (%v)", got, got)
	}

	// End-to-end: a writer constructed with Label=true and a typed-nil
	// LabelManager must downgrade to label=false and emit neither a Category
	// header nor a label column on rows.
	var buf bytes.Buffer
	w := newCSVProtoWriter(&buf, false, true, labelerFromManager(typedNil))
	if w.label {
		t.Fatal("writer must downgrade label to false when LabelManager is a typed-nil pointer")
	}

	hdr := NewHeader(types.Type_NC_TCP, "unit", "v0", false, time.Unix(0, 0))
	if _, err := w.writeHeader(hdr, sampleTCP(1)); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}
	if _, err := w.writeRecord(sampleTCP(1)); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}
	if strings.Contains(buf.String(), "Category") {
		t.Fatalf("downgraded writer must not emit Category column: %q", buf.String())
	}
}
