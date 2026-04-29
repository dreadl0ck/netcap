/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package io

import (
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// fakeWriter is a minimal AuditRecordWriter used as the factory result so
// tests can exercise the registry without constructing a real CSV writer
// (which requires real file IO).
type fakeWriter struct{}

func (f *fakeWriter) Write(_ proto.Message) error                    { return nil }
func (f *fakeWriter) WriteHeader(_ types.Type) error                 { return nil }
func (f *fakeWriter) Flush() error                                   { return nil }
func (f *fakeWriter) Close(_ int64) (name string, size int64)        { return "", 0 }

// register is a thin helper that drives the registry directly so the
// tests can pass a labeler interface (the WriterConfig type fixes
// LabelManager to *manager.LabelManager which would force the tests to
// build a real manager from a YAML file).
func register(t *testing.T, key string, label bool, lm labeler) *sharedWriter {
	t.Helper()
	return globalWriterRegistry.getOrCreateWriter(key, label, lm, func() AuditRecordWriter {
		return &fakeWriter{}
	})
}

// TestSharedWriter_RejectsMismatchedLabelManager covers Bug 1 from the
// adversarial review: prior to the fix, two callers requesting the same
// output file via the registry could pass two different LabelManager
// instances; the second caller silently received the first caller's
// writer (and therefore the first caller's labels), defeating the
// explicit-injection contract of the refactor.
//
// The fix binds the shared writer to a single labelling config at
// creation time and panics on mismatched reuse so the misconfiguration
// is loud rather than silent.
func TestSharedWriter_RejectsMismatchedLabelManager(t *testing.T) {
	ResetWriterRegistry()
	t.Cleanup(ResetWriterRegistry)

	lm1 := &stubLabeler{value: "first"}
	lm2 := &stubLabeler{value: "second"}

	// First caller establishes the shared writer with lm1.
	if got := register(t, "/tmp/t/TCP", true, lm1); got == nil {
		t.Fatal("first caller got nil writer")
	}

	// Second caller asks for the same key with a DIFFERENT manager.
	// The registry must refuse to silently rebind the writer.
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on mismatched LabelManager reuse, got none — first caller's labels would have been silently applied to second caller's records")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic value to be string, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "different label config") {
			t.Fatalf("panic message missing diagnostic; got %q", msg)
		}
	}()

	// This call must panic.
	_ = register(t, "/tmp/t/TCP", true, lm2)
	t.Fatal("unreachable: registry must have panicked")
}

// TestSharedWriter_AllowsMatchingLabelManager confirms that the legitimate
// production case — multiple decoders sharing the same output file with
// the same LabelManager from the central decoder config — still works.
func TestSharedWriter_AllowsMatchingLabelManager(t *testing.T) {
	ResetWriterRegistry()
	t.Cleanup(ResetWriterRegistry)

	lm := &stubLabeler{value: "shared"}

	if got := register(t, "/tmp/t/TCP", true, lm); got == nil {
		t.Fatal("first caller got nil writer")
	}
	// Same manager pointer, same label flag: must reuse without panic.
	if got := register(t, "/tmp/t/TCP", true, lm); got == nil {
		t.Fatal("second caller got nil writer")
	}
}

// TestSharedWriter_RejectsMismatchedLabelFlag checks that flipping the
// Label flag between calls to the same key is caught — header/row column
// counts would otherwise diverge between callers writing to the same
// file.
func TestSharedWriter_RejectsMismatchedLabelFlag(t *testing.T) {
	ResetWriterRegistry()
	t.Cleanup(ResetWriterRegistry)

	if got := register(t, "/tmp/t/TCP", false, nil); got == nil {
		t.Fatal("first caller got nil writer")
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on mismatched Label flag reuse")
		}
	}()

	_ = register(t, "/tmp/t/TCP", true, &stubLabeler{value: "x"})
	t.Fatal("unreachable")
}

// TestSharedWriter_AllowsMatchingNoLabel covers the no-labelling case:
// two callers sharing a key with Label=false and nil manager must reuse
// cleanly.
func TestSharedWriter_AllowsMatchingNoLabel(t *testing.T) {
	ResetWriterRegistry()
	t.Cleanup(ResetWriterRegistry)

	if got := register(t, "/tmp/t/TCP", false, nil); got == nil {
		t.Fatal("first caller got nil")
	}
	if got := register(t, "/tmp/t/TCP", false, nil); got == nil {
		t.Fatal("second caller got nil")
	}
}
