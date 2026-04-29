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

package io

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/types"
)

// writerRegistry manages shared writers for the same output file.
// This prevents race conditions when the same decoder is registered on multiple ports.
type writerRegistry struct {
	mu      sync.Mutex
	writers map[string]*sharedWriterEntry
}

type sharedWriterEntry struct {
	writer        AuditRecordWriter
	refCount      int
	totalRecords  int64
	headerWritten bool

	// Snapshot of label-relevant config from the first caller. Subsequent
	// callers must agree on these values; otherwise the registry would
	// silently apply the first caller's labelling to records produced by
	// the second caller, defeating the explicit-injection contract of the
	// LabelManager refactor.
	label        bool
	labelManager labeler
}

var globalWriterRegistry = &writerRegistry{
	writers: make(map[string]*sharedWriterEntry),
}

// sharedWriter wraps an AuditRecordWriter to support shared access from multiple callers.
// Each caller gets their own sharedWriter instance, but they all share the same underlying writer.
// localRecords is updated atomically because the same *sharedWriter pointer is
// reached from multiple decoder worker goroutines (e.g. connection writers).
type sharedWriter struct {
	key          string // registry key (file path)
	localRecords int64  // records written by this instance (atomic)
}

// getOrCreateWriter returns a shared writer for the given key.
// If a writer already exists for this key, increments its reference count.
// Otherwise creates a new writer using the provided factory function.
//
// label and lm record the labelling config of the calling site so the
// registry can detect a caller that requests the same output file with a
// different LabelManager. The shared writer is bound to a single
// LabelManager at creation time; allowing a later caller to "share" the
// writer while passing a different manager would silently apply the first
// caller's labelling to records produced by the second caller — exactly
// the class of bug the explicit-injection refactor exists to prevent.
//
// Mismatches are therefore treated as programmer errors and panic with
// full context. In production, all decoders sharing an output file read
// the same LabelManager from the central decoder config, so this path is
// not reachable from valid configurations. Tests can recover from the
// panic to assert the contract.
func (r *writerRegistry) getOrCreateWriter(key string, label bool, lm labeler, factory func() AuditRecordWriter) *sharedWriter {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.writers[key]
	if exists {
		if entry.label != label || entry.labelManager != lm {
			ioLog.Error("shared writer label config mismatch on reuse",
				zap.String("key", key),
				zap.Bool("first_label", entry.label),
				zap.Bool("requested_label", label),
				zap.Bool("first_manager_nil", entry.labelManager == nil),
				zap.Bool("requested_manager_nil", lm == nil),
				zap.Bool("manager_pointer_match", entry.labelManager == lm))
			panic(fmt.Sprintf(
				"shared writer %q already bound to a different label config: "+
					"first(label=%v, manager_nil=%v) vs requested(label=%v, manager_nil=%v); "+
					"all decoders sharing an output file must use the same LabelManager",
				key, entry.label, entry.labelManager == nil, label, lm == nil))
		}
		entry.refCount++
		ioLog.Info("reusing existing writer",
			zap.String("key", key),
			zap.Int("refCount", entry.refCount))
		return &sharedWriter{key: key}
	}

	// Create new writer
	writer := factory()
	r.writers[key] = &sharedWriterEntry{
		writer:       writer,
		refCount:     1,
		label:        label,
		labelManager: lm,
	}
	ioLog.Info("created new shared writer",
		zap.String("key", key))

	return &sharedWriter{key: key}
}

// Write writes a record through the shared writer.
func (sw *sharedWriter) Write(msg proto.Message) error {
	globalWriterRegistry.mu.Lock()
	entry := globalWriterRegistry.writers[sw.key]
	globalWriterRegistry.mu.Unlock()

	if entry == nil {
		return nil // Writer already closed
	}

	err := entry.writer.Write(msg)
	if err == nil {
		atomic.AddInt64(&sw.localRecords, 1)
	}
	return err
}

// WriteHeader writes the header (only once per shared writer).
func (sw *sharedWriter) WriteHeader(t types.Type) error {
	globalWriterRegistry.mu.Lock()
	defer globalWriterRegistry.mu.Unlock()

	entry := globalWriterRegistry.writers[sw.key]
	if entry == nil {
		return nil // Writer already closed
	}

	// Only write header once
	if entry.headerWritten {
		return nil
	}

	err := entry.writer.WriteHeader(t)
	if err == nil {
		entry.headerWritten = true
	}
	return err
}

// Flush flushes any buffered data.
func (sw *sharedWriter) Flush() error {
	globalWriterRegistry.mu.Lock()
	entry := globalWriterRegistry.writers[sw.key]
	globalWriterRegistry.mu.Unlock()

	if entry == nil {
		return nil
	}

	return entry.writer.Flush()
}

// Close decrements the reference count and closes the underlying writer when it reaches zero.
// The numRecords parameter is the count from THIS caller, not the total.
func (sw *sharedWriter) Close(numRecords int64) (name string, size int64) {
	globalWriterRegistry.mu.Lock()
	defer globalWriterRegistry.mu.Unlock()

	entry := globalWriterRegistry.writers[sw.key]
	if entry == nil {
		return "", 0
	}

	// Add this caller's records to total
	entry.totalRecords += numRecords
	entry.refCount--

	ioLog.Info("closing shared writer reference",
		zap.String("key", sw.key),
		zap.Int64("localRecords", numRecords),
		zap.Int64("totalRecords", entry.totalRecords),
		zap.Int("remainingRefs", entry.refCount))

	// Only close the actual writer when all references are done
	if entry.refCount <= 0 {
		name, size = entry.writer.Close(entry.totalRecords)
		delete(globalWriterRegistry.writers, sw.key)
		return name, size
	}

	// More references exist, don't close yet
	return "", 0
}

// ResetWriterRegistry clears the global writer registry (useful for testing).
func ResetWriterRegistry() {
	globalWriterRegistry.mu.Lock()
	defer globalWriterRegistry.mu.Unlock()
	globalWriterRegistry.writers = make(map[string]*sharedWriterEntry)
}

// GetSharedAuditRecordWriter returns a shared writer for the given config.
// Multiple callers requesting the same output file will share the same underlying writer.
//
// Note on labelling: the writer cached on first call binds to its caller's
// LabelManager. Later callers requesting the same output file with a
// different LabelManager (or a different value of the Label flag) will
// reuse the original writer; this is logged as an Error so the
// inconsistency is observable rather than silently corrupting output. In
// practice all decoders sharing a file should read the same manager from
// the central decoder config.
func GetSharedAuditRecordWriter(wc *WriterConfig) AuditRecordWriter {
	// Generate a unique key for this writer based on output path and name
	key := wc.Out + "/" + wc.Name

	// Capture an interface-typed view of the (possibly nil) manager so the
	// registry can compare pointer identity safely without importing the
	// concrete manager package.
	var lm labeler
	if wc.LabelManager != nil {
		lm = wc.LabelManager
	}

	return globalWriterRegistry.getOrCreateWriter(key, wc.Label, lm, func() AuditRecordWriter {
		return NewAuditRecordWriter(wc)
	})
}
