/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package io

import (
	"sync"

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
	writer      AuditRecordWriter
	refCount    int
	totalRecords int64
	headerWritten bool
}

var globalWriterRegistry = &writerRegistry{
	writers: make(map[string]*sharedWriterEntry),
}

// sharedWriter wraps an AuditRecordWriter to support shared access from multiple callers.
// Each caller gets their own sharedWriter instance, but they all share the same underlying writer.
type sharedWriter struct {
	key         string  // registry key (file path)
	localRecords int64  // records written by this instance
}

// getOrCreateWriter returns a shared writer for the given key.
// If a writer already exists for this key, increments its reference count.
// Otherwise creates a new writer using the provided factory function.
func (r *writerRegistry) getOrCreateWriter(key string, factory func() AuditRecordWriter) *sharedWriter {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.writers[key]
	if exists {
		entry.refCount++
		ioLog.Info("reusing existing writer",
			zap.String("key", key),
			zap.Int("refCount", entry.refCount))
		return &sharedWriter{key: key}
	}

	// Create new writer
	writer := factory()
	r.writers[key] = &sharedWriterEntry{
		writer:   writer,
		refCount: 1,
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
		sw.localRecords++
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
func GetSharedAuditRecordWriter(wc *WriterConfig) AuditRecordWriter {
	// Generate a unique key for this writer based on output path and name
	key := wc.Out + "/" + wc.Name
	
	return globalWriterRegistry.getOrCreateWriter(key, func() AuditRecordWriter {
		return NewAuditRecordWriter(wc)
	})
}

