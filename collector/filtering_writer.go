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

package collector

import (
	"sync/atomic"
	"time"

	"github.com/gogo/protobuf/proto"

	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// FilteringWriter wraps an AuditRecordWriter and applies filtering and rules before writing.
type FilteringWriter struct {
	underlying netio.AuditRecordWriter
	collector  *Collector
}

// NewFilteringWriter creates a new filtering writer that wraps an underlying writer.
func NewFilteringWriter(underlying netio.AuditRecordWriter, collector *Collector) *FilteringWriter {
	return &FilteringWriter{
		underlying: underlying,
		collector:  collector,
	}
}

// Write applies filtering and rules evaluation before writing the record.
func (fw *FilteringWriter) Write(msg proto.Message) error {
	// Try to cast to AuditRecord
	auditRecord, ok := msg.(types.AuditRecord)
	if !ok {
		// Not an audit record, write directly
		return fw.underlying.Write(msg)
	}

	// First, evaluate rules (even if the record will be filtered out)
	// This ensures we don't miss alerts for filtered traffic
	rulesStart := time.Now()
	alertsGenerated := fw.collector.EvaluateRulesWithMetrics(auditRecord)
	if fw.collector.perfTracker != nil {
		fw.collector.perfTracker.RecordRulesEvaluation(time.Since(rulesStart), alertsGenerated)
	}

	// Then check if the record should be written based on the filter
	filterStart := time.Now()
	shouldWrite := fw.collector.ShouldWriteRecord(auditRecord)
	if fw.collector.perfTracker != nil {
		fw.collector.perfTracker.RecordFilterEvaluation(time.Since(filterStart), !shouldWrite)
	}

	if !shouldWrite {
		// Record filtered out, don't write
		return nil
	}

	// Record passes filter, write it
	return fw.underlying.Write(msg)
}

// WriteHeader writes the header to the underlying writer.
func (fw *FilteringWriter) WriteHeader(t types.Type) error {
	return fw.underlying.WriteHeader(t)
}

// Close closes the underlying writer.
func (fw *FilteringWriter) Close(numRecords int64) (name string, size int64) {
	return fw.underlying.Close(numRecords)
}

// Flush flushes the underlying writer's buffer.
func (fw *FilteringWriter) Flush() error {
	return fw.underlying.Flush()
}

// GetFilteredCount returns the number of records filtered out.
func (c *Collector) GetFilteredCount() int64 {
	return atomic.LoadInt64(&c.filteredCount)
}

// GetAlertCount returns the number of alerts generated.
func (c *Collector) GetAlertCount() int64 {
	return atomic.LoadInt64(&c.alertCount)
}
