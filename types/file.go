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

package types

import (
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldName        = "Name"
	fieldHash        = "Hash"
	fieldIdent       = "Ident"
	fieldSource      = "Source"
	fieldContentType = "ContentType"
)

var fieldsFile = []string{
	fieldTimestamp,
	fieldName,
	fieldLength,
	fieldHash,
	fieldLocation,
	fieldIdent,
	fieldSource,
	fieldContentType,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *File) CSVHeader() []string {
	return filter(fieldsFile)
}

// CSVRecord returns the CSV record for the audit record.
func (a *File) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.Name,
		formatInt64(a.Length),
		a.Hash,
		a.Location,
		a.Ident,
		a.Source,
		a.ContentType,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *File) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *File) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var fieldsFileMetric = []string{
	fieldName,
	fieldLength,
	fieldHash,
	fieldLocation,
	fieldIdent,
	fieldSource,
	fieldContentType,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

var fileMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_File.String()),
		Help: Type_NC_File.String() + " audit records",
	},
	fieldsFileMetric,
)

// CSVRecord returns the CSV record for the audit record.
func (a *File) metricValues() []string {
	return filter([]string{
		a.Name,
		formatInt64(a.Length),
		a.Hash,
		a.Location,
		a.Ident,
		a.Source,
		a.ContentType,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Inc increments the metrics for the audit record.
func (a *File) Inc() {
	fileMetric.WithLabelValues(a.metricValues()...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *File) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *File) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *File) Dst() string {
	return a.DstIP
}

var fileEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *File) Encode() []string {
	return filter([]string{
		fileEncoder.Int64(fieldTimestamp, a.Timestamp),
		fileEncoder.String(fieldName, a.Name),
		fileEncoder.Int64(fieldLength, a.Length),
		fileEncoder.String(fieldHash, a.Hash),
		fileEncoder.String(fieldLocation, a.Location),
		fileEncoder.String(fieldIdent, a.Ident),
		fileEncoder.String(fieldSource, a.Source),
		fileEncoder.String(fieldContentType, a.ContentType),
		fileEncoder.String(fieldSrcIP, a.SrcIP),
		fileEncoder.String(fieldDstIP, a.DstIP),
		fileEncoder.Int32(fieldSrcPort, a.SrcPort),
		fileEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *File) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *File) NetcapType() Type {
	return Type_NC_File
}
