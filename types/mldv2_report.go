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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldNumberOfMulticastAddressRecords = "NumberOfMulticastAddressRecords"
	fieldMulticastAddressRecords         = "MulticastAddressRecords"
	fieldMLDRecordType                   = "RecordType"
	fieldMLDRecordTypeName               = "RecordTypeName"
	fieldMLDAuxDataLen                   = "AuxDataLen"
	fieldMLDAuxiliaryData                = "AuxiliaryData"
	fieldHasJoinRecords                  = "HasJoinRecords"
	fieldHasLeaveRecords                 = "HasLeaveRecords"
)

var fieldsMLDv2MulticastListenerReport = []string{
	fieldTimestamp,
	fieldNumberOfMulticastAddressRecords, // int32
	fieldMulticastAddressRecords,         // []*MLDv2MulticastAddressRecord
	fieldSrcIP,                           // string
	fieldDstIP,                           // string
	fieldHasJoinRecords,                  // bool
	fieldHasLeaveRecords,                 // bool
}

// CSVHeader returns the CSV header for the audit record.
func (m *MLDv2MulticastListenerReport) CSVHeader() []string {
	return filter(fieldsMLDv2MulticastListenerReport)
}

func (r *MLDv2MulticastAddressRecord) toString() string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.RecordType))
	b.WriteString(FieldSeparator)
	b.WriteString(r.RecordTypeName)
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.AuxDataLen))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.NumberOfSources))
	b.WriteString(FieldSeparator)
	b.WriteString(r.MulticastAddress)
	b.WriteString(FieldSeparator)
	b.WriteString(join(r.SourceAddresses...))
	b.WriteString(StructureEnd)
	return b.String()
}

// CSVRecord returns the CSV record for the audit record.
func (m *MLDv2MulticastListenerReport) CSVRecord() []string {
	records := make([]string, 0, len(m.MulticastAddressRecords))
	for _, r := range m.MulticastAddressRecords {
		records = append(records, r.toString())
	}

	return filter([]string{
		formatTimestamp(m.Timestamp),
		formatInt32(m.NumberOfMulticastAddressRecords), // int32
		strings.Join(records, ""),                      // []*MLDv2MulticastAddressRecord
		m.SrcIP,                                        // string
		m.DstIP,                                        // string
		strconv.FormatBool(m.HasJoinRecords),           // bool
		strconv.FormatBool(m.HasLeaveRecords),          // bool
	})
}

// Time returns the timestamp associated with the audit record.
func (m *MLDv2MulticastListenerReport) Time() int64 {
	return m.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (m *MLDv2MulticastListenerReport) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	m.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(m)
}

var mldv2ReportMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_MLDv2MulticastListenerReport.String()),
		Help: Type_NC_MLDv2MulticastListenerReport.String() + " audit records",
	},
	fieldsMLDv2MulticastListenerReport[1:],
)

// Inc increments the metrics for the audit record.
func (m *MLDv2MulticastListenerReport) Inc() {
	mldv2ReportMetric.WithLabelValues(m.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (m *MLDv2MulticastListenerReport) SetPacketContext(ctx *PacketContext) {
	m.SrcIP = ctx.SrcIP
	m.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (m *MLDv2MulticastListenerReport) Src() string {
	return m.SrcIP
}

// Dst returns the destination address of the audit record.
func (m *MLDv2MulticastListenerReport) Dst() string {
	return m.DstIP
}

var mldv2ReportEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (m *MLDv2MulticastListenerReport) Encode() []string {
	records := make([]string, 0, len(m.MulticastAddressRecords))
	for _, r := range m.MulticastAddressRecords {
		records = append(records, r.toString())
	}

	return filter([]string{
		mldv2ReportEncoder.Int64(fieldTimestamp, m.Timestamp),
		mldv2ReportEncoder.Int32(fieldNumberOfMulticastAddressRecords, m.NumberOfMulticastAddressRecords), // int32
		mldv2ReportEncoder.String(fieldMulticastAddressRecords, strings.Join(records, "")),                // []*MLDv2MulticastAddressRecord
		mldv2ReportEncoder.String(fieldSrcIP, m.SrcIP),                                                    // string
		mldv2ReportEncoder.String(fieldDstIP, m.DstIP),                                                    // string
		mldv2ReportEncoder.Bool(m.HasJoinRecords),                                                         // bool
		mldv2ReportEncoder.Bool(m.HasLeaveRecords),                                                        // bool
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (m *MLDv2MulticastListenerReport) Analyze() {}

// NetcapType returns the type of the current audit record
func (m *MLDv2MulticastListenerReport) NetcapType() Type {
	return Type_NC_MLDv2MulticastListenerReport
}

