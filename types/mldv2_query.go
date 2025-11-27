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
	fieldMaximumResponseCode          = "MaximumResponseCode"
	fieldMulticastAddress             = "MulticastAddress"
	fieldSuppressRoutersideProcessing = "SuppressRoutersideProcessing"
	fieldQueriersRobustnessVariable   = "QueriersRobustnessVariable"
	fieldQueriersQueryIntervalCode    = "QueriersQueryIntervalCode"
	fieldIsGeneralQuery               = "IsGeneralQuery"
	fieldIsGroupSpecificQuery         = "IsGroupSpecificQuery"
	fieldIsGroupAndSourceQuery        = "IsGroupAndSourceQuery"
)

var fieldsMLDv2MulticastListenerQuery = []string{
	fieldTimestamp,
	fieldMaximumResponseCode,          // int32
	fieldMulticastAddress,             // string
	fieldSuppressRoutersideProcessing, // bool
	fieldQueriersRobustnessVariable,   // int32
	fieldQueriersQueryIntervalCode,    // int32
	fieldNumberOfSources,              // int32
	fieldSourceAddresses,              // []string
	fieldSrcIP,                        // string
	fieldDstIP,                        // string
	fieldIsGeneralQuery,               // bool
	fieldIsGroupSpecificQuery,         // bool
	fieldIsGroupAndSourceQuery,        // bool
}

// CSVHeader returns the CSV header for the audit record.
func (m *MLDv2MulticastListenerQuery) CSVHeader() []string {
	return filter(fieldsMLDv2MulticastListenerQuery)
}

// CSVRecord returns the CSV record for the audit record.
func (m *MLDv2MulticastListenerQuery) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(m.Timestamp),
		formatInt32(m.MaximumResponseCode),                   // int32
		m.MulticastAddress,                                   // string
		strconv.FormatBool(m.SuppressRoutersideProcessing),   // bool
		formatInt32(m.QueriersRobustnessVariable),            // int32
		formatInt32(m.QueriersQueryIntervalCode),             // int32
		formatInt32(m.NumberOfSources),                       // int32
		join(m.SourceAddresses...),                           // []string
		m.SrcIP,                                              // string
		m.DstIP,                                              // string
		strconv.FormatBool(m.IsGeneralQuery),                 // bool
		strconv.FormatBool(m.IsGroupSpecificQuery),           // bool
		strconv.FormatBool(m.IsGroupAndSourceQuery),          // bool
	})
}

// Time returns the timestamp associated with the audit record.
func (m *MLDv2MulticastListenerQuery) Time() int64 {
	return m.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (m *MLDv2MulticastListenerQuery) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	m.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(m)
}

var mldv2QueryMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_MLDv2MulticastListenerQuery.String()),
		Help: Type_NC_MLDv2MulticastListenerQuery.String() + " audit records",
	},
	fieldsMLDv2MulticastListenerQuery[1:],
)

// Inc increments the metrics for the audit record.
func (m *MLDv2MulticastListenerQuery) Inc() {
	mldv2QueryMetric.WithLabelValues(m.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (m *MLDv2MulticastListenerQuery) SetPacketContext(ctx *PacketContext) {
	m.SrcIP = ctx.SrcIP
	m.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (m *MLDv2MulticastListenerQuery) Src() string {
	return m.SrcIP
}

// Dst returns the destination address of the audit record.
func (m *MLDv2MulticastListenerQuery) Dst() string {
	return m.DstIP
}

var mldv2QueryEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (m *MLDv2MulticastListenerQuery) Encode() []string {
	return filter([]string{
		mldv2QueryEncoder.Int64(fieldTimestamp, m.Timestamp),
		mldv2QueryEncoder.Int32(fieldMaximumResponseCode, m.MaximumResponseCode),                // int32
		mldv2QueryEncoder.String(fieldMulticastAddress, m.MulticastAddress),                     // string
		mldv2QueryEncoder.Bool(m.SuppressRoutersideProcessing),                                  // bool
		mldv2QueryEncoder.Int32(fieldQueriersRobustnessVariable, m.QueriersRobustnessVariable),  // int32
		mldv2QueryEncoder.Int32(fieldQueriersQueryIntervalCode, m.QueriersQueryIntervalCode),    // int32
		mldv2QueryEncoder.Int32(fieldNumberOfSources, m.NumberOfSources),                        // int32
		mldv2QueryEncoder.String(fieldSourceAddresses, join(m.SourceAddresses...)),              // []string
		mldv2QueryEncoder.String(fieldSrcIP, m.SrcIP),                                           // string
		mldv2QueryEncoder.String(fieldDstIP, m.DstIP),                                           // string
		mldv2QueryEncoder.Bool(m.IsGeneralQuery),                                                // bool
		mldv2QueryEncoder.Bool(m.IsGroupSpecificQuery),                                          // bool
		mldv2QueryEncoder.Bool(m.IsGroupAndSourceQuery),                                         // bool
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (m *MLDv2MulticastListenerQuery) Analyze() {}

// NetcapType returns the type of the current audit record
func (m *MLDv2MulticastListenerQuery) NetcapType() Type {
	return Type_NC_MLDv2MulticastListenerQuery
}

