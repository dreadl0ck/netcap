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
	fieldCode     = "Code"
	fieldId       = "Id"
	fieldLength   = "Length"
	fieldTypeData = "TypeData"
)

var fieldsEAP = []string{
	fieldTimestamp,
	fieldCode,   // int32
	fieldId,     // int32
	fieldLength, // int32
	fieldType,   // int32
	//fieldTypeData, // []byte
}

// CSVHeader returns the CSV header for the audit record.
func (a *EAP) CSVHeader() []string {
	return filter(fieldsEAP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *EAP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Code),   // int32
		formatInt32(a.Id),     // int32
		formatInt32(a.Length), // int32
		formatInt32(a.Type),   // int32
		//hex.EncodeToString(a.TypeData), // []byte
	})
}

// Time returns the timestamp associated with the audit record.
func (a *EAP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *EAP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var eapMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EAP.String()),
		Help: Type_NC_EAP.String() + " audit records",
	},
	fieldsEAP[1:],
)

// Inc increments the metrics for the audit record.
func (a *EAP) Inc() {
	eapMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *EAP) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr.
// Src returns the source address of the audit record.
func (a *EAP) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *EAP) Dst() string {
	return ""
}

var eapEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *EAP) Encode() []string {
	return filter([]string{
		eapEncoder.Int64(fieldTimestamp, a.Timestamp),
		eapEncoder.Int32(fieldCode, a.Code),     // int32
		eapEncoder.Int32(fieldId, a.Id),         // int32
		eapEncoder.Int32(fieldLength, a.Length), // int32
		eapEncoder.Int32(fieldType, a.Type),     // int32
		//hex.EncodeToString(a.TypeData), // []byte
	})
}

// Analyze will invoke the configured analyzer(s) for the audit record and return a score.
func (a *EAP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *EAP) NetcapType() Type {
	return Type_NC_EAP
}
