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

var fieldsEAPOL = []string{
	fieldTimestamp,
	fieldVersion, //  int32
	fieldType,    //  int32
	fieldLength,  //  int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *EAPOL) CSVHeader() []string {
	return filter(fieldsEAPOL)
}

// CSVRecord returns the CSV record for the audit record.
func (a *EAPOL) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version), //  int32
		formatInt32(a.Type),    //  int32
		formatInt32(a.Length),  //  int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *EAPOL) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *EAPOL) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var eapPolMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EAPOL.String()),
		Help: Type_NC_EAPOL.String() + " audit records",
	},
	fieldsEAPOL[1:],
)

// Inc increments the metrics for the audit record.
func (a *EAPOL) Inc() {
	eapPolMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *EAPOL) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr.
// Src returns the source address of the audit record.
func (a *EAPOL) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *EAPOL) Dst() string {
	return ""
}

var eapolEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *EAPOL) Encode() []string {
	return filter([]string{
		eapolEncoder.Int64(fieldTimestamp, a.Timestamp),
		eapolEncoder.Int32(fieldVersion, a.Version), //  int32
		eapolEncoder.Int32(fieldType, a.Type),       //  int32
		eapolEncoder.Int32(fieldLength, a.Length),   //  int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *EAPOL) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *EAPOL) NetcapType() Type {
	return Type_NC_EAPOL
}
