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
	fieldMITRE        = "MITRE"        // string
	fieldIPReputation = "IPReputation" // string
)

var fieldsAlert = []string{
	fieldTimestamp,
	fieldName,
	fieldDescription,
	fieldSrcIP,
	fieldSrcPort,
	fieldDstIP,
	fieldDstPort,
	fieldMITRE,
	fieldIPReputation,
}

// CSVHeader returns the CSV header for the audit record.
func (a *Alert) CSVHeader() []string {
	return filter(fieldsAlert)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Alert) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.Name,
		a.Description,
		a.SrcIP,
		a.SrcPort,
		a.DstIP,
		a.DstPort,
		a.MITRE,
		a.IPReputation,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Alert) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Alert) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var aMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Alert.String()),
		Help: Type_NC_Alert.String() + " audit records",
	},
	fieldsAlert[1:],
)

// Inc increments the metrics for the audit record.
func (a *Alert) Inc() {
	aMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Alert) SetPacketContext(*PacketContext) {}

// Src TODO: preserve source and destination mac adresses for Alert and return them here.
// Src returns the source address of the audit record.
func (a *Alert) Src() string {
	return ""
}

// Dst TODO: preserve source and destination mac adresses for Alert and return them here.
// Dst returns the destination address of the audit record.
func (a *Alert) Dst() string {
	return ""
}

var aEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Alert) Encode() []string {
	return filter([]string{
		aEncoder.Int64(fieldTimestamp, a.Timestamp), // int64
		aEncoder.String(fieldName, a.Name),
		aEncoder.String(fieldDescription, a.Description),
		aEncoder.String(fieldSrcIP, a.SrcIP),
		aEncoder.String(fieldSrcPort, a.SrcPort),
		aEncoder.String(fieldDstIP, a.DstIP),
		aEncoder.String(fieldDstPort, a.DstPort),
		aEncoder.String(fieldMITRE, a.MITRE),
		aEncoder.String(fieldIPReputation, a.IPReputation),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Alert) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *Alert) NetcapType() Type {
	return Type_NC_Alert
}
