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
	fieldFunction      = "Function"
	fieldReceiptNumber = "ReceiptNumber"
)

var fieldsEthernetCTPReply = []string{
	fieldTimestamp,
	fieldFunction,      // int32
	fieldReceiptNumber, // int32
	//fieldData,          // bytes
}

// CSVHeader returns the CSV header for the audit record.
func (ectpr *EthernetCTPReply) CSVHeader() []string {
	return filter(fieldsEthernetCTPReply)
}

// CSVRecord returns the CSV record for the audit record.
func (ectpr *EthernetCTPReply) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(ectpr.Timestamp),
		formatInt32(ectpr.Function),
		formatInt32(ectpr.ReceiptNumber),
		//hex.EncodeToString(ectpr.Data),
	})
}

// Time returns the timestamp associated with the audit record.
func (ectpr *EthernetCTPReply) Time() int64 {
	return ectpr.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (ectpr *EthernetCTPReply) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	ectpr.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(ectpr)
}

var ethernetCTPReplyMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EthernetCTPReply.String()),
		Help: Type_NC_EthernetCTPReply.String() + " audit records",
	},
	fieldsEthernetCTPReply[1:],
)

// Inc increments the metrics for the audit record.
func (ectpr *EthernetCTPReply) Inc() {
	ethernetCTPReplyMetric.WithLabelValues(ectpr.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (ectpr *EthernetCTPReply) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (ectpr *EthernetCTPReply) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (ectpr *EthernetCTPReply) Dst() string {
	return ""
}

var ethCTPReplyEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (ectpr *EthernetCTPReply) Encode() []string {
	return filter([]string{
		ethCTPReplyEncoder.Int64(fieldTimestamp, ectpr.Timestamp),
		ethCTPReplyEncoder.Int32(fieldFunction, ectpr.Function),
		ethCTPReplyEncoder.Int32(fieldReceiptNumber, ectpr.ReceiptNumber),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (ectpr *EthernetCTPReply) Analyze() {}

// NetcapType returns the type of the current audit record
func (ectpr *EthernetCTPReply) NetcapType() Type {
	return Type_NC_EthernetCTPReply
}
