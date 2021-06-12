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
	fieldPriority       = "Priority"
	fieldDropEligible   = "DropEligible"
	fieldVLANIdentifier = "VLANIdentifier"
	fieldType           = "Type"
)

var fieldsDot1Q = []string{
	fieldTimestamp,
	fieldPriority,       //  int32
	fieldDropEligible,   //  bool
	fieldVLANIdentifier, //  int32
	fieldType,           //  int32
}

// CSVHeader returns the CSV header for the audit record.
func (d *Dot1Q) CSVHeader() []string {
	return filter(fieldsDot1Q)
}

// CSVRecord returns the CSV record for the audit record.
func (d *Dot1Q) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		formatInt32(d.Priority),            //  int32
		strconv.FormatBool(d.DropEligible), //  bool
		formatInt32(d.VLANIdentifier),      //  int32
		formatInt32(d.Type),                //  int32
	})
}

// Time returns the timestamp associated with the audit record.
func (d *Dot1Q) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *Dot1Q) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

var dot1qMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Dot1Q.String()),
		Help: Type_NC_Dot1Q.String() + " audit records",
	},
	fieldsDot1Q[1:],
)

// Inc increments the metrics for the audit record.
func (d *Dot1Q) Inc() {
	dot1qMetric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *Dot1Q) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr.
// Src returns the source address of the audit record.
func (d *Dot1Q) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (d *Dot1Q) Dst() string {
	return ""
}

var dot1qEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *Dot1Q) Encode() []string {
	return filter([]string{
		dot1qEncoder.Int64(fieldTimestamp, d.Timestamp),
		dot1qEncoder.Int32(fieldPriority, d.Priority),             //  int32
		dot1qEncoder.Bool(d.DropEligible),                         //  bool
		dot1qEncoder.Int32(fieldVLANIdentifier, d.VLANIdentifier), //  int32
		dot1qEncoder.Int32(fieldType, d.Type),                     //  int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *Dot1Q) Analyze() {
}

// NetcapType returns the type of the current audit record
func (d *Dot1Q) NetcapType() Type {
	return Type_NC_Dot1Q
}
