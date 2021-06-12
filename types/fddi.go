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
	fieldFrameControl = "FrameControl"
)

var fieldsFDDI = []string{
	fieldTimestamp,
	fieldFrameControl, //  int32
	fieldPriority,     //  int32
	fieldSrcMAC,       //  string
	fieldDstMAC,       //  string
}

// CSVHeader returns the CSV header for the audit record.
func (a *FDDI) CSVHeader() []string {
	return filter(fieldsFDDI)
}

// CSVRecord returns the CSV record for the audit record.
func (a *FDDI) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.FrameControl), //  int32
		formatInt32(a.Priority),     //  int32
		a.SrcMAC,                    //  string
		a.DstMAC,                    //  string
	})
}

// Time returns the timestamp associated with the audit record.
func (a *FDDI) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *FDDI) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var fddiMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_FDDI.String()),
		Help: Type_NC_FDDI.String() + " audit records",
	},
	fieldsFDDI[1:],
)

// Inc increments the metrics for the audit record.
func (a *FDDI) Inc() {
	fddiMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *FDDI) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *FDDI) Src() string {
	return a.SrcMAC
}

// Dst returns the destination address of the audit record.
func (a *FDDI) Dst() string {
	return a.DstMAC
}

var fddiEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *FDDI) Encode() []string {
	return filter([]string{
		fddiEncoder.Int64(fieldTimestamp, a.Timestamp),
		fddiEncoder.Int32(fieldFrameControl, a.FrameControl), //  int32
		fddiEncoder.Int32(fieldPriority, a.Priority),         //  int32
		fddiEncoder.String(fieldSrcMAC, a.SrcMAC),            //  string
		fddiEncoder.String(fieldDstMAC, a.DstMAC),            //  string
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *FDDI) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *FDDI) NetcapType() Type {
	return Type_NC_FDDI
}
