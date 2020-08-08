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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsLLC = []string{
	"Timestamp", // string
	"DSAP",      // int32
	"IG",        // bool
	"SSAP",      // int32
	"CR",        // bool
	"Control",   // int32
}

// CSVHeader returns the CSV header for the audit record.
func (l *LLC) CSVHeader() []string {
	return filter(fieldsLLC)
}

// CSVRecord returns the CSV record for the audit record.
func (l *LLC) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(l.Timestamp),
		formatInt32(l.DSAP),      // int32
		strconv.FormatBool(l.IG), // bool
		formatInt32(l.SSAP),      // int32
		strconv.FormatBool(l.CR), // bool
		formatInt32(l.Control),   // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (l *LLC) Time() string {
	return l.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (l *LLC) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(l)
}

var llcMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LLC.String()),
		Help: Type_NC_LLC.String() + " audit records",
	},
	fieldsLLC[1:],
)

// Inc increments the metrics for the audit record.
func (l *LLC) Inc() {
	llcMetric.WithLabelValues(l.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (l *LLC) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (l *LLC) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (l *LLC) Dst() string {
	return ""
}
