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

var fieldsLCM = []string{
	"Timestamp",
	"Magic",          // int32
	"SequenceNumber", // int32
	"PayloadSize",    // int32
	"FragmentOffset", // int32
	"FragmentNumber", // int32
	"TotalFragments", // int32
	"ChannelName",    // string
	"Fragmented",     // bool
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

// CSVHeader returns the CSV header for the audit record.
func (a *LCM) CSVHeader() []string {
	return filter(fieldsLCM)
}

// CSVRecord returns the CSV record for the audit record.
func (a *LCM) CSVRecord() []string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Magic),             // int32
		formatInt32(a.SequenceNumber),    // int32
		formatInt32(a.PayloadSize),       // int32
		formatInt32(a.FragmentOffset),    // int32
		formatInt32(a.FragmentNumber),    // int32
		formatInt32(a.TotalFragments),    // int32
		a.ChannelName,                    // string
		strconv.FormatBool(a.Fragmented), // bool
		a.Context.SrcIP,
		a.Context.DstIP,
		a.Context.SrcPort,
		a.Context.DstPort,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *LCM) Time() string {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *LCM) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var lcmMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LCM.String()),
		Help: Type_NC_LCM.String() + " audit records",
	},
	fieldsLCM[1:],
)

func init() {
	prometheus.MustRegister(lcmMetric)
}

// Inc increments the metrics for the audit record.
func (a *LCM) Inc() {
	lcmMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *LCM) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

// Src returns the source address of the audit record.
func (a *LCM) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (a *LCM) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
