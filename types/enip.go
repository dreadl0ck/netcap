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
	"encoding/hex"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsENIP = []string{
	"Timestamp",
	"Command",         // uint32
	"Length",          // uint32
	"SessionHandle",   // uint32
	"Status",          // uint32
	"SenderContext",   // []byte
	"Options",         // uint32
	"CommandSpecific", // *ENIPCommandSpecificData
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

// CSVHeader returns the CSV header for the audit record.
func (en *ENIP) CSVHeader() []string {
	return filter(fieldsENIP)
}

// CSVRecord returns the CSV record for the audit record.
func (en *ENIP) CSVRecord() []string {
	// prevent accessing nil pointer
	if en.Context == nil {
		en.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(en.Timestamp),
		formatUint32(en.Command),             // uint32
		formatUint32(en.Length),              // uint32
		formatUint32(en.SessionHandle),       // uint32
		formatUint32(en.Status),              // uint32
		hex.EncodeToString(en.SenderContext), // []byte
		formatUint32(en.Options),             // uint32
		en.CommandSpecific.String(),          // *ENIPCommandSpecificData
		en.Context.SrcIP,
		en.Context.DstIP,
		en.Context.SrcPort,
		en.Context.DstPort,
	})
}

// Time returns the timestamp associated with the audit record.
func (en *ENIP) Time() string {
	return en.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (en *ENIP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(en)
}

var enipMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ENIP.String()),
		Help: Type_NC_ENIP.String() + " audit records",
	},
	fieldsENIP[1:],
)

// Inc increments the metrics for the audit record.
func (en *ENIP) Inc() {
	enipMetric.WithLabelValues(en.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (en *ENIP) SetPacketContext(ctx *PacketContext) {
	en.Context = ctx
}

// Src returns the source address of the audit record.
func (en *ENIP) Src() string {
	if en.Context != nil {
		return en.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (en *ENIP) Dst() string {
	if en.Context != nil {
		return en.Context.DstIP
	}
	return ""
}
