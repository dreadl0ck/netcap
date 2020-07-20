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

func (e *ENIP) CSVHeader() []string {
	return filter(fieldsENIP)
}
func (e *ENIP) CSVRecord() []string {
	// prevent accessing nil pointer
	if e.Context == nil {
		e.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(e.Timestamp),
		formatUint32(e.Command),             // uint32
		formatUint32(e.Length),              // uint32
		formatUint32(e.SessionHandle),       // uint32
		formatUint32(e.Status),              // uint32
		hex.EncodeToString(e.SenderContext), // []byte
		formatUint32(e.Options),             // uint32
		e.CommandSpecific.String(),          // *ENIPCommandSpecificData
		e.Context.SrcIP,
		e.Context.DstIP,
		e.Context.SrcPort,
		e.Context.DstPort,
	})
}

func (e *ENIP) Time() string {
	return e.Timestamp
}

func (e *ENIP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(e)
}

var (
	enipMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_ENIP.String()),
			Help: Type_NC_ENIP.String() + " audit records",
		},
		fieldsENIP[1:],
	)
)

func init() {
	prometheus.MustRegister(enipMetric)
}

func (e *ENIP) Inc() {
	enipMetric.WithLabelValues(e.CSVRecord()[1:]...).Inc()
}

func (a *ENIP) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (e *ENIP) Src() string {
	if e.Context != nil {
		return e.Context.SrcIP
	}
	return ""
}

func (e *ENIP) Dst() string {
	if e.Context != nil {
		return e.Context.DstIP
	}
	return ""
}
