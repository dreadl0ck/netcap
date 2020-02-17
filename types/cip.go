/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsCIP = []string{
	"Timestamp",
	"Response",         // bool
	"ServiceID",        // int32
	"ClassID",          // uint32
	"InstanceID",       // uint32
	"Status",           // int32
	"AdditionalStatus", // []uint32
	"Data",             // []byte
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

func (a CIP) CSVHeader() []string {
	return filter(fieldsCIP)
}

func (a CIP) CSVRecord() []string {
	var additional = make([]string, len(a.AdditionalStatus))
	if a.Response {
		for _, v := range a.AdditionalStatus {
			additional = append(additional, formatUint32(v))
		}
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.Response), // bool
		formatInt32(a.ServiceID),       // int32
		formatUint32(a.ClassID),        // uint32
		formatUint32(a.InstanceID),     // uint32
		formatInt32(a.Status),          // int32
		strings.Join(additional, ""),   // []uint32
		hex.EncodeToString(a.Data),     // []byte
		a.Context.SrcIP,
		a.Context.DstIP,
		a.Context.SrcPort,
		a.Context.DstPort,
	})
}

func (a CIP) Time() string {
	return a.Timestamp
}

func (a CIP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var cipMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CIP.String()),
		Help: Type_NC_CIP.String() + " audit records",
	},
	fieldsCIP[1:],
)

func init() {
	prometheus.MustRegister(cipMetric)
}

func (a CIP) Inc() {
	cipMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *CIP) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a CIP) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a CIP) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
