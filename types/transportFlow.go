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

var fieldsTransportFlow = []string{
	"TimestampFirst",
	"TimestampLast",
	"Proto",
	"SrcPort",
	"DstPort",
	"TotalSize",
	"NumPackets",
	"UID",
	"Duration",
}

func (f TransportFlow) CSVHeader() []string {
	return filter(fieldsTransportFlow)
}

func (f TransportFlow) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(f.TimestampFirst),
		formatTimestamp(f.TimestampLast),
		f.Proto,
		formatInt32(f.SrcPort),
		formatInt32(f.DstPort),
		formatInt64(f.TotalSize),
		formatInt64(f.NumPackets),
		strconv.FormatUint(f.UID, 10),
		formatInt64(f.Duration),
	})
}

func (f TransportFlow) Time() string {
	return f.TimestampFirst
}

func (u TransportFlow) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&u)
}

var transportFlowMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_TransportFlow.String()),
		Help: Type_NC_TransportFlow.String() + " audit records",
	},
	fieldsTransportFlow[1:],
)

func init() {
	prometheus.MustRegister(transportFlowMetric)
}

func (a TransportFlow) Inc() {
	transportFlowMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *TransportFlow) SetPacketContext(ctx *PacketContext) {}

func (a TransportFlow) Src() string {
	return formatInt32(a.SrcPort)
}

func (a TransportFlow) Dst() string {
	return formatInt32(a.DstPort)
}
