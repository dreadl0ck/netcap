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

var fieldsLinkFlow = []string{
	"TimestampFirst",
	"TimestampLast",
	"Proto",
	"SourceMAC",
	"DstMAC",
	"TotalSize",
	"NumPackets",
	"UID",
	"Duration",
}

func (f LinkFlow) CSVHeader() []string {
	return filter(fieldsLinkFlow)
}

func (f LinkFlow) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(f.TimestampFirst),
		formatTimestamp(f.TimestampLast),
		f.Proto,
		f.SrcMAC,
		f.DstMAC,
		formatInt64(f.TotalSize),
		formatInt64(f.NumPackets),
		strconv.FormatUint(f.UID, 10),
		formatInt64(f.Duration),
	})
}

func (f LinkFlow) Time() string {
	return f.TimestampFirst
}

func (a LinkFlow) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var linkFlowMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LinkFlow.String()),
		Help: Type_NC_LinkFlow.String() + " audit records",
	},
	fieldsLinkFlow[1:],
)

func init() {
	prometheus.MustRegister(linkFlowMetric)
}

func (a LinkFlow) Inc() {
	linkFlowMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *LinkFlow) SetPacketContext(ctx *PacketContext) {}

func (a LinkFlow) Src() string {
	return a.SrcMAC
}

func (a LinkFlow) Dst() string {
	return a.DstMAC
}
