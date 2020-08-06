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

var fieldsEthernetCTPReply = []string{
	"Timestamp",
	"Function",      // int32
	"ReceiptNumber", // int32
	"Data",          // bytes
}

func (ectpr *EthernetCTPReply) CSVHeader() []string {
	return filter(fieldsEthernetCTPReply)
}

func (ectpr *EthernetCTPReply) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(ectpr.Timestamp),
		formatInt32(ectpr.Function),
		formatInt32(ectpr.ReceiptNumber),
		hex.EncodeToString(ectpr.Data),
	})
}

func (ectpr *EthernetCTPReply) Time() string {
	return ectpr.Timestamp
}

func (ectpr *EthernetCTPReply) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(ectpr)
}

var ethernetCTPReplyMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EthernetCTPReply.String()),
		Help: Type_NC_EthernetCTPReply.String() + " audit records",
	},
	fieldsEthernetCTPReply[1:],
)

func init() {
	prometheus.MustRegister(ethernetCTPReplyMetric)
}

func (ectpr *EthernetCTPReply) Inc() {
	ethernetCTPReplyMetric.WithLabelValues(ectpr.CSVRecord()[1:]...).Inc()
}

func (ectpr *EthernetCTPReply) SetPacketContext(*PacketContext) {}

// TODO
func (ectpr *EthernetCTPReply) Src() string {
	return ""
}

func (ectpr *EthernetCTPReply) Dst() string {
	return ""
}
