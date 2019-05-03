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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsEthernetCTPReply = []string{
	"Timestamp",
	"Function",      // int32
	"ReceiptNumber", // int32
	"Data",          // bytes
}

func (i EthernetCTPReply) CSVHeader() []string {
	return filter(fieldsEthernetCTPReply)
}

func (i EthernetCTPReply) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Function),
		formatInt32(i.ReceiptNumber),
		hex.EncodeToString(i.Data),
	})
}

func (i EthernetCTPReply) NetcapTimestamp() string {
	return i.Timestamp
}

func (a EthernetCTPReply) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
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

func (a EthernetCTPReply) Inc() {
	ethernetCTPReplyMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}
