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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsFDDI = []string{
	"Timestamp",
	"FrameControl", //  int32
	"Priority",     //  int32
	"SrcMAC",       //  string
	"DstMAC",       //  string
}

func (a FDDI) CSVHeader() []string {
	return filter(fieldsFDDI)
}

func (a FDDI) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.FrameControl), //  int32
		formatInt32(a.Priority),     //  int32
		a.SrcMAC,                    //  string
		a.DstMAC,                    //  string
	})
}

func (a FDDI) NetcapTimestamp() string {
	return a.Timestamp
}

func (a FDDI) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var fddiMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_FDDI.String()),
		Help: Type_NC_FDDI.String() + " audit records",
	},
	fieldsFDDI,
)

func init() {
	prometheus.MustRegister(fddiMetric)
}

func (a FDDI) Inc() {
	fddiMetric.WithLabelValues(a.CSVRecord()...).Inc()
}
