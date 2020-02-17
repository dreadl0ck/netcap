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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsSCTP = []string{
	"Timestamp",
	"SrcPort",
	"DstPort",
	"VerificationTag",
	"Checksum",
	"SrcIP",
	"DstIP",
}

func (s SCTP) CSVHeader() []string {
	return filter(fieldsSCTP)
}

func (s SCTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		strconv.FormatUint(uint64(s.SrcPort), 10),
		strconv.FormatUint(uint64(s.DstPort), 10),
		strconv.FormatUint(uint64(s.VerificationTag), 10),
		strconv.FormatUint(uint64(s.Checksum), 10),
		s.Context.SrcIP,
		s.Context.DstIP,
	})
}

func (s SCTP) Time() string {
	return s.Timestamp
}

func (u SCTP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&u)
}

var sctpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SCTP.String()),
		Help: Type_NC_SCTP.String() + " audit records",
	},
	fieldsSCTP[1:],
)

func init() {
	prometheus.MustRegister(sctpMetric)
}

func (a SCTP) Inc() {
	sctpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *SCTP) SetPacketContext(ctx *PacketContext) {

	// clear duplicate data
	ctx.SrcIP = ""
	ctx.DstIP = ""

	a.Context = ctx
}

func (a SCTP) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a SCTP) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
