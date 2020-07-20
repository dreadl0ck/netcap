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

var fieldsSCTP = []string{
	"Timestamp",
	"SrcPort",
	"DstPort",
	"VerificationTag",
	"Checksum",
	"SrcIP",
	"DstIP",
}

func (s *SCTP) CSVHeader() []string {
	return filter(fieldsSCTP)
}

func (s *SCTP) CSVRecord() []string {
	// prevent accessing nil pointer
	if s.Context == nil {
		s.Context = &PacketContext{}
	}
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

func (s *SCTP) Time() string {
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

func (s *SCTP) Inc() {
	sctpMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

func (s *SCTP) SetPacketContext(ctx *PacketContext) {

	// create new context and only add information that is
	// not yet present on the audit record type
	s.Context = &PacketContext{
		SrcPort: ctx.SrcPort,
		DstPort: ctx.DstPort,
	}
}

func (s *SCTP) Src() string {
	if s.Context != nil {
		return s.Context.SrcIP
	}
	return ""
}

func (s *SCTP) Dst() string {
	if s.Context != nil {
		return s.Context.DstIP
	}
	return ""
}
