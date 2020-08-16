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

	"github.com/dreadl0ck/netcap/utils"
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

// CSVHeader returns the CSV header for the audit record.
func (s *SCTP) CSVHeader() []string {
	return filter(fieldsSCTP)
}

// CSVRecord returns the CSV record for the audit record.
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

// Time returns the timestamp associated with the audit record.
func (s *SCTP) Time() string {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (u *SCTP) JSON() (string, error) {
	u.Timestamp = utils.TimeToUnixMilli(u.Timestamp)
	return jsonMarshaler.MarshalToString(u)
}

var sctpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SCTP.String()),
		Help: Type_NC_SCTP.String() + " audit records",
	},
	fieldsSCTP[1:],
)

// Inc increments the metrics for the audit record.
func (s *SCTP) Inc() {
	sctpMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *SCTP) SetPacketContext(ctx *PacketContext) {
	// create new context and only add information that is
	// not yet present on the audit record type
	s.Context = &PacketContext{
		SrcPort: ctx.SrcPort,
		DstPort: ctx.DstPort,
	}
}

// Src returns the source address of the audit record.
func (s *SCTP) Src() string {
	if s.Context != nil {
		return s.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (s *SCTP) Dst() string {
	if s.Context != nil {
		return s.Context.DstIP
	}
	return ""
}
