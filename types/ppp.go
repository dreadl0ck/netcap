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
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldPPPType          = "PPPType"
	fieldPPPTypeName      = "PPPTypeName"
	fieldHasPPTPHeader    = "HasPPTPHeader"
	fieldIsControlProtocol = "IsControlProtocol"
	fieldIsAuthentication = "IsAuthentication"
	fieldIsIPv4           = "IsIPv4"
	fieldIsIPv6           = "IsIPv6"
)

var fieldsPPP = []string{
	fieldTimestamp,
	fieldPPPType,          // int32
	fieldPPPTypeName,      // string
	fieldHasPPTPHeader,    // bool
	fieldIsControlProtocol, // bool
	fieldIsAuthentication, // bool
	fieldIsIPv4,           // bool
	fieldIsIPv6,           // bool
}

// CSVHeader returns the CSV header for the audit record.
func (p *PPP) CSVHeader() []string {
	return filter(fieldsPPP)
}

// CSVRecord returns the CSV record for the audit record.
func (p *PPP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(p.Timestamp),
		formatInt32(p.PPPType),                    // int32
		p.PPPTypeName,                             // string
		strconv.FormatBool(p.HasPPTPHeader),       // bool
		strconv.FormatBool(p.IsControlProtocol),   // bool
		strconv.FormatBool(p.IsAuthentication),    // bool
		strconv.FormatBool(p.IsIPv4),              // bool
		strconv.FormatBool(p.IsIPv6),              // bool
	})
}

// Time returns the timestamp associated with the audit record.
func (p *PPP) Time() int64 {
	return p.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (p *PPP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	p.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(p)
}

var pppMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_PPP.String()),
		Help: Type_NC_PPP.String() + " audit records",
	},
	fieldsPPP[1:],
)

// Inc increments the metrics for the audit record.
func (p *PPP) Inc() {
	pppMetric.WithLabelValues(p.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (p *PPP) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (p *PPP) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (p *PPP) Dst() string {
	return ""
}

var pppEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (p *PPP) Encode() []string {
	return filter([]string{
		pppEncoder.Int64(fieldTimestamp, p.Timestamp),
		pppEncoder.Int32(fieldPPPType, p.PPPType),          // int32
		pppEncoder.String(fieldPPPTypeName, p.PPPTypeName), // string
		pppEncoder.Bool(p.HasPPTPHeader),                   // bool
		pppEncoder.Bool(p.IsControlProtocol),               // bool
		pppEncoder.Bool(p.IsAuthentication),                // bool
		pppEncoder.Bool(p.IsIPv4),                          // bool
		pppEncoder.Bool(p.IsIPv6),                          // bool
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (p *PPP) Analyze() {}

// NetcapType returns the type of the current audit record
func (p *PPP) NetcapType() Type {
	return Type_NC_PPP
}

