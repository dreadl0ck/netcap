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
	fieldResponse         = "Response"
	fieldServiceID        = "ServiceID"
	fieldClassID          = "ClassID"
	fieldInstanceID       = "InstanceID"
	fieldStatus           = "Status"
	fieldAdditionalStatus = "AdditionalStatus"
	fieldData             = "Data"
	fieldSrcIP            = "SrcIP"
	fieldDstIP            = "DstIP"
	fieldSrcPort          = "SrcPort"
	fieldDstPort          = "DstPort"
)

var fieldsCIP = []string{
	fieldTimestamp,
	fieldResponse,         // bool
	fieldServiceID,        // int32
	fieldClassID,          // uint32
	fieldInstanceID,       // uint32
	fieldStatus,           // int32
	fieldAdditionalStatus, // []uint32
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (c *CIP) CSVHeader() []string {
	return filter(fieldsCIP)
}

// CSVRecord returns the CSV record for the audit record.
func (c *CIP) CSVRecord() []string {
	additional := make([]string, len(c.AdditionalStatus))

	if c.Response {
		for _, v := range c.AdditionalStatus {
			additional = append(additional, formatUint32(v))
		}
	}

	return filter([]string{
		formatTimestamp(c.Timestamp),
		strconv.FormatBool(c.Response), // bool
		formatInt32(c.ServiceID),       // int32
		formatUint32(c.ClassID),        // uint32
		formatUint32(c.InstanceID),     // uint32
		formatInt32(c.Status),          // int32
		strings.Join(additional, "-"),  // []uint32
		c.SrcIP,
		c.DstIP,
		formatInt32(c.SrcPort),
		formatInt32(c.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (c *CIP) Time() int64 {
	return c.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (c *CIP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	c.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(c)
}

var cipMetric = prometheus.NewCounterVec( //nolint:gochecknoglobals
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CIP.String()),
		Help: Type_NC_CIP.String() + " audit records",
	},
	fieldsCIP[1:],
)

// Inc increments the metrics for the audit record.
func (c *CIP) Inc() {
	cipMetric.WithLabelValues(c.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (c *CIP) SetPacketContext(ctx *PacketContext) {
	c.SrcIP = ctx.SrcIP
	c.DstIP = ctx.DstIP
	c.SrcPort = ctx.SrcPort
	c.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (c *CIP) Src() string {
	return c.SrcIP
}

// Dst returns the destination address of the audit record.
func (c *CIP) Dst() string {
	return c.DstIP
}

var cipEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (c *CIP) Encode() []string {

	additional := make([]string, len(c.AdditionalStatus))

	if c.Response {
		for _, v := range c.AdditionalStatus {
			additional = append(additional, formatUint32(v))
		}
	}

	return filter([]string{
		cipEncoder.Int64(fieldTimestamp, c.Timestamp),
		cipEncoder.Bool(c.Response),                                             // bool
		cipEncoder.Int32(fieldServiceID, c.ServiceID),                           // int32
		cipEncoder.Uint32(fieldClassID, c.ClassID),                              // uint32
		cipEncoder.Uint32(fieldInstanceID, c.InstanceID),                        // uint32
		cipEncoder.Int32(fieldStatus, c.Status),                                 // int32
		cipEncoder.String(fieldAdditionalStatus, strings.Join(additional, "-")), // []uint32
		cipEncoder.String(fieldSrcIP, c.SrcIP),
		cipEncoder.String(fieldDstIP, c.DstIP),
		cipEncoder.Int32(fieldSrcPort, c.SrcPort),
		cipEncoder.Int32(fieldDstPort, c.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (c *CIP) Analyze() {

}

// NetcapType returns the type of the current audit record
func (c *CIP) NetcapType() Type {
	return Type_NC_CIP
}
