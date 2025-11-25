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
	fieldPrefix        = "Prefix"
	fieldParameters    = "Parameters"
	fieldMessage       = "Message"
	fieldIsDCC         = "IsDCC"
	fieldDCCType       = "DCCType"
	fieldDCCFilename   = "DCCFilename"
	fieldDCCIP         = "DCCIP"
	fieldDCCPort       = "DCCPort"
	fieldDCCFilesize   = "DCCFilesize"
	fieldChannel       = "Channel"
	fieldNick          = "Nick"
	fieldIsDataChannel = "IsDataChannel"
)

var fieldsIRC = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldPrefix,
	fieldCommand,
	fieldParameters,
	fieldMessage,
	fieldIsDCC,
	fieldDCCType,
	fieldDCCFilename,
	fieldDCCIP,
	fieldDCCPort,
	fieldDCCFilesize,
	fieldChannel,
	fieldNick,
	fieldIsDataChannel,
}

// CSVHeader returns the CSV header for the audit record.
func (i *IRC) CSVHeader() []string {
	return filter(fieldsIRC)
}

// CSVRecord returns the CSV record for the audit record.
func (i *IRC) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		i.SrcIP,
		i.DstIP,
		formatInt32(i.SrcPort),
		formatInt32(i.DstPort),
		i.Prefix,
		i.Command,
		join(i.Parameters...),
		i.Message,
		strconv.FormatBool(i.IsDCC),
		i.DCCType,
		i.DCCFilename,
		i.DCCIP,
		formatInt32(i.DCCPort),
		formatInt64(i.DCCFilesize),
		i.Channel,
		i.Nick,
		strconv.FormatBool(i.IsDataChannel),
	})
}

// Time returns the timestamp associated with the audit record.
func (i *IRC) Time() int64 {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *IRC) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var ircMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IRC.String()),
		Help: Type_NC_IRC.String() + " audit records",
	},
	fieldsIRC[1:],
)

// Inc increments the metrics for the audit record.
func (i *IRC) Inc() {
	ircMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *IRC) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
	i.SrcPort = ctx.SrcPort
	i.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (i *IRC) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *IRC) Dst() string {
	return i.DstIP
}

var ircEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *IRC) Encode() []string {
	return filter([]string{
		ircEncoder.Int64(fieldTimestamp, i.Timestamp),
		ircEncoder.String(fieldSrcIP, i.SrcIP),
		ircEncoder.String(fieldDstIP, i.DstIP),
		ircEncoder.Int32(fieldSrcPort, i.SrcPort),
		ircEncoder.Int32(fieldDstPort, i.DstPort),
		ircEncoder.String(fieldPrefix, i.Prefix),
		ircEncoder.String(fieldCommand, i.Command),
		ircEncoder.String(fieldParameters, join(i.Parameters...)),
		ircEncoder.String(fieldMessage, i.Message),
		ircEncoder.Bool(i.IsDCC),
		ircEncoder.String(fieldDCCType, i.DCCType),
		ircEncoder.String(fieldDCCFilename, i.DCCFilename),
		ircEncoder.String(fieldDCCIP, i.DCCIP),
		ircEncoder.Int32(fieldDCCPort, i.DCCPort),
		ircEncoder.Int64(fieldDCCFilesize, i.DCCFilesize),
		ircEncoder.String(fieldChannel, i.Channel),
		ircEncoder.String(fieldNick, i.Nick),
		ircEncoder.Bool(i.IsDataChannel),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *IRC) Analyze() {
}

// NetcapType returns the type of the current audit record
func (i *IRC) NetcapType() Type {
	return Type_NC_IRC
}

