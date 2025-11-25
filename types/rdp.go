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
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

// RDP-specific field constants
const (
	fieldRDPConnectionPhase      = "ConnectionPhase"
	fieldRDPRequestedProtocols   = "RequestedProtocols"
	fieldRDPCookie               = "Cookie"
	fieldRDPSelectedProtocol     = "SelectedProtocol"
	fieldRDPClientName           = "ClientName"
	fieldRDPDomain               = "Domain"
	fieldRDPClientVersion        = "ClientVersion"
	fieldRDPDesktopWidth         = "DesktopWidth"
	fieldRDPDesktopHeight        = "DesktopHeight"
	fieldRDPColorDepth           = "ColorDepth"
	fieldRDPEncryptionLevel      = "EncryptionLevel"
	fieldRDPEncryptionLevelName  = "EncryptionLevelName"
	fieldRDPUsesNLA              = "UsesNLA"
	fieldRDPUsesTLS              = "UsesTLS"
	fieldRDPUsesCredSSP          = "UsesCredSSP"
	fieldRDPErrorDescription     = "ErrorDescription"
	fieldRDPIsRequest            = "IsRequest"
)

var fieldsRDP = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldRDPConnectionPhase,
	fieldRDPIsRequest,
	fieldRDPCookie,
	fieldRDPSelectedProtocol,
	fieldRDPClientName,
	fieldUsername,
	fieldRDPDomain,
	fieldRDPClientVersion,
	fieldRDPDesktopWidth,
	fieldRDPDesktopHeight,
	fieldRDPColorDepth,
	fieldRDPEncryptionLevel,
	fieldRDPEncryptionLevelName,
	fieldRDPUsesNLA,
	fieldRDPUsesTLS,
	fieldRDPUsesCredSSP,
	fieldRDPErrorDescription,
}

// CSVHeader returns the CSV header for the audit record.
func (r *RDP) CSVHeader() []string {
	return filter(fieldsRDP)
}

// CSVRecord returns the CSV record for the audit record.
func (r *RDP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(r.Timestamp),
		r.SrcIP,
		r.DstIP,
		formatInt32(r.SrcPort),
		formatInt32(r.DstPort),
		r.ConnectionPhase,
		strconv.FormatBool(r.IsRequest),
		r.Cookie,
		r.SelectedProtocol,
		r.ClientName,
		r.Username,
		r.Domain,
		r.ClientVersion,
		formatInt32(r.DesktopWidth),
		formatInt32(r.DesktopHeight),
		formatInt32(r.ColorDepth),
		formatInt32(r.EncryptionLevel),
		r.EncryptionLevelName,
		strconv.FormatBool(r.UsesNLA),
		strconv.FormatBool(r.UsesTLS),
		strconv.FormatBool(r.UsesCredSSP),
		r.ErrorDescription,
	})
}

// Time returns the timestamp associated with the audit record.
func (r *RDP) Time() int64 {
	return r.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (r *RDP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	r.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(r)
}

var rdpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_RDP.String()),
		Help: Type_NC_RDP.String() + " audit records",
	},
	fieldsRDP[1:],
)

// Inc increments the metrics for the audit record.
func (r *RDP) Inc() {
	rdpMetric.WithLabelValues(r.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (r *RDP) SetPacketContext(ctx *PacketContext) {
	r.SrcIP = ctx.SrcIP
	r.DstIP = ctx.DstIP
	r.SrcPort = ctx.SrcPort
	r.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (r *RDP) Src() string {
	return r.SrcIP
}

// Dst returns the destination address of the audit record.
func (r *RDP) Dst() string {
	return r.DstIP
}

var rdpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (r *RDP) Encode() []string {
	return filter([]string{
		rdpEncoder.Int64(fieldTimestamp, r.Timestamp),
		rdpEncoder.String(fieldSrcIP, r.SrcIP),
		rdpEncoder.String(fieldDstIP, r.DstIP),
		rdpEncoder.Int32(fieldSrcPort, r.SrcPort),
		rdpEncoder.Int32(fieldDstPort, r.DstPort),
		rdpEncoder.String(fieldRDPConnectionPhase, r.ConnectionPhase),
		rdpEncoder.Bool(r.IsRequest),
		rdpEncoder.String(fieldRDPCookie, r.Cookie),
		rdpEncoder.String(fieldRDPSelectedProtocol, r.SelectedProtocol),
		rdpEncoder.String(fieldRDPClientName, r.ClientName),
		rdpEncoder.String(fieldUsername, r.Username),
		rdpEncoder.String(fieldRDPDomain, r.Domain),
		rdpEncoder.String(fieldRDPClientVersion, r.ClientVersion),
		rdpEncoder.Int32(fieldRDPDesktopWidth, r.DesktopWidth),
		rdpEncoder.Int32(fieldRDPDesktopHeight, r.DesktopHeight),
		rdpEncoder.Int32(fieldRDPColorDepth, r.ColorDepth),
		rdpEncoder.Int32(fieldRDPEncryptionLevel, r.EncryptionLevel),
		rdpEncoder.String(fieldRDPEncryptionLevelName, r.EncryptionLevelName),
		rdpEncoder.Bool(r.UsesNLA),
		rdpEncoder.Bool(r.UsesTLS),
		rdpEncoder.Bool(r.UsesCredSSP),
		rdpEncoder.String(fieldRDPErrorDescription, r.ErrorDescription),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (r *RDP) Analyze() {}

// NetcapType returns the type of the current audit record
func (r *RDP) NetcapType() Type {
	return Type_NC_RDP
}

