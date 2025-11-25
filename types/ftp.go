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
	fieldArgument           = "Argument"
	fieldResponseMessage    = "ResponseMessage"
	fieldTransferMode       = "TransferMode"
	fieldDataConnectionMode = "DataConnectionMode"
	fieldDataIP             = "DataIP"
	fieldDataPort           = "DataPort"
	fieldIsControl          = "IsControl"
	fieldFilename           = "Filename"
	fieldUsername           = "Username"
	fieldFileSize           = "FileSize"
)

var fieldsFTP = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldIsResponse,
	fieldCommand,
	fieldArgument,
	fieldResponseCode,
	fieldResponseMessage,
	fieldFilename,
	fieldTransferMode,
	fieldDataConnectionMode,
	fieldDataIP,
	fieldDataPort,
	fieldUsername,
	fieldIsControl,
	fieldFileSize,
}

// CSVHeader returns the CSV header for the audit record.
func (f *FTP) CSVHeader() []string {
	return filter(fieldsFTP)
}

// CSVRecord returns the CSV record for the audit record.
func (f *FTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(f.Timestamp),
		f.SrcIP,
		f.DstIP,
		formatInt32(f.SrcPort),
		formatInt32(f.DstPort),
		strconv.FormatBool(f.IsResponse),
		f.Command,
		f.Argument,
		formatInt32(f.ResponseCode),
		f.ResponseMessage,
		f.Filename,
		f.TransferMode,
		f.DataConnectionMode,
		f.DataIP,
		formatInt32(f.DataPort),
		f.Username,
		strconv.FormatBool(f.IsControl),
		formatInt64(f.FileSize),
	})
}

// Time returns the timestamp associated with the audit record.
func (f *FTP) Time() int64 {
	return f.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (f *FTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	f.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(f)
}

var ftpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_FTP.String()),
		Help: Type_NC_FTP.String() + " audit records",
	},
	fieldsFTP[1:],
)

// Inc increments the metrics for the audit record.
func (f *FTP) Inc() {
	ftpMetric.WithLabelValues(f.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (f *FTP) SetPacketContext(ctx *PacketContext) {
	f.SrcIP = ctx.SrcIP
	f.DstIP = ctx.DstIP
	f.SrcPort = ctx.SrcPort
	f.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (f *FTP) Src() string {
	return f.SrcIP
}

// Dst returns the destination address of the audit record.
func (f *FTP) Dst() string {
	return f.DstIP
}

var ftpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (f *FTP) Encode() []string {
	return filter([]string{
		ftpEncoder.Int64(fieldTimestamp, f.Timestamp),
		ftpEncoder.String(fieldSrcIP, f.SrcIP),
		ftpEncoder.String(fieldDstIP, f.DstIP),
		ftpEncoder.Int32(fieldSrcPort, f.SrcPort),
		ftpEncoder.Int32(fieldDstPort, f.DstPort),
		ftpEncoder.Bool(f.IsResponse),
		ftpEncoder.String(fieldCommand, f.Command),
		ftpEncoder.String(fieldArgument, f.Argument),
		ftpEncoder.Int32(fieldResponseCode, f.ResponseCode),
		ftpEncoder.String(fieldResponseMessage, f.ResponseMessage),
		ftpEncoder.String(fieldFilename, f.Filename),
		ftpEncoder.String(fieldTransferMode, f.TransferMode),
		ftpEncoder.String(fieldDataConnectionMode, f.DataConnectionMode),
		ftpEncoder.String(fieldDataIP, f.DataIP),
		ftpEncoder.Int32(fieldDataPort, f.DataPort),
		ftpEncoder.String(fieldUsername, f.Username),
		ftpEncoder.Bool(f.IsControl),
		ftpEncoder.Int64(fieldFileSize, f.FileSize),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (f *FTP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (f *FTP) NetcapType() Type {
	return Type_NC_FTP
}

