/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package types

import (
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

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
