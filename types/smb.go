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

// SMB-specific field constants (prefixed to avoid conflicts with other types)
const (
	fieldSMBCommandName        = "CommandName"
	fieldSMBStatusName         = "StatusName"
	fieldSMBFlags2             = "Flags2"
	fieldSMBIsResponse         = "IsResponse"
	fieldSMBDomain             = "Domain"
	fieldSMBWorkstation        = "Workstation"
	fieldSMBNTLMVersion        = "NTLMVersion"
	fieldSMBAuthStatus         = "AuthStatus"
	fieldSMBShareName          = "ShareName"
	fieldSMBShareType          = "ShareType"
	fieldSMBFileID             = "FileID"
	fieldSMBAction             = "Action"
	fieldSMBBytesTransferred   = "BytesTransferred"
	fieldSMBAccessMask         = "AccessMask"
	fieldSMBAccessMaskStr      = "AccessMaskStr"
	fieldSMBCreateDisposition  = "CreateDisposition"
	fieldSMBCreateDispStr      = "CreateDispositionStr"
	fieldSMBFileAttributes     = "FileAttributes"
	fieldSMBIsDirectory        = "IsDirectory"
	fieldSMBTreeID             = "TreeID"
	fieldSMBMessageID          = "MessageID"
	fieldSMBIsSigned           = "IsSigned"
	fieldSMBDialectRevision    = "DialectRevision"
	fieldSMBClientGUID         = "ClientGUID"
	fieldSMBServerGUID         = "ServerGUID"
	fieldSMBUsername           = "Username"
	fieldSMBFilename           = "Filename"
	fieldSMBFileSize           = "FileSize"
	fieldSMBOperationType      = "OperationType"
	fieldSMBSecurityContext    = "SecurityContext"
	fieldSMBIsPotentialThreat  = "IsPotentialThreat"
	fieldSMBThreatIndicator    = "ThreatIndicator"
)

var fieldsSMB = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldVersion,
	fieldCommand,
	fieldSMBCommandName,
	fieldStatus,
	fieldSMBStatusName,
	fieldFlags,
	fieldSMBFlags2,
	fieldSMBIsResponse,
	fieldSMBUsername,
	fieldSMBDomain,
	fieldSMBWorkstation,
	fieldSMBNTLMVersion,
	fieldSMBAuthStatus,
	fieldSMBShareName,
	fieldSMBShareType,
	fieldSMBFilename,
	fieldSMBFileID,
	fieldSMBAction,
	fieldSMBBytesTransferred,
	fieldSMBFileSize,
	fieldOffset,
	fieldSMBAccessMask,
	fieldSMBAccessMaskStr,
	fieldSMBCreateDisposition,
	fieldSMBCreateDispStr,
	fieldSMBFileAttributes,
	fieldSMBIsDirectory,
	fieldSessionID,
	fieldSMBTreeID,
	fieldSMBMessageID,
	fieldIsEncrypted,
	fieldSMBIsSigned,
	fieldSMBDialectRevision,
	fieldSMBClientGUID,
	fieldSMBServerGUID,
	fieldCapabilities,
	fieldSMBOperationType,
	fieldSMBSecurityContext,
	fieldSMBIsPotentialThreat,
	fieldSMBThreatIndicator,
}

// CSVHeader returns the CSV header for the audit record.
func (s *SMB) CSVHeader() []string {
	return filter(fieldsSMB)
}

// CSVRecord returns the CSV record for the audit record.
func (s *SMB) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		s.SrcIP,
		s.DstIP,
		formatInt32(s.SrcPort),
		formatInt32(s.DstPort),
		formatInt32(s.Version),
		formatInt32(s.Command),
		s.CommandName,
		strconv.FormatUint(uint64(s.Status), 10),
		s.StatusName,
		strconv.FormatUint(uint64(s.Flags), 10),
		strconv.FormatUint(uint64(s.Flags2), 10),
		strconv.FormatBool(s.IsResponse),
		s.Username,
		s.Domain,
		s.Workstation,
		s.NTLMVersion,
		s.AuthStatus,
		s.ShareName,
		s.ShareType,
		s.Filename,
		strconv.FormatUint(s.FileID, 10),
		s.Action,
		formatInt64(s.BytesTransferred),
		formatInt64(s.FileSize),
		formatInt64(s.Offset),
		strconv.FormatUint(uint64(s.AccessMask), 10),
		s.AccessMaskStr,
		strconv.FormatUint(uint64(s.CreateDisposition), 10),
		s.CreateDispositionStr,
		strconv.FormatUint(uint64(s.FileAttributes), 10),
		strconv.FormatBool(s.IsDirectory),
		strconv.FormatUint(s.SessionID, 10),
		strconv.FormatUint(uint64(s.TreeID), 10),
		strconv.FormatUint(s.MessageID, 10),
		strconv.FormatBool(s.IsEncrypted),
		strconv.FormatBool(s.IsSigned),
		s.DialectRevision,
		s.ClientGUID,
		s.ServerGUID,
		join(s.Capabilities...),
		s.OperationType,
		s.SecurityContext,
		strconv.FormatBool(s.IsPotentialThreat),
		s.ThreatIndicator,
	})
}

// Time returns the timestamp associated with the audit record.
func (s *SMB) Time() int64 {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (s *SMB) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	s.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(s)
}

var smbMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SMB.String()),
		Help: Type_NC_SMB.String() + " audit records",
	},
	fieldsSMB[1:],
)

// Inc increments the metrics for the audit record.
func (s *SMB) Inc() {
	smbMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *SMB) SetPacketContext(ctx *PacketContext) {
	s.SrcIP = ctx.SrcIP
	s.DstIP = ctx.DstIP
	s.SrcPort = ctx.SrcPort
	s.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (s *SMB) Src() string {
	return s.SrcIP
}

// Dst returns the destination address of the audit record.
func (s *SMB) Dst() string {
	return s.DstIP
}

var smbEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (s *SMB) Encode() []string {
	return filter([]string{
		smbEncoder.Int64(fieldTimestamp, s.Timestamp),
		smbEncoder.String(fieldSrcIP, s.SrcIP),
		smbEncoder.String(fieldDstIP, s.DstIP),
		smbEncoder.Int32(fieldSrcPort, s.SrcPort),
		smbEncoder.Int32(fieldDstPort, s.DstPort),
		smbEncoder.Int32(fieldVersion, s.Version),
		smbEncoder.Int32(fieldCommand, s.Command),
		smbEncoder.String(fieldSMBCommandName, s.CommandName),
		smbEncoder.Uint32(fieldStatus, s.Status),
		smbEncoder.String(fieldSMBStatusName, s.StatusName),
		smbEncoder.Uint32(fieldFlags, s.Flags),
		smbEncoder.Uint32(fieldSMBFlags2, s.Flags2),
		smbEncoder.Bool(s.IsResponse),
		smbEncoder.String(fieldSMBUsername, s.Username),
		smbEncoder.String(fieldSMBDomain, s.Domain),
		smbEncoder.String(fieldSMBWorkstation, s.Workstation),
		smbEncoder.String(fieldSMBNTLMVersion, s.NTLMVersion),
		smbEncoder.String(fieldSMBAuthStatus, s.AuthStatus),
		smbEncoder.String(fieldSMBShareName, s.ShareName),
		smbEncoder.String(fieldSMBShareType, s.ShareType),
		smbEncoder.String(fieldSMBFilename, s.Filename),
		smbEncoder.Uint64(fieldSMBFileID, s.FileID),
		smbEncoder.String(fieldSMBAction, s.Action),
		smbEncoder.Int64(fieldSMBBytesTransferred, s.BytesTransferred),
		smbEncoder.Int64(fieldSMBFileSize, s.FileSize),
		smbEncoder.Int64(fieldOffset, s.Offset),
		smbEncoder.Uint32(fieldSMBAccessMask, s.AccessMask),
		smbEncoder.String(fieldSMBAccessMaskStr, s.AccessMaskStr),
		smbEncoder.Uint32(fieldSMBCreateDisposition, s.CreateDisposition),
		smbEncoder.String(fieldSMBCreateDispStr, s.CreateDispositionStr),
		smbEncoder.Uint32(fieldSMBFileAttributes, s.FileAttributes),
		smbEncoder.Bool(s.IsDirectory),
		smbEncoder.Uint64(fieldSessionID, s.SessionID),
		smbEncoder.Uint32(fieldSMBTreeID, s.TreeID),
		smbEncoder.Uint64(fieldSMBMessageID, s.MessageID),
		smbEncoder.Bool(s.IsEncrypted),
		smbEncoder.Bool(s.IsSigned),
		smbEncoder.String(fieldSMBDialectRevision, s.DialectRevision),
		smbEncoder.String(fieldSMBClientGUID, s.ClientGUID),
		smbEncoder.String(fieldSMBServerGUID, s.ServerGUID),
		smbEncoder.String(fieldCapabilities, join(s.Capabilities...)),
		smbEncoder.String(fieldSMBOperationType, s.OperationType),
		smbEncoder.String(fieldSMBSecurityContext, s.SecurityContext),
		smbEncoder.Bool(s.IsPotentialThreat),
		smbEncoder.String(fieldSMBThreatIndicator, s.ThreatIndicator),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *SMB) Analyze() {
}

// NetcapType returns the type of the current audit record
func (s *SMB) NetcapType() Type {
	return Type_NC_SMB
}
