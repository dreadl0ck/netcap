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

package ipp

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

type ippReader struct {
	conversation *core.ConversationInfo
}

// New returns a new IPP reader.
func (r *ippReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &ippReader{
		conversation: conversation,
	}
}

// operationNames maps IPP operation IDs to human-readable names.
var operationNames = map[int]string{
	0x0002: "Print-Job",
	0x0003: "Print-URI",
	0x0004: "Validate-Job",
	0x0005: "Create-Job",
	0x0006: "Send-Document",
	0x0007: "Send-URI",
	0x0008: "Cancel-Job",
	0x0009: "Get-Job-Attributes",
	0x000A: "Get-Jobs",
	0x000B: "Get-Printer-Attributes",
	0x000C: "Hold-Job",
	0x000D: "Release-Job",
	0x000E: "Restart-Job",
	0x0010: "Pause-Printer",
	0x0011: "Resume-Printer",
	0x0012: "Purge-Jobs",
}

// statusNames maps common IPP status codes to human-readable names.
var statusNames = map[int]string{
	0x0000: "successful-ok",
	0x0001: "successful-ok-ignored-or-substituted-attributes",
	0x0002: "successful-ok-conflicting-attributes",
	0x0400: "client-error-bad-request",
	0x0401: "client-error-forbidden",
	0x0402: "client-error-not-authenticated",
	0x0403: "client-error-not-authorized",
	0x0404: "client-error-not-possible",
	0x0405: "client-error-timeout",
	0x0406: "client-error-not-found",
	0x0500: "server-error-internal-error",
	0x0501: "server-error-operation-not-supported",
	0x0502: "server-error-service-unavailable",
}

// IPP attribute group tags
const (
	tagOperationAttributes = 0x01
	tagJobAttributes       = 0x02
	tagEndOfAttributes     = 0x03
	tagPrinterAttributes   = 0x04
)

var httpHeaderEnd = []byte("\r\n\r\n")

// Decode parses IPP messages from the stream.
func (r *ippReader) Decode() {
	if Decoder.Writer == nil {
		ippLog.Error("IPP Decoder.Writer is nil")
		return
	}

	for _, d := range r.conversation.Data {
		raw := d.Raw()
		if len(raw) < 8 {
			continue
		}

		rec := r.parseIPPMessage(raw)
		if rec == nil {
			continue
		}

		rec.SrcIP = r.conversation.ClientIP
		rec.DstIP = r.conversation.ServerIP
		rec.SrcPort = int32(r.conversation.ClientPort)
		rec.DstPort = int32(r.conversation.ServerPort)
		rec.Flow = r.conversation.Ident
		rec.Timestamp = r.conversation.FirstClientPacket.UnixNano()

		err := Decoder.Writer.Write(rec)
		if err != nil {
			ippLog.Error("failed to write ipp record", zap.Error(err))
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	}
}

func (r *ippReader) parseIPPMessage(data []byte) *types.IPP {
	// Find the IPP body after HTTP headers
	ippBody := data
	if idx := bytes.Index(data, httpHeaderEnd); idx >= 0 {
		ippBody = data[idx+4:]
	}

	// IPP body: version-major(1) + version-minor(1) + operation-id/status-code(2) + request-id(4)
	if len(ippBody) < 8 {
		return nil
	}

	versionMajor := int32(ippBody[0])
	versionMinor := int32(ippBody[1])

	// Validate version: major should be 1 or 2
	if versionMajor < 1 || versionMajor > 2 {
		return nil
	}

	operationOrStatus := int32(binary.BigEndian.Uint16(ippBody[2:4]))
	requestID := int32(binary.BigEndian.Uint32(ippBody[4:8]))

	// Determine operation/status name
	opName := operationNames[int(operationOrStatus)]
	if opName == "" {
		opName = statusNames[int(operationOrStatus)]
	}
	if opName == "" {
		opName = "Unknown"
	}

	rec := &types.IPP{
		VersionMajor:      versionMajor,
		VersionMinor:      versionMinor,
		OperationOrStatus: operationOrStatus,
		OperationName:     opName,
		RequestID:         requestID,
	}

	// Parse attributes
	r.parseAttributes(ippBody[8:], rec)

	return rec
}

func (r *ippReader) parseAttributes(data []byte, rec *types.IPP) {
	offset := 0

	for offset < len(data) {
		if data[offset] == tagEndOfAttributes {
			break
		}

		// Check for attribute group tag (delimiter tags are 0x00-0x0F)
		if data[offset] <= 0x0F {
			// This is a delimiter tag (attribute group tag), skip it
			offset++
			continue
		}

		// Parse attribute: value-tag(1) + name-length(2) + name + value-length(2) + value
		if offset+5 > len(data) {
			break
		}

		valueTag := int32(data[offset])
		offset++

		nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+nameLen > len(data) {
			break
		}

		name := string(data[offset : offset+nameLen])
		offset += nameLen

		if offset+2 > len(data) {
			break
		}

		valueLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+valueLen > len(data) {
			break
		}

		value := string(data[offset : offset+valueLen])
		offset += valueLen

		// Extract well-known attributes
		switch name {
		case "printer-uri":
			rec.PrinterURI = value
		case "job-name":
			rec.JobName = value
		}

		// Only store non-empty named attributes
		if nameLen > 0 {
			rec.Attributes = append(rec.Attributes, &types.IPPAttribute{
				Tag:   valueTag,
				Name:  name,
				Value: value,
			})
		}
	}
}
