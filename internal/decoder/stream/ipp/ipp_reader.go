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
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
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

	r.decodeHTTPMessages(func(rec *types.IPP, d *core.StreamData) {
		rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort = r.conversation.Endpoints(d)
		rec.Flow = r.conversation.Ident
		rec.CommunityID = r.conversation.CommunityID
		rec.Timestamp = core.FragmentTime(d)

		err := Decoder.Writer.Write(rec)
		if err != nil {
			ippLog.Error("failed to write ipp record", zap.Error(err))
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

type countedIPPReader struct {
	source io.Reader
	read   int64
}

func (r *countedIPPReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.read += int64(n)
	return n, err
}

// TCP fragment boundaries are not HTTP message boundaries. Never join across loss.
func (r *ippReader) decodeHTTPMessages(emit func(*types.IPP, *core.StreamData)) {
	const maxHeader = 16 << 10
	const maxBody = 8 << 20
	for _, direction := range []reassembly.TCPFlowDirection{reassembly.TCPDirClientToServer, reassembly.TCPDirServerToClient} {
		var readers []io.Reader
		var fragments []*core.StreamData
		var ends []int64
		var total int64
		for _, data := range r.conversation.Data {
			fragment, ok := data.(*core.StreamData)
			if !ok {
				break
			}
			if fragment.Direction() != direction {
				continue
			}
			if fragment.HasGap(total > 0) || fragment.TCPObservation != "" {
				break
			}
			if len(fragment.Raw()) == 0 {
				continue
			}
			readers = append(readers, bytes.NewReader(fragment.Raw()))
			fragments = append(fragments, fragment)
			total += int64(len(fragment.Raw()))
			ends = append(ends, total)
		}
		counter := &countedIPPReader{source: io.MultiReader(readers...)}
		reader := bufio.NewReaderSize(counter, maxHeader)
		fragmentIndex := 0
		for {
			offset := counter.read - int64(reader.Buffered())
			prefix, err := reader.Peek(5)
			if err != nil {
				break
			}
			response := bytes.Equal(prefix, []byte("HTTP/"))
			// Bound header allocation before net/http parses it.
			complete := false
			for size := 4; size <= maxHeader; size++ {
				header, peekErr := reader.Peek(size)
				if peekErr != nil {
					break
				}
				if bytes.HasSuffix(header, httpHeaderEnd) {
					complete = true
					break
				}
			}
			if !complete {
				break
			}
			var body io.ReadCloser
			var contentType string
			var length int64
			if response {
				message, err := http.ReadResponse(reader, nil)
				if err != nil {
					break
				}
				body, contentType, length = message.Body, message.Header.Get("Content-Type"), message.ContentLength
			} else {
				message, err := http.ReadRequest(reader)
				if err != nil {
					break
				}
				body, contentType, length = message.Body, message.Header.Get("Content-Type"), message.ContentLength
			}
			if length > maxBody {
				break
			}
			data, err := io.ReadAll(io.LimitReader(body, maxBody+1))
			if err != nil || len(data) > maxBody {
				break
			}
			if err := body.Close(); err != nil {
				break
			}
			typ, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
			if err != nil || typ != "application/ipp" {
				continue
			}
			record := r.parseIPPBody(data)
			if record == nil {
				continue
			}
			if response {
				record.OperationName = statusNames[int(record.OperationOrStatus)]
				if record.OperationName == "" {
					record.OperationName = "Unknown"
				}
			}
			for fragmentIndex < len(ends)-1 && offset >= ends[fragmentIndex] {
				fragmentIndex++
			}
			if fragmentIndex < len(fragments) {
				emit(record, fragments[fragmentIndex])
			}
		}
	}
}

func (r *ippReader) parseIPPMessage(data []byte) *types.IPP {
	// Find the IPP body after HTTP headers
	ippBody := data
	if idx := bytes.Index(data, httpHeaderEnd); idx >= 0 {
		ippBody = data[idx+4:]
	}
	return r.parseIPPBody(ippBody)
}

func (r *ippReader) parseIPPBody(ippBody []byte) *types.IPP {

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
