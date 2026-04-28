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
	fieldC = "C"
	fieldT = "T"
)

var fieldsLLMNR = []string{
	fieldTimestamp,
	fieldID,           // int32
	fieldQR,           // bool
	fieldOpCode,       // int32
	fieldC,            // bool
	fieldTC,           // bool
	fieldT,            // bool
	fieldResponseCode, // int32
	fieldQDCount,      // int32
	fieldANCount,      // int32
	fieldNSCount,      // int32
	fieldARCount,      // int32
	fieldQuestions,    // []*DNSQuestion
	fieldAnswers,      // []*DNSResourceRecord
	fieldAuthorities,  // []*DNSResourceRecord
	fieldAdditionals,  // []*DNSResourceRecord
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *LLMNR) CSVHeader() []string {
	return filter(fieldsLLMNR)
}

// CSVRecord returns the CSV record for the audit record.
func (a *LLMNR) CSVRecord() []string {
	var (
		questions   = make([]string, 0, len(a.Questions))
		answers     = make([]string, 0, len(a.Answers))
		authorities = make([]string, 0, len(a.Authorities))
		additionals = make([]string, 0, len(a.Additionals))
	)
	for _, q := range a.Questions {
		questions = append(questions, q.toString())
	}
	for _, q := range a.Answers {
		answers = append(answers, q.toString())
	}
	for _, q := range a.Authorities {
		authorities = append(authorities, q.toString())
	}
	for _, q := range a.Additionals {
		additionals = append(additionals, q.toString())
	}

	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.ID),             // int32
		strconv.FormatBool(a.QR),      // bool
		formatInt32(a.OpCode),         // int32
		strconv.FormatBool(a.C),       // bool
		strconv.FormatBool(a.TC),      // bool
		strconv.FormatBool(a.T),       // bool
		formatInt32(a.ResponseCode),   // int32
		formatInt32(a.QDCount),        // int32
		formatInt32(a.ANCount),        // int32
		formatInt32(a.NSCount),        // int32
		formatInt32(a.ARCount),        // int32
		strings.Join(questions, ""),   // []*DNSQuestion
		strings.Join(answers, ""),     // []*DNSResourceRecord
		strings.Join(authorities, ""), // []*DNSResourceRecord
		strings.Join(additionals, ""), // []*DNSResourceRecord
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *LLMNR) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *LLMNR) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var llmnrMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LLMNR.String()),
		Help: Type_NC_LLMNR.String() + " audit records",
	},
	fieldsLLMNR[1:],
)

// Inc increments the metrics for the audit record.
func (a *LLMNR) Inc() {
	llmnrMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *LLMNR) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *LLMNR) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *LLMNR) Dst() string {
	return a.DstIP
}

var llmnrEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *LLMNR) Encode() []string {
	var (
		questions   = make([]string, 0, len(a.Questions))
		answers     = make([]string, 0, len(a.Answers))
		authorities = make([]string, 0, len(a.Authorities))
		additionals = make([]string, 0, len(a.Additionals))
	)
	for _, q := range a.Questions {
		questions = append(questions, q.toString())
	}
	for _, q := range a.Answers {
		answers = append(answers, q.toString())
	}
	for _, q := range a.Authorities {
		authorities = append(authorities, q.toString())
	}
	for _, q := range a.Additionals {
		additionals = append(additionals, q.toString())
	}

	return filter([]string{
		llmnrEncoder.Int64(fieldTimestamp, a.Timestamp),
		llmnrEncoder.Int32(fieldID, a.ID),                                    // int32
		llmnrEncoder.Bool(a.QR),                                              // bool
		llmnrEncoder.Int32(fieldOpCode, a.OpCode),                            // int32
		llmnrEncoder.Bool(a.C),                                               // bool
		llmnrEncoder.Bool(a.TC),                                              // bool
		llmnrEncoder.Bool(a.T),                                               // bool
		llmnrEncoder.Int32(fieldResponseCode, a.ResponseCode),                // int32
		llmnrEncoder.Int32(fieldQDCount, a.QDCount),                          // int32
		llmnrEncoder.Int32(fieldANCount, a.ANCount),                          // int32
		llmnrEncoder.Int32(fieldNSCount, a.NSCount),                          // int32
		llmnrEncoder.Int32(fieldARCount, a.ARCount),                          // int32
		llmnrEncoder.String(fieldQuestions, strings.Join(questions, "")),     // []*DNSQuestion
		llmnrEncoder.String(fieldAnswers, strings.Join(answers, "")),         // []*DNSResourceRecord
		llmnrEncoder.String(fieldAuthorities, strings.Join(authorities, "")), // []*DNSResourceRecord
		llmnrEncoder.String(fieldAdditionals, strings.Join(additionals, "")), // []*DNSResourceRecord
		llmnrEncoder.String(fieldSrcIP, a.SrcIP),
		llmnrEncoder.String(fieldDstIP, a.DstIP),
		llmnrEncoder.Int32(fieldSrcPort, a.SrcPort),
		llmnrEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *LLMNR) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *LLMNR) NetcapType() Type {
	return Type_NC_LLMNR
}
