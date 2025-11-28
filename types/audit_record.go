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

// Package types Contains the type definitions for the supported network protocols
package types

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"
)

var (
	selection []int

	// UTC allows to print timestamp in the utc format.
	UTC bool

	jsonMarshaler = &jsonpb.Marshaler{}
)

// AuditRecord is the interface for basic operations with NETCAP audit records
// this includes dumping as CSV or JSON or prometheus metrics
// and provides access to the timestamp of the audit record.
type AuditRecord interface {

	// CSVRecord returns CSV values
	CSVRecord() []string

	// CSVHeader returns CSV header fields
	CSVHeader() []string

	// Time used to retrieve the timestamp of the audit record for labeling
	Time() int64

	// Src returns the source of an audit record
	// for Layer 2 records this shall be the MAC address
	// for Layer 3+ records this shall be the IP address
	Src() string

	// Dst returns the source of an audit record
	// for Layer 2 records this shall be the MAC address
	// for Layer 3+ records this shall be the IP address
	Dst() string

	// Inc increments the metric for the audit record
	Inc()

	// JSON returns the audit record as JSON
	JSON() (string, error)

	// SetPacketContext can be implemented to set additional information for each audit record
	// important:
	//  - MUST be implemented on a pointer of an instance
	//  - the passed in packet context MUST be set on the Context field of the current audit record
	SetPacketContext(ctx *PacketContext)

	// Encode this audit record into numerical data for processing by machine learning algorithms,
	// and return the result as CSV.
	Encode() []string

	// Analyze will feed this audit record to an analyzer.
	// This could either be a static rule based analyzer, or one that is based on a more complex Anomaly Detector (statistical or ML).
	// TODO: define AnomalyDetector interface
	Analyze()

	// NetcapType returns the audit record type
	NetcapType() Type
}

// selectFields returns an array with the indices of the desired fields for selection.
func selectFields(all []string, selection string) (s []int) {
	var (
		fields = strings.Split(selection, ",")
		ok     bool
	)

	s = make([]int, len(fields))

	for i, val := range fields {
		for index, name := range all {
			if name == val {
				s[i] = index
				ok = true

				break
			}
		}

		if !ok {
			fmt.Println("invalid field: ", ansi.Red+val+ansi.Reset)
			fmt.Println("available fields: ", ansi.Yellow+strings.Join(all, ",")+ansi.Reset)
			os.Exit(1)
		}

		ok = false
	}

	return s
}

// Select takes a proto.Message and sets the selection on the package level.
func Select(msg proto.Message, vals string) {
	if vals != "" && vals != " " {
		if p, ok := msg.(AuditRecord); ok {
			selection = selectFields(p.CSVHeader(), vals)
		} else {
			fmt.Printf("type: %#v\n", msg)
			log.Fatal("type does not implement the types.AuditRecord interface")
		}
	}
}

// filter applies a selection if configured.
func filter(in []string) []string {
	if len(selection) == 0 {
		return in
	}

	r := make([]string, len(selection))
	for i, v := range selection {
		// Safety check: ensure index is within bounds
		if v >= 0 && v < len(in) {
			r[i] = in[v]
		} else {
			// Use empty string for out-of-bounds indices
			r[i] = ""
		}
	}

	return r
}
