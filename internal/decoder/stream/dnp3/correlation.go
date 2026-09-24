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

package dnp3

import (
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const (
	// An outstation drops an unoperated Select after its own timeout, typically
	// a few seconds. Ten is generous, so an Operate past it is reported rather
	// than credited to a Select the device had already discarded.
	selectTimeout = int64(10 * time.Second)

	// Responses are matched within this window. The application sequence number
	// is four bits, so a wider window pairs on a wrapped number.
	responseTimeout = int64(30 * time.Second)
)

const (
	sboMatched          = "matched"
	sboNoSelect         = "operate_without_select"
	sboNeverOperated    = "select_never_operated"
	sboObjectMismatch   = "sbo_object_mismatch"
	sboSequenceMismatch = "sbo_sequence_mismatch"
	sboExpired          = "select_expired"
	sboPending          = "select_pending"

	corrMatched       = "matched"
	corrUnmatched     = "unmatched"
	corrAmbiguous     = "ambiguous"
	corrNotApplicable = "not_applicable"
)

// correlate pairs Selects with Operates within the master's own direction, and
// requests with responses across the two.
//
// Both halves are needed for different questions: SBO says whether a control
// followed the interlock the site's engineering standard requires, and the
// response says whether the outstation accepted it. A matched Operate is an
// attempt; only the reply's status code is evidence of effect.
func correlate(client, server []*types.DNP3) {
	correlateSBO(client)
	correlateResponses(client, server)
}

type sboKey struct {
	source, destination int32
}

type pendingSelect struct {
	record    *types.DNP3
	timestamp int64
	appSeq    int32
	objects   string
}

// correlateSBO walks one direction in capture order. Select and Operate both
// travel master to outstation, so ordering within the direction is enough and
// the two lists never need interleaving.
func correlateSBO(records []*types.DNP3) {
	pending := make(map[sboKey]pendingSelect)

	for _, r := range records {
		if r.ParseStatus != statusValid {
			continue
		}

		key := sboKey{source: r.Source, destination: r.Destination}

		switch r.FunctionCode {
		case FuncSelect:
			if prior, ok := pending[key]; ok {
				// Replaced before it was operated.
				prior.record.SBOStatus = sboNeverOperated
			}

			r.SBOStatus = sboPending
			pending[key] = pendingSelect{
				record: r, timestamp: r.Timestamp,
				appSeq: r.ApplicationSeq, objects: controlFingerprint(r),
			}

		case FuncOperate:
			prior, ok := pending[key]
			if !ok {
				// A control with no interlock in front of it.
				r.SBOStatus = sboNoSelect

				continue
			}

			delete(pending, key)

			r.SelectTimestamp = prior.timestamp
			r.OperateLatency = r.Timestamp - prior.timestamp

			switch {
			case r.Timestamp < prior.timestamp || r.OperateLatency > selectTimeout:
				r.SBOStatus, prior.record.SBOStatus = sboExpired, sboNeverOperated
			case controlFingerprint(r) != prior.objects:
				// IEEE 1815 requires the Operate to name what the Select armed.
				r.SBOStatus, prior.record.SBOStatus = sboObjectMismatch, sboNeverOperated
			case r.ApplicationSeq != (prior.appSeq+1)&0x0F:
				r.SBOStatus, prior.record.SBOStatus = sboSequenceMismatch, sboMatched
			default:
				r.SBOStatus, prior.record.SBOStatus = sboMatched, sboMatched
			}
		}
	}

	for _, prior := range pending {
		prior.record.SBOStatus = sboNeverOperated
	}
}

// controlFingerprint summarizes the objects a Select armed or an Operate names,
// so the two can be compared without retaining the frames.
func controlFingerprint(r *types.DNP3) string {
	var b strings.Builder

	for _, o := range r.Objects {
		b.WriteString(strconv.Itoa(int(o.ObjectGroup)))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(int(o.Variation)))

		for _, c := range o.ControlBlocks {
			b.WriteByte('#')
			b.WriteString(strconv.Itoa(int(c.Index)))
			b.WriteByte('/')
			b.WriteString(strconv.Itoa(int(c.ControlCode)))
		}

		b.WriteByte(';')
	}

	return b.String()
}

type responseKey struct {
	source, destination, appSeq int32
}

// correlateResponses pairs each response with the request it answers.
//
// The application sequence number is four bits, so it repeats every sixteen
// requests. A pairing is therefore only claimed when the link addresses are
// reversed, the response is not earlier than the request, and no second request
// is outstanding on the same number; otherwise the result is ambiguous.
func correlateResponses(client, server []*types.DNP3) {
	if len(client) == 0 || len(server) == 0 {
		return
	}

	type outstanding struct {
		record    *types.DNP3
		timestamp int64
		ambiguous bool
	}

	pending := make(map[responseKey]*outstanding)

	for _, r := range client {
		if r.ParseStatus != statusValid || r.FunctionCode == FuncConfirm {
			continue
		}

		key := responseKey{source: r.Source, destination: r.Destination, appSeq: r.ApplicationSeq}

		// The ambiguity has to travel to the replacement entry: a response
		// arriving now could answer either request, and the older one is no
		// longer reachable to carry the flag.
		_, reused := pending[key]
		pending[key] = &outstanding{record: r, timestamp: r.Timestamp, ambiguous: reused}
	}

	for _, r := range server {
		if r.ParseStatus != statusValid {
			continue
		}

		if r.FunctionCode != FuncResponse && r.FunctionCode != FuncUnsolicitedResponse {
			continue
		}

		if r.FunctionCode == FuncUnsolicitedResponse || r.Unsolicited {
			// Outstation-initiated: there is no request to pair with.
			r.CorrelationStatus = corrNotApplicable

			continue
		}

		r.CorrelationStatus = corrUnmatched

		// A response travels outstation to master, so its link addresses are
		// the request's reversed.
		key := responseKey{source: r.Destination, destination: r.Source, appSeq: r.ApplicationSeq}

		prior, ok := pending[key]
		if !ok {
			continue
		}

		if prior.ambiguous {
			r.CorrelationStatus = corrAmbiguous

			continue
		}

		if r.Timestamp < prior.timestamp || r.Timestamp-prior.timestamp > responseTimeout {
			continue
		}

		delete(pending, key)

		r.CorrelationStatus = corrMatched
		r.RequestTimestamp = prior.timestamp
		r.ResponseLatency = r.Timestamp - prior.timestamp
	}
}
