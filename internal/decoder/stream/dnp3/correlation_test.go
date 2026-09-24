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
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// crob builds a record carrying one control block, which is what the SBO
// fingerprint compares.
func control(fc, seq int32, ts, index int64, code int32) *types.DNP3 {
	return &types.DNP3{
		ParseStatus: statusValid, FunctionCode: fc, ApplicationSeq: seq, Timestamp: ts,
		Source: 4, Destination: 3,
		Objects: []*types.DNP3Object{{
			ObjectGroup: groupCROB, Variation: 1,
			ControlBlocks: []*types.DNP3CROB{{Index: index, ControlCode: code}},
		}},
	}
}

func TestSBOMatched(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)
	op := control(FuncOperate, 2, 2000, 7, 0x41)

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboMatched || sel.SBOStatus != sboMatched {
		t.Fatalf("select=%q operate=%q, want both matched", sel.SBOStatus, op.SBOStatus)
	}
	if op.SelectTimestamp != 1000 || op.OperateLatency != 1000 {
		t.Errorf("SelectTimestamp=%d OperateLatency=%d", op.SelectTimestamp, op.OperateLatency)
	}
}

// The control that needs no interlock in front of it. This is the state the
// hunt is looking for where a site's standard requires Select-Before-Operate.
func TestOperateWithoutSelect(t *testing.T) {
	op := control(FuncOperate, 2, 2000, 7, 0x41)

	correlateSBO([]*types.DNP3{op})

	if op.SBOStatus != sboNoSelect {
		t.Fatalf("SBOStatus = %q, want %q", op.SBOStatus, sboNoSelect)
	}
}

func TestSelectNeverOperated(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)

	correlateSBO([]*types.DNP3{sel})

	if sel.SBOStatus != sboNeverOperated {
		t.Fatalf("SBOStatus = %q, want %q", sel.SBOStatus, sboNeverOperated)
	}
}

// An Operate naming a different point than the Select armed is not the pair it
// appears to be.
func TestSBOObjectMismatch(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)
	op := control(FuncOperate, 2, 2000, 9, 0x41)

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboObjectMismatch {
		t.Errorf("operate = %q, want %q", op.SBOStatus, sboObjectMismatch)
	}
	if sel.SBOStatus != sboNeverOperated {
		t.Errorf("select = %q, want %q", sel.SBOStatus, sboNeverOperated)
	}
}

// Same point, but the Operate asks for a trip where the Select armed a close.
func TestSBOControlCodeMismatch(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)
	op := control(FuncOperate, 2, 2000, 7, 0x81)

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboObjectMismatch {
		t.Errorf("operate = %q, want %q", op.SBOStatus, sboObjectMismatch)
	}
}

func TestSBOSequenceMismatch(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)
	op := control(FuncOperate, 5, 2000, 7, 0x41)

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboSequenceMismatch {
		t.Errorf("operate = %q, want %q", op.SBOStatus, sboSequenceMismatch)
	}
}

// The sequence number is four bits, so 15 is followed by 0.
func TestSBOSequenceWraps(t *testing.T) {
	sel := control(FuncSelect, 15, 1000, 7, 0x41)
	op := control(FuncOperate, 0, 2000, 7, 0x41)

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboMatched {
		t.Errorf("operate = %q, want %q", op.SBOStatus, sboMatched)
	}
}

// An outstation discards an unoperated Select after its own timeout, so an
// Operate past it is not credited to a Select the device had already dropped.
func TestSBOSelectExpires(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)
	op := control(FuncOperate, 2, 1000+int64(11*time.Second), 7, 0x41)

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboExpired {
		t.Errorf("operate = %q, want %q", op.SBOStatus, sboExpired)
	}
	if sel.SBOStatus != sboNeverOperated {
		t.Errorf("select = %q, want %q", sel.SBOStatus, sboNeverOperated)
	}
}

// Selects are tracked per outstation, so one outstation's Operate cannot be
// credited to another's Select.
func TestSBOScopedPerOutstation(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)
	op := control(FuncOperate, 2, 2000, 7, 0x41)
	op.Destination = 99

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboNoSelect {
		t.Errorf("operate = %q, want %q", op.SBOStatus, sboNoSelect)
	}
	if sel.SBOStatus != sboNeverOperated {
		t.Errorf("select = %q, want %q", sel.SBOStatus, sboNeverOperated)
	}
}

// A malformed frame carries no decoded objects, so it must not arm or consume
// an interlock.
func TestSBOIgnoresMalformed(t *testing.T) {
	sel := control(FuncSelect, 1, 1000, 7, 0x41)
	sel.ParseStatus = statusMalformed
	op := control(FuncOperate, 2, 2000, 7, 0x41)

	correlateSBO([]*types.DNP3{sel, op})

	if op.SBOStatus != sboNoSelect {
		t.Errorf("operate = %q, want %q", op.SBOStatus, sboNoSelect)
	}
	if sel.SBOStatus != "" {
		t.Errorf("malformed select got SBOStatus %q", sel.SBOStatus)
	}
}

func response(seq int32, ts int64, unsolicited bool) *types.DNP3 {
	fc := int32(FuncResponse)
	if unsolicited {
		fc = FuncUnsolicitedResponse
	}

	return &types.DNP3{
		ParseStatus: statusValid, FunctionCode: fc, ApplicationSeq: seq, Timestamp: ts,
		Source: 3, Destination: 4, Unsolicited: unsolicited,
	}
}

func TestResponseMatched(t *testing.T) {
	req := control(FuncOperate, 2, 1000, 7, 0x41)
	resp := response(2, 1500, false)

	correlateResponses([]*types.DNP3{req}, []*types.DNP3{resp})

	if resp.CorrelationStatus != corrMatched {
		t.Fatalf("CorrelationStatus = %q, want %q", resp.CorrelationStatus, corrMatched)
	}
	if resp.RequestTimestamp != 1000 || resp.ResponseLatency != 500 {
		t.Errorf("RequestTimestamp=%d ResponseLatency=%d", resp.RequestTimestamp, resp.ResponseLatency)
	}
}

func TestResponseUnmatchedOnDifferentSequence(t *testing.T) {
	req := control(FuncOperate, 2, 1000, 7, 0x41)
	resp := response(9, 1500, false)

	correlateResponses([]*types.DNP3{req}, []*types.DNP3{resp})

	if resp.CorrelationStatus != corrUnmatched {
		t.Errorf("CorrelationStatus = %q, want %q", resp.CorrelationStatus, corrUnmatched)
	}
}

// The sequence number repeats every sixteen requests, so two outstanding on the
// same number cannot be told apart.
func TestResponseAmbiguousOnReusedSequence(t *testing.T) {
	first := control(FuncOperate, 2, 1000, 7, 0x41)
	second := control(FuncOperate, 2, 1200, 7, 0x41)
	resp := response(2, 1500, false)

	correlateResponses([]*types.DNP3{first, second}, []*types.DNP3{resp})

	if resp.CorrelationStatus != corrAmbiguous {
		t.Errorf("CorrelationStatus = %q, want %q", resp.CorrelationStatus, corrAmbiguous)
	}
}

// An unsolicited response is outstation-initiated; there is no request.
func TestUnsolicitedResponseNotCorrelated(t *testing.T) {
	req := control(FuncOperate, 2, 1000, 7, 0x41)
	resp := response(2, 1500, true)

	correlateResponses([]*types.DNP3{req}, []*types.DNP3{resp})

	if resp.CorrelationStatus != corrNotApplicable {
		t.Errorf("CorrelationStatus = %q, want %q", resp.CorrelationStatus, corrNotApplicable)
	}
	if resp.RequestTimestamp != 0 {
		t.Error("unsolicited response inherited a request timestamp")
	}
}

// Link addresses must be the request's reversed; a reply from a different
// outstation is not an answer.
func TestResponseRequiresReversedAddresses(t *testing.T) {
	req := control(FuncOperate, 2, 1000, 7, 0x41)
	resp := response(2, 1500, false)
	resp.Source = 77

	correlateResponses([]*types.DNP3{req}, []*types.DNP3{resp})

	if resp.CorrelationStatus != corrUnmatched {
		t.Errorf("CorrelationStatus = %q, want %q", resp.CorrelationStatus, corrUnmatched)
	}
}

func TestResponseTimeoutNotMatched(t *testing.T) {
	req := control(FuncOperate, 2, 1000, 7, 0x41)
	resp := response(2, 1000+int64(31*time.Second), false)

	correlateResponses([]*types.DNP3{req}, []*types.DNP3{resp})

	if resp.CorrelationStatus != corrUnmatched {
		t.Errorf("CorrelationStatus = %q, want %q", resp.CorrelationStatus, corrUnmatched)
	}
}
