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

import "testing"

// The IEEE 1815 Table 4-1 assignments, pinned so a renumbering or a dropped
// entry fails here rather than silently reclassifying a control as unknown.
func TestFunctionCodeNames(t *testing.T) {
	for code, want := range map[int32]string{
		0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
		5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NO_ACK",
		13: "COLD_RESTART", 14: "WARM_RESTART",
		18: "STOP_APPLICATION", 19: "SAVE_CONFIGURATION",
		20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
		25: "OPEN_FILE", 27: "DELETE_FILE", 29: "AUTHENTICATE_FILE",
		31: "ACTIVATE_CONFIG", 32: "AUTHENTICATE_REQ", 33: "AUTHENTICATE_REQ_NO_ACK",
		129: "RESPONSE", 130: "UNSOLICITED_RESPONSE", 131: "AUTHENTICATE_RESP",
	} {
		if got := functionCodeName(code); got != want {
			t.Errorf("function %d = %q, want %q", code, got, want)
		}
	}

	if got := functionCodeName(200); got != "UNKNOWN" {
		t.Errorf("unassigned function = %q, want UNKNOWN", got)
	}
}

// The telemetry codes. Everything else is the control plane, which is the whole
// premise of the function-code hunt.
func TestTelemetryCodesAreNotFlagged(t *testing.T) {
	for _, fc := range []int32{FuncRead, FuncResponse, FuncUnsolicitedResponse} {
		if criticalFunctions[fc] || configChangeFunctions[fc] || authenticationFunctions[fc] {
			t.Errorf("function %d is flagged, but it is routine telemetry", fc)
		}
	}
}

// A configuration downloaded over the file functions and activated by FC31
// replaces what the outstation does. None of these were classified before.
func TestFileAndActivateAreConfigChanges(t *testing.T) {
	for _, fc := range []int32{
		FuncOpenFile, FuncCloseFile, FuncDeleteFile,
		FuncAuthenticateFile, FuncAbortFile, FuncActivateConfig,
	} {
		if !configChangeFunctions[fc] {
			t.Errorf("function %d (%s) is not flagged as a config change", fc, functionCodeName(fc))
		}
	}
}

// FC29 authenticates a file transfer, not a session. Counting it as Secure
// Authentication reports SAv5 on outstations that support none.
func TestAuthenticationIsSecureAuthenticationOnly(t *testing.T) {
	for _, fc := range []int32{FuncAuthenticateReq, FuncAuthenticateReqNoAck, FuncAuthenticateResp} {
		if !authenticationFunctions[fc] {
			t.Errorf("function %d is not flagged as authentication", fc)
		}
	}
	if authenticationFunctions[FuncAuthenticateFile] {
		t.Error("AUTHENTICATE_FILE is flagged as Secure Authentication")
	}
}

func TestCriticalFunctions(t *testing.T) {
	for _, fc := range []int32{
		FuncOperate, FuncDirectOperate, FuncDirectOperateNoAck,
		FuncColdRestart, FuncWarmRestart, FuncStopApplication, FuncActivateConfig,
	} {
		if !criticalFunctions[fc] {
			t.Errorf("function %d (%s) is not flagged critical", fc, functionCodeName(fc))
		}
	}
	if criticalFunctions[FuncSelect] {
		t.Error("SELECT is flagged critical: it arms a control, it does not operate one")
	}
}

func TestLinkFunctionNamesDependOnDirection(t *testing.T) {
	// The same nibble means different things in each direction.
	if got := linkFunctionName(0x0, true); got != "RESET_LINK_STATES" {
		t.Errorf("primary 0x0 = %q", got)
	}
	if got := linkFunctionName(0x0, false); got != "ACK" {
		t.Errorf("secondary 0x0 = %q", got)
	}
	if got := linkFunctionName(0xB, false); got != "LINK_STATUS" {
		t.Errorf("secondary 0xB = %q", got)
	}
}

// Only user data frames carry an application PDU. Parsing a link control frame
// reads link state as a function code.
func TestCarriesAPDU(t *testing.T) {
	if !carriesAPDU(linkConfirmedUserData, true) || !carriesAPDU(linkUnconfirmedUserData, true) {
		t.Error("user data frames should carry an APDU")
	}
	for _, code := range []byte{linkResetLinkStates, linkTestLinkStates, linkRequestLinkStatus} {
		if carriesAPDU(code, true) {
			t.Errorf("primary link function %#x should not carry an APDU", code)
		}
	}
	// No secondary frame carries one.
	for code := byte(0); code < 16; code++ {
		if carriesAPDU(code, false) {
			t.Errorf("secondary link function %#x should not carry an APDU", code)
		}
	}
}
