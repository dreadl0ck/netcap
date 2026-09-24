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

// Application layer function codes, IEEE 1815 Table 4-1.
const (
	FuncConfirm              = 0
	FuncRead                 = 1
	FuncWrite                = 2
	FuncSelect               = 3
	FuncOperate              = 4
	FuncDirectOperate        = 5
	FuncDirectOperateNoAck   = 6
	FuncImmediateFreeze      = 7
	FuncImmediateFreezeNoAck = 8
	FuncFreezeAndClear       = 9
	FuncFreezeAndClearNoAck  = 10
	FuncFreezeAtTime         = 11
	FuncFreezeAtTimeNoAck    = 12
	FuncColdRestart          = 13
	FuncWarmRestart          = 14
	FuncInitData             = 15
	FuncInitApplication      = 16
	FuncStartApplication     = 17
	FuncStopApplication      = 18
	FuncSaveConfiguration    = 19
	FuncEnableUnsolicited    = 20
	FuncDisableUnsolicited   = 21
	FuncAssignClass          = 22
	FuncDelayMeasurement     = 23
	FuncRecordCurrentTime    = 24
	FuncOpenFile             = 25
	FuncCloseFile            = 26
	FuncDeleteFile           = 27
	FuncGetFileInfo          = 28
	FuncAuthenticateFile     = 29
	FuncAbortFile            = 30
	FuncActivateConfig       = 31
	FuncAuthenticateReq      = 32
	FuncAuthenticateReqNoAck = 33
	FuncResponse             = 129
	FuncUnsolicitedResponse  = 130
	FuncAuthenticateResp     = 131
)

var functionCodeNames = map[int32]string{
	FuncConfirm:              "CONFIRM",
	FuncRead:                 "READ",
	FuncWrite:                "WRITE",
	FuncSelect:               "SELECT",
	FuncOperate:              "OPERATE",
	FuncDirectOperate:        "DIRECT_OPERATE",
	FuncDirectOperateNoAck:   "DIRECT_OPERATE_NO_ACK",
	FuncImmediateFreeze:      "IMMEDIATE_FREEZE",
	FuncImmediateFreezeNoAck: "IMMEDIATE_FREEZE_NO_ACK",
	FuncFreezeAndClear:       "FREEZE_AND_CLEAR",
	FuncFreezeAndClearNoAck:  "FREEZE_AND_CLEAR_NO_ACK",
	FuncFreezeAtTime:         "FREEZE_AT_TIME",
	FuncFreezeAtTimeNoAck:    "FREEZE_AT_TIME_NO_ACK",
	FuncColdRestart:          "COLD_RESTART",
	FuncWarmRestart:          "WARM_RESTART",
	FuncInitData:             "INITIALIZE_DATA",
	FuncInitApplication:      "INITIALIZE_APPLICATION",
	FuncStartApplication:     "START_APPLICATION",
	FuncStopApplication:      "STOP_APPLICATION",
	FuncSaveConfiguration:    "SAVE_CONFIGURATION",
	FuncEnableUnsolicited:    "ENABLE_UNSOLICITED",
	FuncDisableUnsolicited:   "DISABLE_UNSOLICITED",
	FuncAssignClass:          "ASSIGN_CLASS",
	FuncDelayMeasurement:     "DELAY_MEASUREMENT",
	FuncRecordCurrentTime:    "RECORD_CURRENT_TIME",
	FuncOpenFile:             "OPEN_FILE",
	FuncCloseFile:            "CLOSE_FILE",
	FuncDeleteFile:           "DELETE_FILE",
	FuncGetFileInfo:          "GET_FILE_INFO",
	FuncAuthenticateFile:     "AUTHENTICATE_FILE",
	FuncAbortFile:            "ABORT_FILE",
	FuncActivateConfig:       "ACTIVATE_CONFIG",
	FuncAuthenticateReq:      "AUTHENTICATE_REQ",
	FuncAuthenticateReqNoAck: "AUTHENTICATE_REQ_NO_ACK",
	FuncResponse:             "RESPONSE",
	FuncUnsolicitedResponse:  "UNSOLICITED_RESPONSE",
	FuncAuthenticateResp:     "AUTHENTICATE_RESP",
}

// criticalFunctions operate the process or the device's availability.
var criticalFunctions = map[int32]bool{
	FuncOperate:              true,
	FuncDirectOperate:        true,
	FuncDirectOperateNoAck:   true,
	FuncColdRestart:          true,
	FuncWarmRestart:          true,
	FuncInitData:             true,
	FuncInitApplication:      true,
	FuncStartApplication:     true,
	FuncStopApplication:      true,
	FuncImmediateFreeze:      true,
	FuncImmediateFreezeNoAck: true,
	FuncFreezeAndClear:       true,
	FuncFreezeAndClearNoAck:  true,
	FuncFreezeAtTime:         true,
	FuncFreezeAtTimeNoAck:    true,
	FuncActivateConfig:       true,
}

// configChangeFunctions alter what the outstation is, rather than what it is
// doing. The file set belongs here: a config downloaded over FC25-30 and then
// activated by FC31 replaces the device's behavior wholesale.
var configChangeFunctions = map[int32]bool{
	FuncWrite:              true,
	FuncSaveConfiguration:  true,
	FuncAssignClass:        true,
	FuncEnableUnsolicited:  true,
	FuncDisableUnsolicited: true,
	FuncOpenFile:           true,
	FuncCloseFile:          true,
	FuncDeleteFile:         true,
	FuncAuthenticateFile:   true,
	FuncAbortFile:          true,
	FuncActivateConfig:     true,
}

// authenticationFunctions are Secure Authentication v5. FC29 is deliberately
// absent: it authenticates a file transfer, not a session, and treating it as
// SAv5 reports authentication on outstations that support none.
var authenticationFunctions = map[int32]bool{
	FuncAuthenticateReq:      true,
	FuncAuthenticateReqNoAck: true,
	FuncAuthenticateResp:     true,
}

func functionCodeName(code int32) string {
	if name, ok := functionCodeNames[code]; ok {
		return name
	}

	return nameUnknown
}
