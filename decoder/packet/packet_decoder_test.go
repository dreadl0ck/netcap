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

package packet

import (
	"testing"
)

// Overwriting the package level conf when executing other tests in parallel is a bad idea...
//func TestInitPacketDecoders(t *testing.T) {
//	_ = os.MkdirAll("tests/packetDecoders", defaults.DirectoryPermission)
//
//	conf = &Config{
//		Out:                     "tests/packetDecoders",
//		Source:                  "",
//		CustomRegex:             "",
//		MemProfile:              "",
//		IncludeDecoders:         "",
//		ExcludeDecoders:         "",
//		FileStorage:             "",
//		ConnFlushInterval:       0,
//		MemBufferSize:           0,
//		FlowTimeOut:             0,
//		StreamDecoderBufSize:    0,
//		CloseInactiveTimeOut:    0,
//		FlushEvery:              0,
//		HarvesterBannerSize:     0,
//		BannerSize:              0,
//		ClosePendingTimeOut:     0,
//		FlowFlushInterval:       0,
//		ConnTimeOut:             0,
//		UseRE2:                  false,
//		StopAfterHarvesterMatch: false,
//		Buffer:                  false,
//		WriteIncomplete:         false,
//		Chan:                    false,
//		CSV:                     false,
//		Proto:                   true,
//		AddContext:              false,
//		WaitForConnections:      false,
//		HexDump:                 false,
//		Debug:                   false,
//		AllowMissingInit:        false,
//		IgnoreFSMerr:            false,
//		CalculateEntropy:        false,
//		SaveConns:               false,
//		TCPDebug:                false,
//		NoOptCheck:              false,
//		Checksum:                false,
//		DefragIPv4:              false,
//		Export:                  false,
//		IncludePayloads:         false,
//		Compression:             true,
//		IgnoreDecoderInitErrors: false,
//	}
//	decoders, err := InitPacketDecoders(conf)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	if len(decoders) == 0 {
//		t.Fatal("no packet decoders after initialization")
//	}
//
//	utils.CloseBleve(exploitsIndex)
//	utils.CloseBleve(vulnerabilitiesIndex)
//}

func TestPacketDecoder_Decode(t *testing.T) {
}

func TestPacketDecoder_Destroy(t *testing.T) {
}
