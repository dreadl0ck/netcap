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

package ssh

import (
	"encoding/binary"
	"testing"
)

func TestParseSSHInfoFromHasshDB(t *testing.T) {
	sshVersion, product, version, os := parseSSHInfoFromHasshDB("SSH 2.0 | OpenSSH 7.4 ? Debian")
	if sshVersion != "SSH 2.0" {
		t.Fatal("expected sshVersion: SSH 2.0")
	}
	if product != "OpenSSH" {
		t.Fatal("expected product: OpenSSH")
	}
	if version != "7.4" {
		t.Fatal("expected version: 7.4")
	}
	if os != "Debian" {
		t.Fatal("expected os: Debian")
	}
}

func TestParseSSHIdent(t *testing.T) {
	i := parseSSHIdent("SSH-2.0-OpenSSH_for_Windows_7.7\\r\\n")
	if i == nil {
		t.Fatal("failed to parse")
	}
	if i.sshVersion != "SSH-2.0" {
		t.Fatal("unexpected ssh version", i.sshVersion)
	}
	if i.productName != "OpenSSH_for_Windows" {
		t.Fatal("unexpected product name", i.productName)
	}
	if i.productVersion != "7.7" {
		t.Fatal("unexpected product version", i.productVersion)
	}
	if i.os != "" {
		t.Fatal("unexpected os", i.os)
	}

	i = parseSSHIdent("SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\\r\\n")
	if i == nil {
		t.Fatal("failed to parse")
	}
	if i.sshVersion != "SSH-2.0" {
		t.Fatal("unexpected ssh version", i.sshVersion)
	}
	if i.productName != "OpenSSH" {
		t.Fatal("unexpected product name", i.productName)
	}
	if i.productVersion != "7.6p1" {
		t.Fatal("unexpected product version", i.productVersion)
	}
	if i.os != "Ubuntu" {
		t.Fatal("unexpected os", i.os)
	}

	i = parseSSHIdent("SSH-2.0-PuTTY_Release_0.73")
	if i == nil {
		t.Fatal("failed to parse")
	}
	if i.sshVersion != "SSH-2.0" {
		t.Fatal("unexpected ssh version", i.sshVersion)
	}
	if i.productName != "PuTTY_Release" {
		t.Fatal("unexpected product name", i.productName)
	}
	if i.productVersion != "0.73" {
		t.Fatal("unexpected product version", i.productVersion)
	}
	if i.os != "" {
		t.Fatal("unexpected os", i.os)
	}
}

func TestParseSSHKexInitMsgLength(t *testing.T) {
	// FYI: parseInt handles hex strings as well: strconv.ParseInt("0x00000634", 0, 64)
	if binary.BigEndian.Uint32([]byte{0x00, 0x00, 0x06, 0x34}) != 1588 {
		t.Fatal("expected 1588")
	}
}

func TestParseSSHKexInitMsgPadding(t *testing.T) {
	if uint8(0x06) != 6 {
		t.Fatal("the value should be 6")
	}
}
