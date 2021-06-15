/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
