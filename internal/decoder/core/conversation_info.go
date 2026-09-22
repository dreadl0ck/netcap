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

package core

import "time"

// ConversationInfo is wrapper structure for traffic sent over a Transport protocol
// to allow Transport agnostic decoding of data streams.
type ConversationInfo struct {
	Data DataFragments
	// TCP directions in reassembly order; capture timestamps can run backwards.
	ClientData        DataFragments
	ServerData        DataFragments
	Ident             string
	FirstClientPacket time.Time
	FirstServerPacket time.Time

	ClientIP   string
	ServerIP   string
	ClientPort int32
	ServerPort int32

	// True only when SYN, SYN-ACK and the acknowledging client ACK were observed.
	TCPHandshakeComplete bool

	// CommunityID is the Corelight Community ID v1 for this stream.
	// This provides a standardized flow identifier compatible with
	// Zeek, Suricata, and other network monitoring tools.
	// See: https://github.com/corelight/community-id-spec
	CommunityID string
}
