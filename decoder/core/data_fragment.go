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

import (
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/reassembly"
)

// dataFragment describes functionality of encapsulation structures for network data fragments.
type dataFragment interface {
	Raw() []byte
	Context() reassembly.AssemblerContext
	Direction() reassembly.TCPFlowDirection
	SetDirection(reassembly.TCPFlowDirection)
	CaptureInfo() gopacket.CaptureInfo
	Network() gopacket.Flow
	Transport() gopacket.Flow
}
