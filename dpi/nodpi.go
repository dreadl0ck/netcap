//go:build nodpi
// +build nodpi

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

package dpi

// this file contains function stubs that do nothing, but allow us to compile
import (
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/types"
)

// IsEnabled will return true if goDPI has been initialized
func IsEnabled() bool {
	return false
}

// Init is a stub that accepts modules parameter but does nothing when DPI is disabled
func Init(modules string) {}

func Destroy() {}

// Reset is a stub that does nothing when DPI is disabled
func Reset(modules string) {}

func GetProtocols(packet gopacket.Packet) map[string]struct{} {
	uniqueResults := make(map[string]struct{})

	return uniqueResults
}

func NewProto(i *struct{}) *types.Protocol {
	return &types.Protocol{}
}

// GetModuleProtocols returns an empty map when DPI is disabled
func GetModuleProtocols() map[string][]string {
	return make(map[string][]string)
}
