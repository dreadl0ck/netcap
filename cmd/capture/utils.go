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

package capture

import (
	"fmt"

	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/io"
)

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("capture tool usage examples:")
	fmt.Println("	$ net capture -read dump.pcap")
	fmt.Println("	$ net capture -iface eth0")
	fmt.Println()
}

const (
	pgzipMaxSpeed       = "max-speed"
	pgzipMaxCompression = "max-compression"
	pgzipNone           = "none"
)

func getCompressionLevel(in string) int {
	switch in {
	case pgzipMaxSpeed:
		return pgzip.BestSpeed
	case pgzipMaxCompression:
		return pgzip.BestCompression
	case pgzipNone:
		return pgzip.NoCompression
	default:
		return pgzip.DefaultCompression
	}
}

func compressionLevelToString(in int) string {
	switch in {
	case pgzip.BestSpeed:
		return pgzipMaxSpeed
	case pgzip.BestCompression:
		return pgzipMaxCompression
	case pgzip.NoCompression:
		return pgzipNone
	default:
		return "default"
	}
}
