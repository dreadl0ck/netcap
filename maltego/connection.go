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

package maltego

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dreadl0ck/maltego"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

// connCountFunc is a function that counts something over multiple conn audit records.
type connCountFunc = func(conn *types.Connection, ipaddr string, min, max *uint64, sizes *[]int)

// countIncomingConnBytes returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all incoming conns for a given ip address.
//
//goland:noinspection GoUnusedGlobalVariable
var countIncomingConnBytes = func(conn *types.Connection, ipaddr string, min, max *uint64, sizes *[]int) {
	if conn.DstIP == ipaddr {

		*sizes = append(*sizes, int(conn.TotalSize))

		if uint64(conn.TotalSize) < *min {
			*min = uint64(conn.TotalSize)
		}
		if uint64(conn.TotalSize) > *max {
			*max = uint64(conn.TotalSize)
		}
	}
}

// CountIncomingConnBytesFiltered countIncomingconnPackets returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all incoming conns for a given ip address
// filtered against the domain whitelist.
var CountIncomingConnBytesFiltered = func(conn *types.Connection, ipaddr string, min, max *uint64, sizes *[]int) {
	if conn.DstIP == ipaddr {
		name := resolvers.LookupDNSNameLocal(conn.SrcIP)
		if name != "" {
			if !resolvers.IsWhitelistedDomain(name) {
				*sizes = append(*sizes, int(conn.TotalSize))

				if uint64(conn.TotalSize) < *min {
					*min = uint64(conn.TotalSize)
				}
				if uint64(conn.TotalSize) > *max {
					*max = uint64(conn.TotalSize)
				}
			}
		} else {
			// bare IP
			*sizes = append(*sizes, int(conn.TotalSize))

			if uint64(conn.TotalSize) < *min {
				*min = uint64(conn.TotalSize)
			}
			if uint64(conn.TotalSize) > *max {
				*max = uint64(conn.TotalSize)
			}
		}
	}
}

// countIncomingConnPackets returns the lowest and highest number of packets as well as an array of sizes
// seen for all incoming conns for a given ip address.
//
//goland:noinspection GoUnusedGlobalVariable
var countIncomingConnPackets = func(conn *types.Connection, ipaddr string, min, max *uint64, sizes *[]int) {
	if conn.DstIP == ipaddr {

		*sizes = append(*sizes, int(conn.TotalSize))

		if uint64(conn.NumPackets) < *min {
			*min = uint64(conn.NumPackets)
		}
		if uint64(conn.NumPackets) > *max {
			*max = uint64(conn.NumPackets)
		}
	}
}

// countOutgoingConnBytes returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all outgoing conns from a given ip address
// filtered against the domain whitelist.
//
//goland:noinspection GoUnusedGlobalVariable
var countOutgoingConnBytes = func(conn *types.Connection, ipaddr string, min, max *uint64, sizes *[]int) {
	if conn.SrcIP == ipaddr {

		*sizes = append(*sizes, int(conn.TotalSize))

		if uint64(conn.TotalSize) < *min {
			*min = uint64(conn.TotalSize)
		}
		if uint64(conn.TotalSize) > *max {
			*max = uint64(conn.TotalSize)
		}
	}
}

// CountOutgoingConnBytesFiltered returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all outgoing conns from a given ip address
// filtered against the domain whitelist.
var CountOutgoingConnBytesFiltered = func(conn *types.Connection, ipaddr string, min, max *uint64, sizes *[]int) {
	if conn.SrcIP == ipaddr {
		name := resolvers.LookupDNSNameLocal(conn.DstIP)
		if name != "" {
			if !resolvers.IsWhitelistedDomain(name) {
				*sizes = append(*sizes, int(conn.TotalSize))

				if uint64(conn.TotalSize) < *min {
					*min = uint64(conn.TotalSize)
				}
				if uint64(conn.TotalSize) > *max {
					*max = uint64(conn.TotalSize)
				}
			}
		} else {
			// bare IP
			*sizes = append(*sizes, int(conn.TotalSize))

			if uint64(conn.TotalSize) < *min {
				*min = uint64(conn.TotalSize)
			}
			if uint64(conn.TotalSize) > *max {
				*max = uint64(conn.TotalSize)
			}
		}
	}
}

// CountPacketsDevices returns the lowest and highest number of packets as well as an array of sizes
// seen for all outgoing conns from a given ip address.
//
//goland:noinspection GoUnusedGlobalVariable
var countOutgoingconnPackets = func(conn *types.Connection, ipaddr string, min, max *uint64, sizes *[]int) {
	if conn.SrcIP == ipaddr {

		*sizes = append(*sizes, int(conn.TotalSize))

		if uint64(conn.NumPackets) < *min {
			*min = uint64(conn.NumPackets)
		}
		if uint64(conn.NumPackets) > *max {
			*max = uint64(conn.NumPackets)
		}
	}
}

// connTransformationFunc is a transformation over conn audit records.
type connTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ip string, sizes *[]int)

// ConnectionTransform applies a maltego transformation over types.Connection audit records.
func ConnectionTransform(count connCountFunc, transform connTransformationFunc) {
	var (
		lt               = maltego.ParseLocalArguments(os.Args[3:])
		path             = lt.Values["path"]
		mac              = lt.Values["mac"]
		ipaddr           = lt.Values[PropertyIpAddr]
		dir              = filepath.Dir(path)
		connAuditRecords = filepath.Join(dir, "Connection.ncap.gz")
		trx              = maltego.Transform{}
	)

	netio.FPrintBuildInfo(os.Stderr)

	log.Println("opening", connAuditRecords)

	f, path := openFile(connAuditRecords)

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		maltego.Die("input file must be an audit record file, but got", f.Name())
	}

	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		maltego.Die(errFileHeader.Error(), "failed to read file header")
	}

	if header != nil && header.Type != types.Type_NC_Connection {
		maltego.Die("file does not contain conn records", header.Type.String())
	}

	var (
		conn = new(types.Connection)
		pm   proto.Message
		ok   bool
	)

	pm = conn

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min   uint64 = 10000000
		max   uint64 = 0
		sizes []int
		err   error
	)

	if count != nil {
		for {
			err = r.Next(conn)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				maltego.Die(err.Error(), errUnexpectedReadFailure)
			}

			count(conn, ipaddr, &min, &max, &sizes)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}

		sort.Ints(sizes)
	}

	r = openNetcapArchive(path)

	// read netcap header - ignore err as it has been checked before
	_, _ = r.ReadHeader()

	var top12 []int
	if len(sizes) > 12 {
		top12 = sizes[len(sizes)-12:]
	}

	log.Println("==> top12", top12)

	for {
		err = r.Next(conn)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, conn, min, max, path, mac, ipaddr, &top12)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
