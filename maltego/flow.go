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

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

// flowCountFunc is a function that counts something over multiple Flow audit records.
type flowCountFunc = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int)

// countIncomingFlowBytes returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all incoming flows for a given ip address.
//goland:noinspection GoUnusedGlobalVariable
var countIncomingFlowBytes = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.DstIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.TotalSize) < *min {
			*min = uint64(flow.TotalSize)
		}
		if uint64(flow.TotalSize) > *max {
			*max = uint64(flow.TotalSize)
		}
	}
}

// CountIncomingFlowBytesFiltered countIncomingFlowPackets returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all incoming flows for a given ip address
// filtered against the domain whitelist.
var CountIncomingFlowBytesFiltered = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.DstIP == ipaddr {
		name := resolvers.LookupDNSNameLocal(flow.SrcIP)
		if name != "" {
			if !resolvers.IsWhitelistedDomain(name) {
				*sizes = append(*sizes, int(flow.TotalSize))

				if uint64(flow.TotalSize) < *min {
					*min = uint64(flow.TotalSize)
				}
				if uint64(flow.TotalSize) > *max {
					*max = uint64(flow.TotalSize)
				}
			}
		} else {
			// bare IP
			*sizes = append(*sizes, int(flow.TotalSize))

			if uint64(flow.TotalSize) < *min {
				*min = uint64(flow.TotalSize)
			}
			if uint64(flow.TotalSize) > *max {
				*max = uint64(flow.TotalSize)
			}
		}
	}
}

// countIncomingFlowPackets returns the lowest and highest number of packets as well as an array of sizes
// seen for all incoming flows for a given ip address.
//goland:noinspection GoUnusedGlobalVariable
var countIncomingFlowPackets = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.DstIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.NumPackets) < *min {
			*min = uint64(flow.NumPackets)
		}
		if uint64(flow.NumPackets) > *max {
			*max = uint64(flow.NumPackets)
		}
	}
}

// CountOutgoingFlowBytesFiltered returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all outgoing flows from a given ip address
// filtered against the domain whitelist.
//goland:noinspection GoUnusedGlobalVariable
var countOutgoingFlowBytes = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.SrcIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.TotalSize) < *min {
			*min = uint64(flow.TotalSize)
		}
		if uint64(flow.TotalSize) > *max {
			*max = uint64(flow.TotalSize)
		}
	}
}

// CountOutgoingFlowBytesFiltered returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all outgoing flows from a given ip address
// filtered against the domain whitelist.
var CountOutgoingFlowBytesFiltered = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.SrcIP == ipaddr {
		name := resolvers.LookupDNSNameLocal(flow.DstIP)
		if name != "" {
			if !resolvers.IsWhitelistedDomain(name) {
				*sizes = append(*sizes, int(flow.TotalSize))

				if uint64(flow.TotalSize) < *min {
					*min = uint64(flow.TotalSize)
				}
				if uint64(flow.TotalSize) > *max {
					*max = uint64(flow.TotalSize)
				}
			}
		} else {
			// bare IP
			*sizes = append(*sizes, int(flow.TotalSize))

			if uint64(flow.TotalSize) < *min {
				*min = uint64(flow.TotalSize)
			}
			if uint64(flow.TotalSize) > *max {
				*max = uint64(flow.TotalSize)
			}
		}
	}
}

// CountPacketsDevices returns the lowest and highest number of packets as well as an array of sizes
// seen for all outgoing flows from a given ip address.
//goland:noinspection GoUnusedGlobalVariable
var countOutgoingFlowPackets = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.SrcIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.NumPackets) < *min {
			*min = uint64(flow.NumPackets)
		}
		if uint64(flow.NumPackets) > *max {
			*max = uint64(flow.NumPackets)
		}
	}
}

// flowTransformationFunc is a transformation over Flow audit records.
type flowTransformationFunc = func(lt LocalTransform, trx *Transform, flow *types.Flow, min, max uint64, path string, mac string, ip string, sizes *[]int)

// FlowTransform applies a maltego transformation over Flow audit records.
func FlowTransform(count flowCountFunc, transform flowTransformationFunc) {
	var (
		lt               = ParseLocalArguments(os.Args[1:])
		path             = lt.Values["path"]
		mac              = lt.Values["mac"]
		ipaddr           = lt.Values["ipaddr"]
		dir              = filepath.Dir(path)
		flowAuditRecords = filepath.Join(dir, "Flow.ncap.gz")
		trx              = Transform{}
	)

	netio.FPrintBuildInfo(os.Stderr)

	log.Println("opening", flowAuditRecords)

	f, err := os.Open(flowAuditRecords)
	if err != nil {
		die(err.Error(), "failed to open audit records")
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		die("input file must be an audit record file, but got", f.Name())
	}

	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		die(errFileHeader.Error(), "failed to read file header")
	}

	if header.Type != types.Type_NC_Flow {
		die("file does not contain Flow records", header.Type.String())
	}

	var (
		flow = new(types.Flow)
		pm   proto.Message
		ok   bool
	)

	pm = flow

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min   uint64 = 10000000
		max   uint64 = 0
		sizes []int
	)

	if count != nil {
		for {
			err = r.Next(flow)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				die(err.Error(), errUnexpectedReadFailure)
			}

			count(flow, ipaddr, &min, &max, &sizes)
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
		err = r.Next(flow)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, flow, min, max, path, mac, ipaddr, &top12)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
