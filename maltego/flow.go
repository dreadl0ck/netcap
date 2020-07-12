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
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FlowCountFunc is a function that counts something over multiple Flow audit records
type FlowCountFunc = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int)

// CountIncomingFlowPackets returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all incoming flows for a given ip address
var CountIncomingFlowBytes = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
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

// CountIncomingFlowPackets returns the lowest and highest number of bytes transferred as well as an array of sizes
// seen for all incoming flows for a given ip address
// filtered against the domain whitelist
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

// CountIncomingFlowPackets returns the lowest and highest number of packets as well as an array of sizes
// seen for all incoming flows for a given ip address
var CountIncomingFlowPackets = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
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
// filtered against the domain whitelist
var CountOutgoingFlowBytes = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
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
// filtered against the domain whitelist
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
// seen for all outgoing flows from a given ip address
var CountOutgoingFlowPackets = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
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

// FlowTransformationFunc is a transformation over Flow audit records
type FlowTransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, flow *types.Flow, min, max uint64, profilesFile string, mac string, ip string, sizes *[]int)

// FlowTransform applies a maltego transformation over Flow audit records
func FlowTransform(count FlowCountFunc, transform FlowTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	mac := lt.Values["mac"]
	ipaddr := lt.Values["ipaddr"]

	stdout := os.Stdout
	os.Stdout = os.Stderr
	netcap.PrintBuildInfo()

	dir := filepath.Dir(profilesFile)
	flowAuditRecords := filepath.Join(dir, "Flow.ncap.gz")
	log.Println("open", flowAuditRecords)
	f, err := os.Open(flowAuditRecords)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	os.Stdout = stdout

	r, err := netcap.Open(flowAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}
	if header.Type != types.Type_NC_Flow {
		panic("file does not contain Flow records: " + header.Type.String())
	}

	var (
		flow = new(types.Flow)
		pm   proto.Message
		ok   bool
		trx  = MaltegoTransform{}
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
			err := r.Next(flow)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(flow, ipaddr, &min, &max, &sizes)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}

		sort.Ints(sizes)
	}

	r, err = netcap.Open(flowAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	var top12 []int
	if len(sizes) > 12 {
		top12 = sizes[len(sizes)-12:]
	}
	log.Println("==> top12", top12)

	for {
		err := r.Next(flow)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, flow, min, max, profilesFile, mac, ipaddr, &top12)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
