package utils

import (
	"strconv"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

const typeTCP = "tcp"

func getServiceName(data []byte, flow gopacket.Flow) string {
	var (
		dstPort, _ = strconv.Atoi(flow.Dst().String())
		s          = resolvers.LookupServiceByPort(dstPort, typeTCP)
	)

	if s != "" {
		return s
	}

	// what about the source port?
	srcPort, _ := strconv.Atoi(flow.Src().String())
	s = resolvers.LookupServiceByPort(srcPort, typeTCP)

	if s != "" {
		return s
	}

	// still no clue? lets check if its ascii
	if utils.IsASCII(data) {
		return "ascii"
	}

	return "unknown"
}
