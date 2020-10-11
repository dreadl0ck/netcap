package utils

import (
	"strconv"
	"strings"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

const (
	unknown = "unknown"
)

func getServiceName(data []byte, flow gopacket.Flow, proto string) string {
	var (
		dstPort, _ = strconv.Atoi(flow.Dst().String())
		s          = resolvers.LookupServiceByPort(dstPort, strings.ToLower(proto))
	)

	if s != "" {
		return s
	}

	// still no clue? lets check if its ascii
	if utils.IsASCII(data) {
		return "ascii"
	}

	return unknown
}
