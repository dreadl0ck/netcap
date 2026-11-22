package protocoltest

import (
	"fmt"
	"strconv"
	"strings"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

func selectTLSStream(rows, id string) (int, error) {
	found := -1
	for _, row := range strings.Split(strings.TrimSuffix(rows, "\n"), "\n") {
		fields := strings.Split(row, "\t")
		if len(fields) != 7 {
			continue
		}
		index, err := strconv.Atoi(fields[0])
		if err != nil || index < 0 {
			continue
		}
		sp, err := strconv.ParseUint(fields[3], 10, 16)
		if err != nil {
			continue
		}
		dp, err := strconv.ParseUint(fields[6], 10, 16)
		if err != nil {
			continue
		}
		match := false
		for _, pair := range [][2]int{{1, 4}, {2, 5}} {
			if fields[pair[0]] != "" && fields[pair[1]] != "" && streamutils.CalcCommunityIDTCP(fields[pair[0]], fields[pair[1]], uint16(sp), uint16(dp)) == id {
				match = true
			}
		}
		if match {
			if found >= 0 && found != index {
				return 0, fmt.Errorf("Community ID matches multiple TLS streams; select --stream explicitly")
			}
			found = index
		}
	}
	if found < 0 {
		return 0, fmt.Errorf("no TLS stream matches Community ID %s", id)
	}
	return found, nil
}
