package protocoltest

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

var errNoDecryptedTLS = errors.New("no decrypted application bytes: secrets, stream selection or capture coverage may be insufficient")

func analyzeUniqueTLSCapture(ctx context.Context, input, keyLog string) (TLSCaptureResult, error) {
	var empty TLSCaptureResult
	if _, err := boundedFile(input, 256<<20); err != nil {
		return empty, err
	}
	if _, err := boundedFile(keyLog, 4<<20); err != nil {
		return empty, err
	}
	tool, err := exec.LookPath("tshark")
	if err != nil {
		return empty, fmt.Errorf("TLS selection requires tshark: %w", err)
	}
	command := exec.CommandContext(ctx, tool, "-n", "-r", input, "-Y", "tls", "-T", "fields", "-E", "occurrence=l", "-e", "tls.stream")
	output, stderr := &cappedBuffer{limit: 4 << 20}, &cappedBuffer{limit: 65536}
	command.Stdout, command.Stderr = output, stderr
	if err := command.Run(); err != nil {
		return empty, fmt.Errorf("TLS stream discovery: %w", err)
	}
	indexes := map[int]bool{}
	for _, value := range strings.Fields(output.String()) {
		index, err := strconv.Atoi(value)
		if err != nil || index < 0 {
			return empty, fmt.Errorf("invalid TLS stream discovery output")
		}
		indexes[index] = true
		if len(indexes) > 64 {
			return empty, fmt.Errorf("more than 64 TLS candidates; select --stream or --community-id explicitly")
		}
	}
	ordered := make([]int, 0, len(indexes))
	for index := range indexes {
		ordered = append(ordered, index)
	}
	sort.Ints(ordered)
	var selected TLSCaptureResult
	var matches []int
	for _, index := range ordered {
		result, err := AnalyzeTLSCapture(ctx, input, keyLog, index)
		if errors.Is(err, errNoDecryptedTLS) {
			continue
		}
		if err != nil {
			return empty, err
		}
		matches = append(matches, index)
		selected = result
	}
	if len(matches) == 0 {
		return empty, errNoDecryptedTLS
	}
	if len(matches) != 1 {
		return empty, fmt.Errorf("multiple decryptable TLS streams %v; select --stream or --community-id explicitly", matches)
	}
	return selected, nil
}

func TLSStreamByCommunityID(ctx context.Context, input, id string) (int, error) {
	if !strings.HasPrefix(id, "1:") || len(id) != 30 {
		return 0, fmt.Errorf("expected a Community ID v1 value")
	}
	if _, err := boundedFile(input, 256<<20); err != nil {
		return 0, err
	}
	tool, err := exec.LookPath("tshark")
	if err != nil {
		return 0, fmt.Errorf("TLS selection requires tshark: %w", err)
	}
	command := exec.CommandContext(ctx, tool, "-n", "-r", input, "-Y", "tls", "-T", "fields", "-E", "occurrence=l", "-e", "tls.stream", "-e", "ip.src", "-e", "ipv6.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.dstport")
	output, stderr := &cappedBuffer{limit: 32 << 20}, &cappedBuffer{limit: 65536}
	command.Stdout, command.Stderr = output, stderr
	if err := command.Run(); err != nil {
		return 0, fmt.Errorf("TLS stream discovery: %w", err)
	}
	return selectTLSStream(output.String(), id)
}

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
