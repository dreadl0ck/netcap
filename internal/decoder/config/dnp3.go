package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// DNP3Point names one point on one outstation.
//
// A DNP3 index is not an address. Group 12 index 7 is a particular feeder only
// because that outstation's device profile says so, and two vendors do not
// share a map. Without the profile a capture shows that a breaker moved but not
// which one.
type DNP3Point struct {
	Outstation int32
	Group      int32
	Index      int64
}

var (
	dnp3PointsOnce sync.Once
	dnp3Points     map[DNP3Point]string
)

// ValidateDNP3PointMap parses the point map so a bad file fails decoder
// initialisation rather than silently leaving every point unnamed.
func (c *Config) ValidateDNP3PointMap() error {
	if c.DNP3PointMap == "" {
		return nil
	}

	_, err := parseDNP3PointMap(c.DNP3PointMap)

	return err
}

// DNP3PointName returns the configured name for a point, or "".
func (c *Config) DNP3PointName(outstation, group int32, index int64) string {
	if c == nil || c.DNP3PointMap == "" {
		return ""
	}

	dnp3PointsOnce.Do(func() {
		points, err := parseDNP3PointMap(c.DNP3PointMap)
		if err != nil {
			return
		}

		dnp3Points = points
	})

	return dnp3Points[DNP3Point{Outstation: outstation, Group: group, Index: index}]
}

// parseDNP3PointMap reads a CSV of outstation,group,index,name. Lines beginning
// with # and blank lines are ignored.
//
// The outstation is the DNP3 link address, not an IP: one address can be
// reached over several paths, and an IP can front several outstations.
func parseDNP3PointMap(path string) (map[DNP3Point]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("DNP3 point map: %w", err)
	}
	defer file.Close()

	points := make(map[DNP3Point]string)
	scanner := bufio.NewScanner(file)

	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		fields := strings.SplitN(text, ",", 4)
		if len(fields) != 4 {
			return nil, fmt.Errorf("DNP3 point map line %d: want outstation,group,index,name", line)
		}

		// Each column is validated at its own wire width: a link address is
		// 16 bits, an object group 8, and a point index 32. Parsing at the
		// exact width is what makes the conversions below total.
		outstation, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("DNP3 point map line %d: %q is not a 16-bit link address", line, fields[0])
		}

		group, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("DNP3 point map line %d: %q is not an 8-bit object group", line, fields[1])
		}

		index, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("DNP3 point map line %d: %q is not a 32-bit point index", line, fields[2])
		}

		name := strings.TrimSpace(fields[3])
		if name == "" {
			return nil, fmt.Errorf("DNP3 point map line %d: empty name", line)
		}

		key := DNP3Point{Outstation: int32(outstation), Group: int32(group), Index: int64(index)}
		if prior, ok := points[key]; ok && prior != name {
			return nil, fmt.Errorf("DNP3 point map line %d: point already named %q", line, prior)
		}

		points[key] = name
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("DNP3 point map: %w", err)
	}

	return points, nil
}
