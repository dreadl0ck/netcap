package networkdetect

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

const StatsFilename = "NetworkDetection.json"

func ReadStats(path string) (Stats, error) {
	var s Stats
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil {
		return s, err
	} else if info.Size() > 65536 {
		return s, errors.New("detection status exceeds 64 KiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	if err := d.Decode(&s); err != nil {
		return s, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return s, errors.New("invalid detection status framing")
	}
	if s.Schema != 1 || s.Keys < 0 || s.Keys > 100000 || s.Flows < 0 || s.Flows > 10000 || s.Indicators < 0 || s.Indicators > 4096 || len(s.Error) > 4096 {
		return s, errors.New("invalid detection status")
	}
	return s, nil
}
