package dbs

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type nvdAcquisition struct {
	Year          int    `json:"year"`
	SHA256        string `json:"sha256"`
	AcquiredAt    string `json:"acquired_at"`
	FeedTimestamp string `json:"feed_timestamp"`
	DeclaredCount int    `json:"declared_count"`
	IndexedCount  int    `json:"indexed_count"`
}

func nvdAcquisitionRevision(build string, inputs []NVDInput, counts map[string]int) (string, error) {
	var observations []nvdAcquisition
	for _, input := range inputs {
		path := filepath.Join(build, "nvdcve-2.0-"+strconv.Itoa(input.Year)+".json.gz")
		f, err := openRegular(path)
		if err != nil {
			return "", err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return "", err
		}
		dec := json.NewDecoder(io.LimitReader(gz, 1<<20))
		if token, err := dec.Token(); err != nil || token != json.Delim('{') {
			gz.Close()
			f.Close()
			return "", fmt.Errorf("invalid NVD feed header")
		}
		observation := nvdAcquisition{Year: input.Year, SHA256: input.SHA256, IndexedCount: counts[strconv.Itoa(input.Year)]}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				gz.Close()
				f.Close()
				return "", err
			}
			if key == "vulnerabilities" {
				break
			}
			var value json.RawMessage
			if err := dec.Decode(&value); err != nil {
				gz.Close()
				f.Close()
				return "", err
			}
			switch key {
			case "timestamp":
				if err := json.Unmarshal(value, &observation.FeedTimestamp); err != nil {
					gz.Close()
					f.Close()
					return "", err
				}
			case "totalResults":
				if err := json.Unmarshal(value, &observation.DeclaredCount); err != nil {
					gz.Close()
					f.Close()
					return "", err
				}
			}
		}
		gz.Close()
		f.Close()
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		observation.AcquiredAt = info.ModTime().UTC().Format(time.RFC3339Nano)
		sum, size, err := hashFile(path)
		if err != nil || sum != input.SHA256 || size != input.Size {
			return "", fmt.Errorf("NVD acquisition changed after indexing")
		}
		observations = append(observations, observation)
	}
	b, err := json.Marshal(observations)
	return ";acquisition=" + string(b), err
}

func validateNVDAcquisition(source SourceEvidence, counts map[string]int, maxAge int64) error {
	_, raw, ok := strings.Cut(source.Revision, ";acquisition=")
	if !ok {
		return fmt.Errorf("NVD source lacks acquisition observations")
	}
	var observations []nvdAcquisition
	if err := decodeJSON([]byte(raw), &observations); err != nil {
		return err
	}
	if len(observations) != len(source.NVDInputs) {
		return fmt.Errorf("NVD acquisition inventory mismatch")
	}
	now := time.Now().UTC()
	for i, observation := range observations {
		input := source.NVDInputs[i]
		if observation.Year != input.Year || observation.SHA256 != input.SHA256 || observation.IndexedCount != counts[strconv.Itoa(input.Year)] || observation.DeclaredCount != observation.IndexedCount || observation.DeclaredCount <= 0 {
			return fmt.Errorf("NVD year %d declared/indexed count mismatch", input.Year)
		}
		acquired, err := time.Parse(time.RFC3339Nano, observation.AcquiredAt)
		if err != nil || acquired.After(now.Add(5*time.Minute)) || now.Sub(acquired) > 24*time.Hour {
			return fmt.Errorf("NVD acquisition timestamp invalid or older than 24 hours")
		}
		if input.Year != now.Year() {
			continue
		}
		stamp, err := time.Parse(time.RFC3339Nano, observation.FeedTimestamp)
		if err != nil {
			stamp, err = time.Parse("2006-01-02T15:04:05.999999999", observation.FeedTimestamp)
		}
		if err != nil || stamp.After(now.Add(5*time.Minute)) || now.Sub(stamp) > time.Duration(maxAge)*time.Second {
			return fmt.Errorf("current NVD feed timestamp is invalid or exceeds policy age")
		}
	}
	return nil
}
