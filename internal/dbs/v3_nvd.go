package dbs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func nvdInputURL(year int) string {
	return fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz", year)
}

func validateNVDInputs(inputs []NVDInput) error {
	if len(inputs) == 0 {
		return fmt.Errorf("missing per-year NVD snapshot inventory")
	}
	for i, input := range inputs {
		if input.Year < 2002 || input.Year > 9999 || input.URL != nvdInputURL(input.Year) || !validDigest(input.SHA256) || input.Size <= 0 || input.Size > maxReleaseBytes {
			return fmt.Errorf("invalid NVD year snapshot")
		}
		if i > 0 && input.Year != inputs[i-1].Year+1 {
			return fmt.Errorf("NVD year inventory is not contiguous")
		}
	}
	return nil
}

func nvdInputDigest(inputs []NVDInput) string {
	var inventory strings.Builder
	for _, input := range inputs {
		fmt.Fprintf(&inventory, "%d %s\n", input.Year, input.SHA256)
	}
	return digest([]byte(inventory.String()))
}

// Freeze the exact bytes the indexer will read. Source paths are never reopened
// for indexing, so replacing an upstream input mid-build cannot change coverage.
func freezeNVDInputs(from, to string, start, end int) ([]NVDInput, error) {
	if err := os.Mkdir(to, 0o700); err != nil {
		return nil, err
	}
	var inputs []NVDInput
	for year := start; year <= end; year++ {
		name := fmt.Sprintf("nvdcve-2.0-%d.json.gz", year)
		input, err := freezeInput(filepath.Join(from, name), filepath.Join(to, name))
		if err != nil {
			return nil, fmt.Errorf("required NVD year %d: %w", year, err)
		}
		inputs = append(inputs, NVDInput{Year: year, URL: nvdInputURL(year), SHA256: input.SHA256, Size: input.Size})
	}
	return inputs, validateNVDInputs(inputs)
}

func freezeInput(from, to string) (ReleaseFile, error) {
	in, err := openRegular(from)
	if err != nil {
		return ReleaseFile{}, err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return ReleaseFile{}, err
	}
	if before.Size() <= 0 || before.Size() > maxReleaseBytes {
		return ReleaseFile{}, fmt.Errorf("invalid input size")
	}
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ReleaseFile{}, err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(in, before.Size()+1))
	if err != nil {
		out.Close()
		return ReleaseFile{}, err
	}
	after, err := in.Stat()
	if err != nil || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		out.Close()
		return ReleaseFile{}, fmt.Errorf("input changed during freeze")
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return ReleaseFile{}, err
	}
	if err := out.Chmod(0o400); err != nil {
		out.Close()
		return ReleaseFile{}, err
	}
	if err := out.Close(); err != nil {
		return ReleaseFile{}, err
	}
	return ReleaseFile{Path: filepath.Base(to), SHA256: hex.EncodeToString(hash.Sum(nil)), Size: n}, nil
}
