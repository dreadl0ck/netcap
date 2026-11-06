package dbs

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const hasshTransformation = "netcap-hassh-v1: parse pinned upstream hash/banner/percentage lines, sort hashes, preserve banner and likelihood strings as legacy JSON"

type hasshSoftware struct {
	Name       string `json:"name"`
	Likelihood string `json:"likelyhood"`
}
type hasshRecord struct {
	Hash     string          `json:"hash"`
	Software []hasshSoftware `json:"softwares"`
}

func convertHASSH(in string, d *datasource, base string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	var records []hasshRecord
	seen := map[string]bool{}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		hash, rest, ok := strings.Cut(line, " ")
		decoded, err := hex.DecodeString(hash)
		if !ok || err != nil || len(decoded) != 16 || seen[hash] {
			return fmt.Errorf("invalid or duplicate HASSH fingerprint")
		}
		seen[hash] = true
		record := hasshRecord{Hash: hash}
		for _, entry := range strings.Split(rest, " || ") {
			index := strings.LastIndex(entry, " (")
			if index < 1 || !strings.HasSuffix(entry, ")") {
				return fmt.Errorf("invalid HASSH banner likelihood")
			}
			percent := entry[index+2 : len(entry)-1]
			n, err := strconv.Atoi(strings.TrimSuffix(percent, "+"))
			if err != nil || n < 0 || n > 100 {
				return fmt.Errorf("invalid HASSH likelihood")
			}
			record.Software = append(record.Software, hasshSoftware{entry[:index], percent})
		}
		records = append(records, record)
	}
	if err := scan.Err(); err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("empty HASSH catalogue")
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Hash < records[j].Hash })
	b, err := json.Marshal(records)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(base, "dbs", d.name), b, 0o644)
}
