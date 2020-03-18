package resolvers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
)

var (
	ja3DB = make(map[string]*Ja3Summary)
)

type Ja3Summary struct {
	Desc string `json:"desc"`
	Hash string `json:"ja3_hash"`
}

// https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json

// LookupJa3 tries to locate the JA3(S) hash in the ja3 database and return a description
// access to the underlying map is not locked
// because after initialization the map is always read and never written again
func LookupJa3(hash string) string {
	if res, ok := ja3DB[hash]; ok {
		return res.Desc
	}
	return ""
}

// InitJa3Resolver loads the JSON mac DB into a map in memory
func InitJa3Resolver() {

	var sums int

	data, err := ioutil.ReadFile(filepath.Join(dataBaseSource, "ja3fingerprint.json"))
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {

		if len(line) == 0 {
			continue
		}

		// ignore comments
		if string(line[0]) == "#" {
			continue
		}

		var sum Ja3Summary
		if err := json.Unmarshal(line, &sum); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			log.Fatal("failed to unmarshal record:", err)
		}

		ja3DB[sum.Hash] = &sum
		sums++
	}

	if !Quiet {
		fmt.Println("loaded", sums, "JA3 summaries")
	}
}