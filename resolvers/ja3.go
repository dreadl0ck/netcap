/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package resolvers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

var ja3DB = make(map[string]*ja3Summary)

// ja3Summary models the Trisul ja3DB json structure
// https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json
// the format is also compatible with ja3er.com, but comes as an array of records
// whereas trisul uses newline delimited summary structures.
type ja3Summary struct {
	Desc string `json:"desc"`
	Hash string `json:"ja3_hash"`
}

// ja3UserAgent DB from ja3er.com
// entry example: {"User-Agent": "-", "Count": 1, "md5": "e05744a5eb9f795f148ed77cb471f725", "Last_seen": "2019-11-19 21:10:04"},.
type ja3UserAgent struct {
	UserAgent string `json:"User-Agent"`
	Hash      string `json:"md5"`
}

// LookupJa3 tries to locate the JA3(S) hash in the ja3 database and return a description
// access to the underlying map is not locked
// because after initialization the map is always read and never written again.
func LookupJa3(hash string) string {
	if res, ok := ja3DB[hash]; ok {
		return res.Desc
	}
	return ""
}

// initJa3Resolver loads the JSON mac DB into a map in memory.
func initJa3Resolver() {
	// read database dir
	files, err := ioutil.ReadDir(DataBaseFolderPath)
	if err != nil {
		log.Println(err)

		return
	}

	// iterate over results
	for _, f := range files { // only process files that start with ja3 and have the JSON file extension
		if !strings.HasPrefix(f.Name(), "ja3") || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}

		// read file contents into memory
		data, errRead := ioutil.ReadFile(filepath.Join(DataBaseFolderPath, f.Name()))
		if errRead != nil {
			log.Println(errRead)

			continue
		}

		// decide which parser to use
		switch f.Name() {
		case "ja3UserAgents.json":
			// TODO: the user agent list grew to over half a million entries
			// parsing them everytime on startup is no longer feasible
			// populate a bleve db in advance instead...
			//parseUserAgents(data, f)
		case "ja3erDB.json":
			parseSummariesArray(data, f)
		default:
			parseSummaries(data, f)
		}
	}

	resolverLog.Info("loaded JA3 summaries", zap.Int("total", len(ja3DB)))
}

/*
 * Utils
 */

func addToJa3DB(sum ja3Summary, updated *int, sums *int) {
	if e, ok := ja3DB[sum.Hash]; ok {
		if !strings.Contains(e.Desc, sum.Desc) {
			e.Desc += "; " + sum.Desc
			*updated++
		}
	} else {
		ja3DB[sum.Hash] = &ja3Summary{
			Desc: sum.Desc,
			Hash: sum.Hash,
		}
		*sums++
	}
}

func parseUserAgents(data []byte, f os.FileInfo) {
	var (
		sums       = 0
		updated    = 0
		userAgents []ja3UserAgent
	)

	if err := json.Unmarshal(data, &userAgents); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return
		}
		log.Println("failed to unmarshal record:", err, f.Name())
		return
	}

	for _, sum := range userAgents {
		if e, ok := ja3DB[sum.Hash]; ok {
			if !strings.Contains(e.Desc, sum.UserAgent) {
				e.Desc += "; " + sum.UserAgent
				updated++
			}
		} else {
			ja3DB[sum.Hash] = &ja3Summary{
				Desc: sum.UserAgent,
				Hash: sum.Hash,
			}
			sums++
		}
	}

	if !quiet {
		resolverLog.Info("updated JA3 summaries",
			zap.String("source", f.Name()),
			zap.Int("new", sums),
			zap.Int("updated", updated),
		)
	}
}

func parseSummariesArray(data []byte, f os.FileInfo) {
	var (
		sums      = 0
		updated   = 0
		summaries []ja3Summary
	)

	if err := json.Unmarshal(data, &summaries); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return
		}
		log.Println("failed to unmarshal record:", err, f.Name())
		return
	}

	for _, sum := range summaries {
		addToJa3DB(sum, &updated, &sums)
	}

	if !quiet {
		resolverLog.Info("updated JA3 summaries",
			zap.String("source", f.Name()),
			zap.Int("new", sums),
			zap.Int("updated", updated),
		)
	}
}

func parseSummaries(data []byte, f os.FileInfo) {
	var (
		sums    = 0
		updated = 0
	)

	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}

		// ignore comments
		if string(line[0]) == "#" {
			continue
		}

		var sum ja3Summary
		if err := json.Unmarshal(line, &sum); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			log.Println("failed to unmarshal record:", err, f.Name())
			continue
		}

		addToJa3DB(sum, &updated, &sums)
	}
	if !quiet {
		resolverLog.Info("updated JA3 summaries",
			zap.String("source", f.Name()),
			zap.Int("new", sums),
			zap.Int("updated", updated),
		)
	}
}
