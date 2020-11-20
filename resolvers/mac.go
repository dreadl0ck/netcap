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
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// https://macaddress.io/database/macaddress.io-db.json
// Single record:
// {
//     "oui":"08:EC:F5",
//     "isPrivate":false,
//     "companyName":"Cisco Systems, Inc",
//     "companyAddress":"80 West Tasman Drive San Jose CA 94568",
//     "countryCode":"US",
//     "assignmentBlockSize":"MA-L",
//     "dateCreated":"2018-11-09",
//     "dateUpdated":"2018-11-09"
// }

// macSummary contains infos about a specific OUI.
type macSummary struct {
	OUI         string `json:"oui"`
	IsPrivate   bool   `json:"isPrivate"`
	CompanyName string `json:"companyName"`
	CountryCode string `json:"countryCode"`
}

var macDB = make(map[string]macSummary)

// initMACResolver loads the JSON mac DB into a map in memory.
func initMACResolver() {
	var sums int

	data, err := ioutil.ReadFile(filepath.Join(DataBaseFolderPath, "macaddress.io-db.json"))
	if err != nil {
		log.Println(err)
		return
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}

		var sum macSummary
		if err = json.Unmarshal(line, &sum); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			log.Println("failed to unmarshal record:", err, string(line), "in macaddress.io-db.json")
			continue
		}

		macDB[sum.OUI] = sum
		sums++
	}
	if !quiet {
		resolverLog.Info("loaded OUI summaries",
			zap.Int("total", sums),
		)
	}
}

// LookupManufacturer resolves a MAC addr to the manufacturer.
func LookupManufacturer(mac string) string {
	if len(mac) < 8 {
		return ""
	}

	oui := strings.ToUpper(mac[:8])

	if res, ok := macDB[oui]; ok {
		return res.CompanyName
	}

	return ""
}
