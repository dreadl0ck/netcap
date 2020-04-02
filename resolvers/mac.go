package resolvers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
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

// MacSummary contains infos about a specific OUI
type MacSummary struct {
	OUI         string `json:"oui"`
	IsPrivate   bool   `json:"isPrivate"`
	CompanyName string `json:"companyName"`
	CountryCode string `json:"countryCode"`
}

var macDB = make(map[string]MacSummary)

// InitMACResolver loads the JSON mac DB into a map in memory
func InitMACResolver() {

	var sums int

	data, err := ioutil.ReadFile(filepath.Join(dataBaseSource, "macaddress.io-db.json"))
	if err != nil {
		log.Println(err)
		return
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {

		if len(line) == 0 {
			continue
		}

		var sum MacSummary
		if err := json.Unmarshal(line, &sum); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			log.Fatal("failed to unmarshal record:", err)
		}

		macDB[sum.OUI] = sum
		sums++
	}
	if !Quiet {
		fmt.Println("loaded", sums, "OUI summaries")
	}
}

// LookupManufacturer resolves a MAC addr to the manufacturer
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
