package util

import (
	"fmt"
)

var sources = []string{
	"http://s3.amazonaws.com/alexa-static/top-1m.csv.zip",
	"https://raw.githubusercontent.com/tobie/ua-parser/master/regexes.yaml",
	"https://svn.nmap.org/nmap/nmap-service-probes",
	"https://macaddress.io/database-download",
	"https://ja3er.com/getAllHashesJson",
	"https://ja3er.com/getAllUasJson",
	"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv",
	"https://raw.githubusercontent.com/0x4D31/hassh-utils/master/hasshdb",
	"https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json",
	"https://raw.githubusercontent.com/karottc/fingerbank/master/upstream/startup/fingerprints.csv",
	"https://github.com/AliasIO/wappalyzer/blob/master/src/technologies.json",
}

func generateDBs() {
	for _, s := range sources {
		// TODO: fetch resource and apply preprocessing if necessary
		fmt.Println("TODO: fetch", s)
	}
}

// TODO: automate generation of cmsdb.json from the technologies.json file
type WebTechnologies struct {
	Schema     string `json:"$schema"`
	Categories struct {
		Num1 struct {
			Name     string `json:"name"`
			Priority int    `json:"priority"`
		} `json:"1"`
	} `json:"categories"`
	Technologies struct {
		OneCBitrix struct {
			Cats        []int  `json:"cats"`
			Description string `json:"description"`
			Headers     struct {
				SetCookie   string `json:"Set-Cookie"`
				XPoweredCMS string `json:"X-Powered-CMS"`
			} `json:"headers"`
			HTML    string `json:"html"`
			Icon    string `json:"icon"`
			Implies string `json:"implies"`
			Scripts string `json:"scripts"`
			Website string `json:"website"`
		} `json:"1C-Bitrix"`
	} `json:"technologies"`
}