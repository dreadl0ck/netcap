package resolvers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

var (
	dnsWhitelist = make(map[string]struct{})
)

func InitDNSWhitelist() {

	var hosts int

	data, err := ioutil.ReadFile(filepath.Join(dataBaseSource, "top-1m.csv"))
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {

		if len(line) == 0 {
			continue
		}

		// ignore comments
		if string(line[0]) == "#" || string(line[0]) == "*" {
			continue
		}

		parts := strings.Split(string(line), ",")
		if len(parts) == 2 {
			dnsWhitelist[parts[1]] = struct{}{}
		}

		hosts++
	}

	if !Quiet {
		fmt.Println("loaded", hosts, "whitelisted DNS hosts")
	}
}

func getHost(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func IsWhitelisted(domain string) bool {
	if _, ok := dnsWhitelist[getHost(domain)]; ok {
		//log.Println(domain, "is whitelisted")
		return true
	}
	//log.Println(domain, "is NOT whitelisted")
	return false
}