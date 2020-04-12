package resolvers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"
	"strings"
)

var (
	localDNSNamesDB = make(map[string]string)
)

func InitLocalDNS() {

	var hosts int

	data, err := ioutil.ReadFile(filepath.Join(dataBaseSource, "hosts"))
	if err != nil {
		log.Println(err)
		return
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {

		if len(line) == 0 {
			continue
		}

		// ignore comments
		if string(line[0]) == "#" {
			continue
		}

		parts := strings.Split(string(line), "\t")
		if len(parts) == 2 {
			localDNSNamesDB[parts[0]] = parts[1]
		}

		hosts++
	}

	if !Quiet {
		fmt.Println("loaded", hosts, "local DNS hosts")
	}
}

// LookupDNSNames retrieves the DNS names associated with an IP addr
func LookupDNSNameLocal(ip string) string {

	// check if ip is valid
	i := net.ParseIP(ip)
	if i == nil {
		return ""
	}

	// lookup
	if res, ok := localDNSNamesDB[ip]; ok {
		return res
	}
	return ""

}
