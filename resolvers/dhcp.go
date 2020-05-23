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
	"github.com/dreadl0ck/netcap/utils"
	deadlock "github.com/sasha-s/go-deadlock"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

var (
	dhcpFingerprintDB        = make(map[string]string)
	dhcpFingerprintMu        deadlock.Mutex
)

// InitDHCPFingerprintDB initializes the DHCP fingerprint database
// initial database source: https://raw.githubusercontent.com/karottc/fingerbank/master/upstream/startup/fingerprints.csv
func InitDHCPFingerprintDB() {

	var fingerprints int

	data, err := ioutil.ReadFile(filepath.Join(dataBaseSource, "dhcp-fingerprints.csv"))
	if err != nil {
		log.Fatal(err)
	}

	dhcpFingerprintMu.Lock()
	for _, line := range bytes.Split(data, []byte{'\n'}) {

		if len(line) == 0 {
			continue
		}

		// ignore comments
		if string(line[0]) == "#" {
			continue
		}

		parts := strings.Split(string(line), "|")
		if len(parts) == 2 {
			dhcpFingerprintDB[parts[0]] = strings.TrimSpace(parts[1])
		}

		fingerprints++
	}
	dhcpFingerprintMu.Unlock()

	if !Quiet {
		utils.DebugLog.Println("loaded", fingerprints, "DHCP fingerprints")
	}
}

// LookupDHCPFingerprintLocal retrieves the data associated with an DHCP fingerprint
func LookupDHCPFingerprintLocal(fp string) string {

	if len(fp) == 0 {
		return ""
	}

	// check if ip has already been resolved
	dhcpFingerprintMu.Lock()
	if res, ok := dhcpFingerprintDB[fp]; ok {
		dhcpFingerprintMu.Unlock()
		return res
	}
	dhcpFingerprintMu.Unlock()

	return ""
}
