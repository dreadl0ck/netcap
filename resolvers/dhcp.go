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
	"github.com/dreadl0ck/netcap/utils"
	deadlock "github.com/sasha-s/go-deadlock"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	dhcpFingerprintDB = make(map[string]*DHCPResult)
	dhcpFingerprintMu deadlock.Mutex

	dhcpDBinitialized bool
	dhcpDBFile = "dhcp-fingerprints.json"
)

// TODO: use a boltDB?
func SaveFingerprintDB() {

	if !dhcpDBinitialized {
		return
	}

	data, err := json.Marshal(dhcpFingerprintDB)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(filepath.Join(DataBaseSource, dhcpDBFile))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		log.Fatal(err)
	}

	utils.DebugLog.Println("saved fingerprint db with", len(dhcpFingerprintDB), "items")
}

// Fingerbank.org API
// endpoint: https://api.fingerbank.org
//
// Combinations
// GET /api/v2/combinations/interrogate
// POST /api/v2/combinations/interrogate
//
// Devices
// GET /api/v2/devices/:id
// GET /api/v2/devices/:id/is_a/:other_device_id
// GET /api/v2/devices/base_info
//
// Oui
// GET /api/v2/oui/:oui/to_device_id
//
// Static
// GET /api/v2/download/db
//
// Users
// GET /api/v2/devices/:account_key

var apiKey string

func InitDHCPFingerprintAPIKey() {

	k := os.Getenv("FINGERPRINT_API_KEY")

	if k != "" {
		apiKey = "?key=" + k
	} else {
		data, err := ioutil.ReadFile(filepath.Join("/usr/local/etc/netcap", "fingerprint_api_key"))
		if err != nil {
			log.Fatal(err)
		}
		apiKey = "?key=" + string(data)
	}

	dhcpDBinitialized = true
}

// DHCPResult is the data structure returned from the fingerbank.org service
type DHCPResult struct {
	Device struct {
		CreatedAt time.Time `json:"created_at"`
		ID        int       `json:"id"`
		Name      string    `json:"name"`
		ParentID  int       `json:"parent_id"`
		Parents   []struct {
			CreatedAt       time.Time   `json:"created_at"`
			ID              int         `json:"id"`
			Name            string      `json:"name"`
			ParentID        int         `json:"parent_id"`
			UpdatedAt       time.Time   `json:"updated_at"`
			VirtualParentID interface{} `json:"virtual_parent_id"`
		} `json:"parents"`
		UpdatedAt       time.Time   `json:"updated_at"`
		VirtualParentID interface{} `json:"virtual_parent_id"`
	} `json:"device"`
	DeviceName string `json:"device_name"`
	Score      int    `json:"score"`
	Version    string `json:"version"`
}

type DHCPFingerprintRequest struct {
	Fingerprint string   `json:"dhcp_fingerprint"`
	Vendor      string   `json:"dhcp_vendor"`
	UserAgents  []string `json:"user_agents"`
}

// LookupDHCPFingerprint retrieves the data associated with an DHCP fingerprint
func LookupDHCPFingerprint(fp string, vendor string, userAgents []string) (*DHCPResult, error) {

	if len(fp) == 0 {
		return nil, nil
	}

	// check if fp has already been resolved
	dhcpFingerprintMu.Lock()
	if res, ok := dhcpFingerprintDB[fp]; ok {
		dhcpFingerprintMu.Unlock()
		return res, nil
	}
	dhcpFingerprintMu.Unlock()

	// create API request
	req := &DHCPFingerprintRequest{
		Fingerprint: fp,
		Vendor:      vendor,
		UserAgents:  userAgents,
	}
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// build
	r, err := http.NewRequest("GET", "https://api.fingerbank.org/api/v2/combinations/interrogate"+apiKey, bytes.NewReader(reqData))
	if err != nil {
		return nil, err
	}

	// send request
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}

	// read response body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// check status
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected status code from fingerbank API: " + resp.Status)
	}

	// parse JSON response
	var res = new(DHCPResult)
	err = json.Unmarshal(data, res)
	if err != nil {
		return nil, err
	}

	// pretty print JSON api response
	//var out bytes.Buffer
	//err = json.Indent(&out, data, " ", "  ")
	//if err != nil {
	//	return nil, err
	//}
	//fmt.Println(string(out.Bytes()))

	// add result to map
	dhcpFingerprintMu.Lock()
	dhcpFingerprintDB[fp] = res
	dhcpFingerprintMu.Unlock()

	return res, nil
}

// InitDHCPFingerprintDB initializes the DHCP fingerprint database from the JSON encoded mapping persisted on disk
func InitDHCPFingerprintDB() {

	dhcpDBinitialized = true

	data, err := ioutil.ReadFile(filepath.Join(DataBaseSource, dhcpDBFile))
	if err != nil {
		log.Fatal(err)
	}

	dhcpFingerprintMu.Lock()
	err = json.Unmarshal(data, &dhcpFingerprintDB)
	if err != nil {
		log.Fatal(err)
	}
	dhcpFingerprintMu.Unlock()

	if !Quiet {
		dhcpFingerprintMu.Lock()
		utils.DebugLog.Println("loaded", len(dhcpFingerprintDB), "DHCP fingerprints")
		dhcpFingerprintMu.Unlock()
	}
}

// InitDHCPFingerprintDBCSV initializes the DHCP fingerprint database from a CSV formatted source
// initial database source: https://raw.githubusercontent.com/karottc/fingerbank/master/upstream/startup/fingerprints.csv
func InitDHCPFingerprintDBCSV() {

	dhcpDBinitialized = true

	var fingerprints int

	data, err := ioutil.ReadFile(filepath.Join(DataBaseSource, "dhcp-fingerprints.csv"))
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
			dhcpFingerprintDB[parts[0]] = &DHCPResult{
				DeviceName: strings.TrimSpace(parts[1]),
			}
		}

		fingerprints++
	}
	dhcpFingerprintMu.Unlock()

	if !Quiet {
		utils.DebugLog.Println("loaded", fingerprints, "DHCP fingerprints")
	}
}

// LookupDHCPFingerprintLocal retrieves the data associated with an DHCP fingerprint
func LookupDHCPFingerprintLocal(fp string) *DHCPResult {

	if len(fp) == 0 {
		return nil
	}

	// check if ip has already been resolved
	dhcpFingerprintMu.Lock()
	if res, ok := dhcpFingerprintDB[fp]; ok {
		dhcpFingerprintMu.Unlock()
		return res
	}
	dhcpFingerprintMu.Unlock()

	return nil
}
