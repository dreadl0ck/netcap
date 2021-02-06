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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/env"
)

var (
	dhcpFingerprintDB = make(map[string]*dhcpResult)
	dhcpFingerprintMu sync.Mutex

	dhcpDBinitialized bool
	dhcpDBFile        = "dhcp-fingerprints.json"

	errFingerbankQueryFailed = errors.New("fingerbank query failed")
)

// SaveFingerprintDB will persist the fingerprint database on disk.
// TODO: use a boltDB?
func SaveFingerprintDB() {
	if !dhcpDBinitialized {
		return
	}

	data, err := json.Marshal(dhcpFingerprintDB)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(filepath.Join(DataBaseFolderPath, dhcpDBFile))
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil {
			resolverLog.Error("failed to close file handle:", zap.Error(errClose))
		}
	}()

	_, err = f.Write(data)
	if err != nil {
		log.Fatal(err)
	}

	resolverLog.Info("saved fingerprint db", zap.Int("items", len(dhcpFingerprintDB)))
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

// InitDHCPFingerprintAPIKey initializes the DHCP fingerprinting API key
func InitDHCPFingerprintAPIKey() {
	k := os.Getenv(env.FingerbankAPIKey)

	if k != "" {
		apiKey = "?key=" + k
	} else {
		data, err := ioutil.ReadFile(filepath.Join("/usr", "local", "etc", "netcap", "fingerprint_api_key"))
		if err != nil {
			log.Fatal(err)
		}
		apiKey = "?key=" + string(data)
	}

	dhcpDBinitialized = true
}

// dhcpResult is the data structure returned from the fingerbank.org service.
type dhcpResult struct {
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

// dhcpFingerprintRequest models a request for a DHCP fingerprint query.
type dhcpFingerprintRequest struct {
	Fingerprint string   `json:"dhcp_fingerprint"`
	Vendor      string   `json:"dhcp_vendor"`
	UserAgents  []string `json:"user_agents"`
}

// LookupDHCPFingerprint retrieves the data associated with an DHCP fingerprint.
func LookupDHCPFingerprint(fp, vendor string, userAgents []string) (*dhcpResult, error) {
	if fp == "" {
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
	req := &dhcpFingerprintRequest{
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

	defer func() {
		errClose := resp.Body.Close()
		if errClose != nil {
			resolverLog.Error("failed to close DHCP fingerprint API response body:", zap.Error(errClose))
		}
	}()

	// read response body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// check status
	if resp.StatusCode != http.StatusOK {
		fmt.Println(string(data))
		return nil, fmt.Errorf("unexpected status code from fingerbank API: %s %w", resp.Status, errFingerbankQueryFailed)
	}

	// parse JSON response
	res := new(dhcpResult)

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

// InitDHCPFingerprintDB initializes the DHCP fingerprint database from the JSON encoded mapping persisted on disk.
func InitDHCPFingerprintDB() {
	dhcpDBinitialized = true

	data, err := ioutil.ReadFile(filepath.Join(DataBaseFolderPath, dhcpDBFile))
	if err != nil {
		log.Fatal(err)
	}

	dhcpFingerprintMu.Lock()

	err = json.Unmarshal(data, &dhcpFingerprintDB)
	if err != nil {
		log.Fatal(err)
	}

	dhcpFingerprintMu.Unlock()

	if !quiet {
		dhcpFingerprintMu.Lock()
		resolverLog.Info("loaded DHCP fingerprints", zap.Int("items", len(dhcpFingerprintDB)))
		dhcpFingerprintMu.Unlock()
	}
}

// initDHCPFingerprintDBCSV initializes the DHCP fingerprint database from a CSV formatted source
// initial database source: https://raw.githubusercontent.com/karottc/fingerbank/master/upstream/startup/fingerprints.csv
func initDHCPFingerprintDBCSV() {
	dhcpDBinitialized = true

	var fingerprints int

	data, err := ioutil.ReadFile(filepath.Join(DataBaseBuildPath, "dhcp-fingerprints.csv"))
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
			dhcpFingerprintDB[parts[0]] = &dhcpResult{
				DeviceName: strings.TrimSpace(parts[1]),
			}
		}

		fingerprints++
	}
	dhcpFingerprintMu.Unlock()

	if !quiet {
		resolverLog.Info("loaded DHCP fingerprints", zap.Int("items", fingerprints))
	}
}

// lookupDHCPFingerprintLocal retrieves the data associated with an DHCP fingerprint.
func lookupDHCPFingerprintLocal(fp string) *dhcpResult {
	if fp == "" {
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
