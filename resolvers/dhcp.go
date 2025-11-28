/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

	resolverLog.Debug("attempting DHCP fingerprint lookup in local database",
		zap.String("fingerprint", fp),
		zap.String("vendor", vendor),
	)

	// check if fp has already been resolved
	dhcpFingerprintMu.Lock()
	if res, ok := dhcpFingerprintDB[fp]; ok {
		dhcpFingerprintMu.Unlock()
		resolverLog.Debug("DHCP fingerprint found in local database",
			zap.String("fingerprint", fp),
			zap.String("device", res.DeviceName),
		)
		return res, nil
	}
	dhcpFingerprintMu.Unlock()

	resolverLog.Info("DHCP fingerprint not found in local database, querying Fingerbank API",
		zap.String("fingerprint", fp),
		zap.String("vendor", vendor),
	)

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

	resolverLog.Info("successfully resolved DHCP fingerprint via Fingerbank API",
		zap.String("fingerprint", fp),
		zap.String("device", res.DeviceName),
		zap.Int("score", res.Score),
	)

	return res, nil
}

// InitDHCPFingerprintDB initializes the DHCP fingerprint database from the JSON encoded mapping persisted on disk.
func InitDHCPFingerprintDB() {
	dhcpDBinitialized = true

	dbPath := filepath.Join(DataBaseFolderPath, dhcpDBFile)
	resolverLog.Info("loading DHCP fingerprint database",
		zap.String("path", dbPath),
	)

	data, err := ioutil.ReadFile(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	dhcpFingerprintMu.Lock()

	err = json.Unmarshal(data, &dhcpFingerprintDB)
	if err != nil {
		log.Fatal(err)
	}

	dhcpFingerprintMu.Unlock()

	dhcpFingerprintMu.Lock()
	resolverLog.Info("loaded DHCP fingerprints", zap.Int("items", len(dhcpFingerprintDB)))
	dhcpFingerprintMu.Unlock()
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

	resolverLog.Info("loaded DHCP fingerprints", zap.Int("items", fingerprints))
}

// LookupDHCPFingerprintLocal retrieves the data associated with an DHCP fingerprint from the local database.
func LookupDHCPFingerprintLocal(fp string) string {
	if fp == "" {
		return ""
	}

	resolverLog.Info("attempting DHCP fingerprint lookup in local database",
		zap.String("fingerprint", fp),
	)

	// check if ip has already been resolved
	dhcpFingerprintMu.Lock()
	if res, ok := dhcpFingerprintDB[fp]; ok {
		dhcpFingerprintMu.Unlock()
		if res != nil {
			resolverLog.Debug("DHCP fingerprint found in local database",
				zap.String("fingerprint", fp),
				zap.String("device", res.DeviceName),
			)
			return res.DeviceName
		}
	}
	dhcpFingerprintMu.Unlock()

	resolverLog.Debug("DHCP fingerprint not found in local database",
		zap.String("fingerprint", fp),
	)

	return ""
}
