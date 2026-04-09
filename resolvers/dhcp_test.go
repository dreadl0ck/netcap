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
	"log"
	"os"
	"testing"

	logging "github.com/dreadl0ck/netcap/internal/logger"
)

// init does not seem to be called for the compiled program,
// even this file is in the resolvers package scope.
// so we abuse it here to guarantee the logfile handles are initialized for all tests
func init() {
	// Create a temp directory for test logs
	tempDir, err := os.MkdirTemp("", "netcap-resolvers-test-*")
	if err != nil {
		log.Fatal("failed to create temp directory for test logs:", err)
	}

	resolverLog, _, err = logging.InitZapLogger(tempDir, "resolvers", true)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: sync on exit, move to a central place
}

type dhcpFingerprintResult struct {
	fingerprint string
	expected    string
}

func TestDHCPRemote(t *testing.T) {
	// TODO: fingerprint API seems to be having trouble atm
	return
	InitDHCPFingerprintAPIKey()
	// InitDHCPFingerprintDB()

	// Win XP
	re, err := LookupDHCPFingerprint("53,116,61,12,60,55", "MSFT 5.0", []string{"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) SCAgent"})
	if err != nil {
		t.Fatal(err)
	}
	if re.DeviceName != "Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2" {
		t.Fatal("expected Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2, got ", re.DeviceName)
	}

	// Win 10
	re, err = LookupDHCPFingerprint("53,61,12,81,60,55", "MSFT 5.0", []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML(comma) like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"})
	if err != nil {
		t.Fatal(err)
	}
	if re.DeviceName != "Operating System/Windows OS/Microsoft Windows Kernel 10.0" {
		t.Fatal("expected Operating System/Windows OS/Microsoft Windows Kernel 10.0, got ", re.DeviceName)
	}

	// SaveFingerprintDB()
}

func TestInitLocalDHCPFingerprintDB(t *testing.T) {
	// Skip this test if the build CSV file doesn't exist
	// The CSV file is generated during the database build process
	csvPath := DataBaseBuildPath + "/dhcp-fingerprints.csv"
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skipf("Skipping test: DHCP fingerprints CSV not found at %s (run 'zeus dbs-generate' to create)", csvPath)
	}
	initDHCPFingerprintDBCSV()
	SaveFingerprintDB()
}

func TestDHCPFingerprintLocal(t *testing.T) {
	// Skip this test if the database file doesn't exist
	dbPath := DataBaseFolderPath + "/" + dhcpDBFile
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Skipf("Skipping test: DHCP fingerprint database not found at %s", dbPath)
	}
	InitDHCPFingerprintDB()

	tests := []dhcpFingerprintResult{
		{
			fingerprint: "58,59,1,28,121,33,3,12,119,15,6,40,41,42,26,17,120,9,7,44,45,46,47",
			expected:    "VMware vCenter Server Appliance",
		},
		{
			fingerprint: "1,3,44,6,7,12,15,22,54,58,59,69,18,43,119,154",
			expected:    "HP Printer",
		},
		{
			fingerprint: "1,15,3,6,44,46,47,31,33,121,249,43,0,64,112",
			expected:    "Microsoft Windows Vista/7 or Server 2008 (Version 6.0)",
		},
		{
			fingerprint: "1,15,3,6,44,46,47,31,33,43,252",
			expected:    "Microsoft Windows 2000 (Version 5.0)",
		},
	}

	for _, test := range tests {
		res := LookupDHCPFingerprintLocal(test.fingerprint)
		if res == "" {
			t.Fatal("got no result")
		}
		if res != test.expected {
			t.Fatal("got", res, ", expected", test.expected)
		}
	}

	SaveFingerprintDB()
}
