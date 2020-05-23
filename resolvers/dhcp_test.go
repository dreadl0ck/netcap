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
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

type dhcpFingerprintResult struct {
	fingerprint string
	expected    string
}

func TestDHCPRemote(t *testing.T) {

	InitDHCPFingerprintAPIKey()

	fp := "1,33,3,6,12,15,28,51,58,59,119"

	r, err := http.NewRequest("GET", "https://api.fingerbank.org/api/v2/combinations/interrogate"+apiKey, bytes.NewReader([]byte("{\"dhcp_fingerprint\":\""+fp+"\"}")))
	if err != nil {
		t.Fatal(err)
	}

	// send request
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}

	// print response body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(data))

	// print status
	fmt.Println(resp.Status)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("api error")
	}

	// parse JSON response
	var res = new(DHCPResult)
	err = json.Unmarshal(data, res)
	if err != nil {
		t.Fatal(err)
	}

	// pretty print JSON api response
	var out bytes.Buffer
	err = json.Indent(&out, data, " ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(out.Bytes()))
}

func TestDHCPFingerprint(t *testing.T) {

	InitDHCPFingerprintDB()

	var tests = []dhcpFingerprintResult{
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
		if res != test.expected {
			t.Fatal("got", res, ", expected", test.expected)
		}
	}
}
