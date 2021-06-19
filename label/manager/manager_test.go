/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2019 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package manager

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"testing"
	"time"
)

// mock audit record for testing
type testAuditRecord struct {

	// properties used to determine which label to choose.
	time time.Time
	src  string
	dst  string

	// expected label
	expected string

	// human readable description for scenario
	description string
}

// implement audit record interface
// the only relevant three functions for these tests are:

func (t *testAuditRecord) Time() int64 {
	return t.time.UnixNano()
}

func (t *testAuditRecord) Src() string {
	return t.src
}

func (t *testAuditRecord) Dst() string {
	return t.dst
}

func (t *testAuditRecord) CSVRecord() []string                       { return nil }
func (t *testAuditRecord) CSVHeader() []string                       { return nil }
func (t *testAuditRecord) Inc()                                      {}
func (t *testAuditRecord) JSON() (string, error)                     { return "", nil }
func (t *testAuditRecord) SetPacketContext(ctx *types.PacketContext) {}
func (t *testAuditRecord) Encode() []string                          { return nil }
func (t *testAuditRecord) Analyze()                                  {}
func (t *testAuditRecord) NetcapType() types.Type                    { return 0 }

const timeFormat = "Monday-02-01-2006 15:04"

func date(str string) time.Time {
	t, err := time.ParseInLocation(timeFormat, str, Location)
	if err != nil {
		log.Fatal(err)
	}
	return t
}

func TestLabeling(t *testing.T) {
	debug := false
	m := NewLabelManager(
		false,
		debug,
		false,
		false,
		5*time.Minute)
	m.Init("../configs/test.yml")

	var records = []types.AuditRecord{

		// first attack
		&testAuditRecord{
			time:        date("Thursday-15-02-2018 8:00"),
			src:         "127.0.0.1",
			dst:         "127.0.0.1",
			expected:    "normal",
			description: "event out of the time range should be ignored",
		},
		&testAuditRecord{
			time:        date("Thursday-15-02-2018 10:00"),
			src:         "127.0.0.1",
			dst:         "127.0.0.1",
			expected:    "normal",
			description: "event from the first attack's time range but no attacker or victim IP",
		},
		&testAuditRecord{
			time:        date("Thursday-15-02-2018 10:00"),
			src:         "18.217.21.148",
			dst:         "127.0.0.1",
			expected:    "denial-of-service",
			description: "event from the first attack's time range with attacker ip",
		},

		// second attack
		&testAuditRecord{
			time:        date("Thursday-22-02-2018 11:00"),
			src:         "18.218.115.60",
			dst:         "18.218.83.150",
			expected:    "bruteforce",
			description: "event from the second attack's time range with attacker to victim communication",
		},
		&testAuditRecord{
			time:        date("Thursday-22-02-2018 11:00"),
			src:         "18.218.83.150",
			dst:         "18.218.115.60",
			expected:    "bruteforce",
			description: "event from the second attack's time range with victim to attacker communication",
		},
		&testAuditRecord{
			time:        date("Thursday-22-02-2018 11:00"),
			src:         "18.218.83.150",
			dst:         "18.218.83.151",
			expected:    "normal",
			description: "event from the second attack's time range with victim to non-attacker communication",
		},

		// third attack
		&testAuditRecord{
			time:        date("Thursday-01-03-2018 14:30"),
			src:         "13.58.225.34",
			dst:         "172.31.69.13",
			expected:    "infiltration",
			description: "event from the third attack's time range with attacker to victim communication",
		},
		&testAuditRecord{
			time:        date("Thursday-01-03-2018 14:30"),
			src:         "18.216.254.154",
			dst:         "13.58.225.34",
			expected:    "infiltration",
			description: "event from the third attack's time range with victim to attacker communication",
		},
		&testAuditRecord{
			time:        date("Thursday-01-03-2018 14:30"),
			src:         "172.31.69.13",
			dst:         "172.31.69.14",
			expected:    "infiltration",
			description: "event from the third attack's time range with victim to non-attacker communication",
		},

		// test time range edges
		&testAuditRecord{
			time:        date("Thursday-01-03-2018 14:00"),
			src:         "172.31.69.13",
			dst:         "172.31.69.14",
			expected:    "infiltration",
			description: "event from the third attack's time range with victim to non-attacker communication, edge of time range",
		},
		&testAuditRecord{
			time:        date("Thursday-01-03-2018 15:37"),
			src:         "172.31.69.13",
			dst:         "172.31.69.14",
			expected:    "infiltration",
			description: "event from the third attack's time range with victim to non-attacker communication, edge of time range",
		},
		&testAuditRecord{
			time:        date("Thursday-01-03-2018 15:38"),
			src:         "172.31.69.13",
			dst:         "172.31.69.14",
			expected:    "normal",
			description: "event from the third attack's time range with victim to non-attacker communication, out of time range",
		},
	}

	for _, r := range records {
		l := m.Label(r)
		if l != r.(*testAuditRecord).expected {
			fmt.Println("===================================")
			spew.Dump(r)
			fmt.Println("===================================")
			t.Fatal("unexpected label for audit record, expected: ", r.(*testAuditRecord).expected, " but got: ", l)
		}
	}
}

func TestReadIDS2018Labels(t *testing.T) {
	m := NewLabelManager(false, false, false, false, 5*time.Minute)
	labelMap, labels := m.parseAttackInfosYAML("../configs/cic-ids2018-attacks.yml")

	fmt.Println("=== labelMap")
	spew.Dump(labelMap)

	fmt.Println("=== labels")
	spew.Dump(labels)
}

func TestReadSWAT2019Labels(t *testing.T) {
	m := NewLabelManager(false, false, false, false, 5*time.Minute)
	labelMap, labels := m.parseAttackInfosYAML("../configs/swat-2019-attacks.yml")

	fmt.Println("=== labelMap")
	spew.Dump(labelMap)

	fmt.Println("=== labels")
	spew.Dump(labels)
}
