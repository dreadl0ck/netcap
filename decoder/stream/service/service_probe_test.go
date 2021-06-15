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

package service

import (
	"fmt"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/db"
	"github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/resolvers"
)

func init() {
	dbLog, _, err := logger.InitZapLogger("../../tests", "db", false)
	if err != nil {
		panic(err)
	}

	db.SetLogger(dbLog)

	serviceLog = zap.NewNop()
}

type regexTest struct {
	name     string
	input    string
	expected string
}

func (r regexTest) testCleanRegex(t *testing.T) {
	// remove backtracking from regex and replace with a group of a single char repetition (.*)
	out := clean(r.input)
	if out != r.expected {
		t.Fatal("failed to clean regex, got:", ansi.Red, out, ansi.Reset, "expected", ansi.Green, r.expected, ansi.Reset, "input", ansi.Blue, r.input, ansi.Reset)
	}

	// make sure the regex compiles
	_, err := regexp.Compile(out)
	if err != nil {
		t.Fatal(err)
	}
}

func TestExtractGroupIdent(t *testing.T) {
	m := reGroup.FindString("asdf$1asdf")
	if m != "$1" {
		t.Fatal("expected $1, got", m)
	}
	m = reGroup.FindString("asdf$2asdf")
	if m != "$2" {
		t.Fatal("expected $2, got", m)
	}
	m = reGroup.FindString("asdf$3asdf")
	if m != "$3" {
		t.Fatal("expected $3, got", m)
	}
}

func TestExtractGroups(t *testing.T) {
	in := "$1"
	in = extractGroup(&in, []string{"", "first", "second", "third", "fourth"})
	if in != "first" {
		t.Fatal("expected first, got", in)
	}

	in = "$4"
	in = extractGroup(&in, []string{"", "first", "second", "third", "fourth"})
	if in != "fourth" {
		t.Fatal("expected fourth, got", in)
	}
}

type bannerTest struct {
	banner  string
	product string
	host    string
	os      string
	version string

	// can be used to quickly test if a regex works
	// in case this field is set, the regex will be compiled and used instead of the loaded service probes
	reg string
}

var serviceBanners = []bannerTest{
	// FTP
	{
		banner:  "220 (vsFTPd 3.0.3)\n200 Always in UTF8 mode.\n331 Please specify the password.\n230 Login successful.\n200 PORT command successful. Consider using PASV.\n150 Here comes the directory listing.\n226 Directory send OK.\n221 Goodbye.\n",
		product: "vsFTPd",
		version: "3.0.3",
		reg:     "^220\\s\\((.*)\\s(.*)\\)",
	},
	// SSH
	{
		banner:  "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
		product: "OpenSSH",
		version: "7.6p1",
		os:      "Ubuntu-4ubuntu0.3",
		reg:     "^SSH-(.*)-(.*)_(.*)\\s(.*)",
	},
	// POP3
	{
		banner:  "+OK POP server ready H migmx027 0M8Bvu-1XYRm80CF0-00vllf\\r\\n+OK Capability list follows\\r\\n",
		product: "POP3 server",
		reg:     "^\\+OK POP server ready",
	},
	// TODO: fix test
	// Postgresql
	//{
	//	banner:  "......./N...O....user.root.database.root.application_name.psql.client_encoding.WIN1252..R.........?..p...(md5c9fd3dd66713de84341542478ace7780.R........S....client_encoding.WIN1252.S....DateStyle.ISO, MDY.S....integer_datetimes.on.S....IntervalStyle.postgres.S....is_superuser.on.S....server_encoding.UTF8.S....server_version\x008.4.22\x00S....session_authorization.root.S...$standard_conforming_strings.off.S....TimeZone.UTC.K......Q._..Z....I",
	//	version: "8.4.22",
	//	product: "PostgreSQL",
	//},
	//{
	//	banner:  "␛[31m␀␀␀␈\\u{4}\\xD2\\u{16}/␛[0m␛[34mN␛[0m␛[31m␀␀␀O␀\\u{3}␀␀user␀root␀database␀root␀application_name␀psql␀client_encoding␀WIN1252␀␀␛[0m␛[34mR␀␀␀␈␀␀␀␀S␀␀␀\\u{1a}application_name␀psql␀S␀␀␀\\u{1c}client_encoding␀WIN1252␀S␀␀␀\\u{17}DateStyle␀ISO,•MDY␀S␀␀␀\\u{19}integer_datetimes␀on␀S␀␀␀␛Inter\n       │ valStyle␀postgres␀S␀␀␀\\u{14}is_superuser␀on␀S␀␀␀\\u{19}server_encoding␀UTF8␀S␀␀␀\\u{1a}server_version␀9.1.10␀S␀␀␀\\u{1f}session_authorization␀root␀S␀␀␀#standard_conforming_strings␀on␀S␀␀␀\\u{11}TimeZone␀UTC␀K␀␀␀\\u{c}␀␀&*␀\\x958OZ␀␀␀\\u{5}I␛[0m",
	//	version: "9.1.10",
	//	product: "PostgreSQL",
	//},
}

// use one global var for the vuln index so it can be shared between tests?
func TestClassifyBanners(t *testing.T) {
	conf := config.DefaultConfig

	// Load vulnerabilities DB index
	indexName := filepath.Join(resolvers.DataBaseFolderPath, "nvd.bleve")
	var err error
	db.VulnerabilitiesIndex, err = db.OpenBleve(indexName)
	if err != nil {
		t.Fatal(err)
	}

	defer db.CloseBleve(db.VulnerabilitiesIndex)

	indexName = filepath.Join(resolvers.DataBaseFolderPath, "exploit-db.bleve")
	db.ExploitsIndex, err = db.OpenBleve(indexName)
	if err != nil {
		t.Fatal(err)
	}

	defer db.CloseBleve(db.ExploitsIndex)

	// conf.Debug = true
	// important: needs to be set prior to loading probes
	// otherwise config is not initialized and defaults to false
	conf.UseRE2 = true

	// load nmap service probes
	err = initServiceProbes()
	if err != nil {
		t.Fatal(err)
	}

	for _, b := range serviceBanners {
		if b.reg != "" {
			// invoke custom test regex
			r := regexp.MustCompile(b.reg)
			m := r.FindStringSubmatch(b.banner)
			if len(m) > 1 {
				fmt.Println("matches for test regex", m[1:])
			}
		} else {
			// invoke nmap banner probes
			b.testClassifyBanner(t)
		}
	}
}

func (b bannerTest) testClassifyBanner(t *testing.T) {
	// make dummy service
	serv := NewService(time.Now().UnixNano(), 0, 0, "")
	serv.IP = "127.0.0.1"
	serv.Port = 21
	ident := "127.0.0.1:4322->127.0.0.1:21"
	serv.Flows = []string{ident}

	MatchServiceProbes(serv, []byte(b.banner), ident)

	if serv.Product != b.product {
		t.Fatal("unexpected product, expected", b.product, "got:", serv.Product)
	}
	if serv.Version != b.version {
		t.Fatal("unexpected version, expected", b.version, "got:", serv.Version)
	}
	if serv.Hostname != b.host {
		t.Fatal("unexpected notes, expected", b.host, "got:", serv.Hostname)
	}
}

var regexTests = []regexTest{
	{
		name:     "",
		input:    "(?ms)^\\x00\\x03\\xf1\\x26.{88}(.*)\\0\\0(?:.*?:){5}(.*)\\0\\0$",
		expected: "(?ms)^\\x00\\x03\\xf1\\x26.{88}(.*)\\0\\0(.*){5}(.*)\\0\\0$",
	},
	{
		name:     "",
		input:    "(?ms)^HTTP/1\\.1 \\d\\d\\d (?:[^\\r\\n]*\\r\\n(?!\\r\\n))*?X-Powered-By: sisRapid Framework\\r\\n",
		expected: "(?ms)^HTTP/1\\.1 \\d\\d\\d (.*)*?X-Powered-By: sisRapid Framework\\r\\n",
	},
	{
		name:     "",
		input:    "(?m)^\\xff\\xff\\xff\\xffstatusResponse\\n.*\\\\version\\\\([^\\\\]* linux-[^\\\\]*)(?=\\\\).*\\\\gamename\\\\q3ut4(?=\\\\)",
		expected: "(?m)^\\xff\\xff\\xff\\xffstatusResponse\\n.*\\\\version\\\\([^\\\\]* linux-[^\\\\]*)(.*).*\\\\gamename\\\\q3ut4(.*)",
	},
	{
		name:     "",
		input:    "(?mi)^\\xff\\xfd\\x18\\xff\\xfa\\x18\\x01\\xff\\xf0\\xff\\xfb\\x01\\xff\\xfb\\x03\\xff\\xfd\\x01\\r\\n\\r\\nUltrix(?:-32)? V([\\d.]+) \\(Rev\\.? (\\d+)\\) \\(([^)]+)\\)\\r\\n\\r\\r\\n\\rlogin:",
		expected: "(?mi)^\\xff\\xfd\\x18\\xff\\xfa\\x18\\x01\\xff\\xf0\\xff\\xfb\\x01\\xff\\xfb\\x03\\xff\\xfd\\x01\\r\\n\\r\\nUltrix(.*)? V([\\d.]+) \\(Rev\\.? (\\d+)\\) \\(([^)]+)\\)\\r\\n\\r\\r\\n\\rlogin:",
	},
	{
		name:     "",
		input:    "(?m)^220 FUJI XEROX DocuPrint ([A-Z][A-Z\\d]+(?: ?[a-zA-Z]{1,2})?)\\r\\n",
		expected: "(?m)^220 FUJI XEROX DocuPrint ([A-Z][A-Z\\d]+(.*)?)\\r\\n",
	},
	{
		name:     "",
		input:    "(?ms)^Content-Length: [0-9]+\n\n<\\?xml version=\"1\\.0\"\\?>\\s*<xmlsysd init=\"1\">\\s*<system>\\s*<identity>\\s*<hostname>([^<]*)</hostname>\\s*<hostip>([^<]*)</hostip>\\s*</identity>\\s*</system>\\s*<proc>\\s*<version>([^<]*)</version>\\s*</proc>\\s*</xmlsysd>",
		expected: "(?ms)^Content-Length: [0-9]+\n\n<\\?xml version=\"1\\.0\"\\?>\\s*<xmlsysd init=\"1\">\\s*<system>\\s*<identity>\\s*<hostname>([^<]*)</hostname>\\s*<hostip>([^<]*)</hostip>\\s*</identity>\\s*</system>\\s*<proc>\\s*<version>([^<]*)</version>\\s*</proc>\\s*</xmlsysd>",
	},
	{
		name:     "",
		input:    "(?m)^220 ([-\\w_.]+) ESMTP (?:[^(]+? )?\\(Ubuntu\\)\\r\\n502 5\\.5\\.2 Error: command not recognized\\r\\n",
		expected: "(?m)^220 ([-\\w_.]+) ESMTP (.*)?\\(Ubuntu\\)\\r\\n502 5\\.5\\.2 Error: command not recognized\\r\\n",
	},
	{
		name:     "",
		input:    "(?m)^\\0\\0\\0a\\xffSMBr\\0\\0\\0\\0\\x80\\0{16}@\\x06\\0\\0\\x01\\0\\x11\\x07\\0\\x03\\x01\\0\\x14\\0@\\x1e\\0\\0\\xff\\xff\\0\\0....\\x14\\x02\\0{10}..\\x08\\x1c\\0.{8}((?:(?!\\0\\0).)+?)\\0\\0",
		expected: "(?m)^\\0\\0\\0a\\xffSMBr\\0\\0\\0\\0\\x80\\0{16}@\\x06\\0\\0\\x01\\0\\x11\\x07\\0\\x03\\x01\\0\\x14\\0@\\x1e\\0\\0\\xff\\xff\\0\\0....\\x14\\x02\\0{10}..\\x08\\x1c\\0.{8}((.*))\\0\\0",
	},
	// TODO: nested backtracking ...
	//{
	//	name:     "",
	//	input:    "(?m)^SSH-([\\d.]+)-(?=[\\w._-]{5,15}\\r?\\n$).*(?:[a-z](?:[A-Z]\\d|\\d[A-Z])|[A-Z](?:[a-z]\\d|\\d[a-z])|\\d(?:[a-z][A-Z]|[A-Z][a-z]))",
	//	expected: "(?m)^SSH-([\\d.]+)-(.*).*(.*)",
	//},
}

func TestCleanRegex(t *testing.T) {
	for _, r := range regexTests {
		r.testCleanRegex(t)
	}
}
