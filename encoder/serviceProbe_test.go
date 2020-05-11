package encoder

import (
	"github.com/mgutz/ansi"
	"regexp"
	"testing"
)

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

var serviceProbeTests = []regexTest{
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
	for _, r := range serviceProbeTests {
		r.testCleanRegex(t)
	}
}
