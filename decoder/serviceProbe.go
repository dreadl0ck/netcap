package decoder

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/umisama/go-cpe"
	"io"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/dlclark/regexp2"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/mgutz/ansi"
)

var (
	// all initialized service probes at runtime
	serviceProbes []*ServiceProbe

	// ignored probes for RE2 engine (RE2 does not support backtracking
	// groups in regexes with backtracking will be replaced by wildcard groups)
	ignoredProbesRE2 = map[string]struct{}{
		"pc-duo-gw":          {},
		"ventrilo":           {},
		"pc-duo":             {},
		"ssl":                {},
		"hpdss":              {},
		"xinetd":             {},
		"qotd":               {},
		"basestation":        {},
		"modem":              {},
		"sharp-remote":       {},
		"crossmatchverifier": {},
		"landesk-rc":         {},
		"nagios-nsca":        {},
	}

	// ignored probes for .NET compatible engine (supports backtracking)
	ignoredProbes = map[string]struct{}{
		"pc-duo-gw": {},
		"ventrilo":  {},
		"pc-duo":    {},
	}
)

// ServiceProbe is a regex based probe to fingerprint a network service by looking at its banner
// the term banner refers to the first X bytes of data (usually 512) that have been sent by the server
type ServiceProbe struct {
	RegEx           *regexp.Regexp
	RegExDotNet     *regexp2.Regexp
	RegExRaw        string
	Product         string
	Vendor          string
	Version         string
	Info            string
	Hostname        string
	OS              string
	DeviceType      string
	CPEs            map[string]string
	CaseInsensitive bool
	IncludeNewlines bool
	Ident           string
}

func (s *ServiceProbe) String() string {

	var b strings.Builder

	b.WriteString("ServiceProbe: ")
	b.WriteString(s.Ident)
	b.WriteString("\nRegEx: ")
	b.WriteString(s.RegExRaw)
	if len(s.Vendor) > 0 {
		b.WriteString("\nVendor: ")
		b.WriteString(s.Vendor)
	}
	if len(s.Version) > 0 {
		b.WriteString("\nVersion: ")
		b.WriteString(s.Version)
	}
	if len(s.Info) > 0 {
		b.WriteString("\nInfo: ")
		b.WriteString(s.Info)
	}
	if len(s.Hostname) > 0 {
		b.WriteString("\nHostname: ")
		b.WriteString(s.Hostname)
	}
	if len(s.OS) > 0 {
		b.WriteString("\nOS: ")
		b.WriteString(s.OS)
	}
	if len(s.DeviceType) > 0 {
		b.WriteString("\nDeviceType: ")
		b.WriteString(s.DeviceType)
	}
	//b.WriteString("\nCPEs: ")
	//b.WriteString(s.CPEs)
	b.WriteString("\nCaseInsensitive: ")
	b.WriteString(strconv.FormatBool(s.CaseInsensitive))
	b.WriteString("\nIncludeNewlines: ")
	b.WriteString(strconv.FormatBool(s.IncludeNewlines))

	return b.String()
}

func writeSoftwareFromBanner(serv *Service, ident string, probeIdent string) {
	writeSoftware([]*Software{
		{
			Software: &types.Software{
				Timestamp:  serv.Timestamp,
				Product:    serv.Product,
				Vendor:     serv.Vendor,
				Version:    serv.Version,
				SourceName: "Service Probe Match: " + probeIdent,
				Service:    serv.Name,
				Flows:      []string{ident},
				Notes:      "Protocol: " + serv.Protocol,
			},
		},
	}, nil)
}

func matchServiceProbes(serv *Service, banner []byte, ident string) {
	// match banner against nmap service probes
	for _, serviceProbe := range serviceProbes {
		if c.UseRE2 {
			if m := serviceProbe.RegEx.FindStringSubmatch(string(banner)); m != nil {

				// add initial values, may contain group identifiers ($1, $2 etc)
				serv.Product = addInfo(serv.Product, extractGroup(&serviceProbe.Product, m))
				serv.Vendor = addInfo(serv.Vendor, extractGroup(&serviceProbe.Vendor, m))
				serv.Hostname = addInfo(serv.Hostname, extractGroup(&serviceProbe.Hostname, m))
				serv.OS = addInfo(serv.OS, extractGroup(&serviceProbe.OS, m))
				serv.Version = addInfo(serv.Version, extractGroup(&serviceProbe.Version, m))

				if c.Debug {
					fmt.Println("\n\nMATCH!", ident)
					fmt.Println(serviceProbe, "\n\nSERVICE:\n"+proto.MarshalTextString(serv.Service), "\nBanner:", "\n"+hex.Dump(banner))
				}

				writeSoftwareFromBanner(serv, ident, serviceProbe.Ident)
			}
		} else { // use the .NET compatible regex implementation
			if m, err := serviceProbe.RegExDotNet.FindStringMatch(string(banner)); err == nil && m != nil {

				// add initial values, may contain group identifiers ($1, $2 etc)
				serv.Product = addInfo(serv.Product, extractGroupDotNet(&serviceProbe.Product, m))
				serv.Vendor = addInfo(serv.Vendor, extractGroupDotNet(&serviceProbe.Vendor, m))
				serv.Hostname = addInfo(serv.Hostname, extractGroupDotNet(&serviceProbe.Hostname, m))
				serv.OS = addInfo(serv.OS, extractGroupDotNet(&serviceProbe.OS, m))
				serv.Version = addInfo(serv.Version, extractGroupDotNet(&serviceProbe.Version, m))

				if c.Debug {
					fmt.Println("\nMATCH!", ident)
					fmt.Println(serviceProbe, "\n\nSERVICE:\n"+proto.MarshalTextString(serv.Service), "\nBanner:", "\n"+hex.Dump(banner))
				}

				writeSoftwareFromBanner(serv, ident, serviceProbe.Ident)
			}
		}
	}
}

var reGroup = regexp.MustCompile("\\$[0-9]+")

func extractGroup(in *string, m []string) string {
	if strings.Contains(*in, "$") {
		g := reGroup.FindString(*in)
		if len(g) == 2 {
			index, err := strconv.Atoi(string(g[1]))
			if err == nil {
				if len(m) > index {
					return strings.Replace(*in, g, m[index], 1)
				}
			}
		}
	}
	return *in
}

func extractGroupDotNet(in *string, m *regexp2.Match) string {
	if strings.Contains(*in, "$") {
		g := reGroup.FindString(*in)
		if len(g) == 2 {
			index, err := strconv.Atoi(string(g[1]))
			if err == nil {
				if len(m.Groups()) > index {
					return strings.Replace(*in, g, m.Groups()[index].Captures[0].String(), 1)
				}
			}
		}
	}
	return *in
}

// only parse the match directive for now.
// match <proto> m|<regex>|<i>/<s> <meta>
// allow using $1 or $2 perl style substrings in meta section
// helpers:
// - filter unprintable chars
// - substitute strings
// - unpack unsigned int

// example data:
//match amanda m|^220 ([-.\w]+) AMANDA index server \((\d[-.\w ]+)\) ready\.\r\n| p/Amanda backup system index server/ v/$2/ o/Unix/ h/$1/ cpe:/a:amanda:amanda:$2/
//match amanda m|^501 Could not read config file [^!\r\n]+!\r\n220 ([-.\w]+) AMANDA index server \(([-\w_.]+)\) ready\.\r\n| p/Amanda backup system index server/ v/$2/ i/broken: config file not found/ h/$1/ cpe:/a:amanda:amanda:$2/
//match amanda m|^ld\.so\.1: amandad: fatal: (libsunmath\.so\.1): open failed: No such file or directory\n$| p/Amanda backup system index server/ i/broken: $1 not found/ cpe:/a:amanda:amanda/
//match amanda m|^\n\*\* \(process:\d+\): CRITICAL \*\*: GLib version too old \(micro mismatch\): Amanda was compiled with glib-[\d.]+, but linking with ([\d.]+)\n| p/Amanda backup system index server/ i/broken: GLib $1 too old/ cpe:/a:amanda:amanda/

// parseVersionInfo uses the next read byte as a delimiter
// and reads everything into a buffer until the delimiter appears again
// it returns the final buffer and an error and advances the passed in *bytes.Reader to the
func parseVersionInfo(r io.ByteReader) (string, error) {

	var res []byte
	d, err := r.ReadByte()
	if err != nil {
		return "", err
	}

	for {
		bb, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if bb == d {
			break
		}
		res = append(res, bb)
	}

	//fmt.Println("parsed meta", string(res))
	return string(res), nil
}

var serviceProbeIdentEnums = make(map[string]int)

func enumerate(in string) string {
	if v, ok := serviceProbeIdentEnums[in]; ok {
		serviceProbeIdentEnums[in]++
		return in + "-" + strconv.Itoa(v+1)
	} else {
		serviceProbeIdentEnums[in] = 1
		return in + "-1"
	}
}

func InitServiceProbes() error {
	// load nmap service probes
	data, err := ioutil.ReadFile("/usr/local/etc/netcap/dbs/nmap-service-probes")
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	serviceProbes = make([]*ServiceProbe, 0, len(lines))

	for _, line := range lines {
		if len(line) == 0 || line == "\n" || strings.HasPrefix(line, "#") {
			// ignore comments and blanks
			continue
		}
		if strings.HasPrefix(line, "match") {

			// check if rule ident field has been excluded
			ident := strings.Fields(line)[1]
			if c.UseRE2 {
				if _, ok := ignoredProbesRE2[ident]; ok {
					utils.DebugLog.Println("ignoring probe", ident)
					continue
				}
			} else {
				if _, ok := ignoredProbes[ident]; ok {
					utils.DebugLog.Println("ignoring probe", ident)
					continue
				}
			}

			var (
				spaces    int
				delim     byte
				regex     []byte
				r         = bytes.NewReader([]byte(line))
				checkOpts bool
				parseMeta bool
				s         = new(ServiceProbe)
			)

			// enumerate the ident type (e.g: http -> http-1 for the first http banner probe)
			// useful to see which rule matched exactly, since multiple rules for the same protocol / service are usually present
			s.Ident = enumerate(ident)

			for {
				b, err := r.ReadByte()
				if errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					return err
				}
				//fmt.Println("read", string(b))

				if unicode.IsSpace(rune(b)) && !checkOpts {
					//fmt.Println("its a space", string(b))
					spaces++

					if delim != 0 {
						// collect whitespace when parsing the regex string
						regex = append(regex, b)
					}
					continue
				}
				// last part versionInfo: m/[regex]/[opts] [meta]
				// example: p/Amanda backup system index server/ i/broken: GLib $1 too old/ cpe:/a:amanda:amanda/
				if parseMeta {

					// skip over whitespace
					if unicode.IsSpace(rune(b)) {
						//fmt.Println("parse meta: skip whitespace")
						continue
					}

					// parse a version info block
					var errParse error
					switch string(b) {
					case "p":
						s.Product, errParse = parseVersionInfo(r)
						if errParse != nil {
							return errParse
						}
					case "v":
						s.Version, errParse = parseVersionInfo(r)
						if errParse != nil {
							return errParse
						}
					case "i":
						s.Info, errParse = parseVersionInfo(r)
						if errParse != nil {
							return errParse
						}
					case "h":
						s.Hostname, errParse = parseVersionInfo(r)
						if errParse != nil {
							return errParse
						}
					case "o":
						s.OS, errParse = parseVersionInfo(r)
						if errParse != nil {
							return errParse
						}
					case "d":
						s.DeviceType, errParse = parseVersionInfo(r)
						if errParse != nil {
							return errParse
						}
					case "c":

						// Common Platform Enumeration Tags
						var buf bytes.Buffer
						buf.WriteString("c")

						// read until the EOF of the line
						for {
							b, err = r.ReadByte()
							if errors.Is(err, io.EOF) {
								// TODO: split by fields, might be multiple cpes
								var i *cpe.Item
								i, err = cpe.NewItemFromUri(buf.String())
								if err != nil {
									utils.DebugLog.Println("error while parsing cpe tag for service probe:", err, "probe:", s.Ident)
									goto next
								}
								// set vendor
								s.Vendor = i.Vendor().String()
								goto next
							}
							buf.WriteByte(b)
						}
					}

					continue
				}
				// m/[regex]/[opts]
				// - there can be an optional i for case insensitive matching
				// - or an 's' to include newlines in the '.' specifier
				if checkOpts {
					if unicode.IsSpace(rune(b)) {

						//fmt.Println("options done!")
						// options done
						checkOpts = false
						parseMeta = true
						continue
					}
					switch string(b) {
					case "i":
						s.CaseInsensitive = true
					case "s":
						s.IncludeNewlines = true
					}
					continue
				}
				// check if delimiter was already found
				if delim != 0 {
					if b == delim {
						//fmt.Println("parsed regex", ansi.Blue, string(regex), ansi.Reset, "from line", ansi.Green, line, ansi.Reset)

						// parse options
						checkOpts = true

						continue
					}
					regex = append(regex, b)
					continue
				}
				// start of regex
				if spaces == 2 {
					if string(b) != "m" {
						return errors.New("invalid format for line: " + line)
					}

					// read delimiter
					b, err = r.ReadByte()
					if errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						return err
					}

					//fmt.Println("read delim", string(b))

					delim = b
					continue
				}
			}
		next:
			// compile regex
			var (
				errCompile error
				finalReg   = "(?m"
			)

			// To change the default matching behavior, you can add a set of flags to the beginning of a regular expression.
			// For example, the prefix "(?is)" makes the matching case-insensitive and lets . match \n. (The default matching is case-sensitive and . doesn’t match \n.)
			if s.CaseInsensitive {
				finalReg += "i"
			}
			if s.IncludeNewlines {
				finalReg += "s"
			}

			finalReg += ")" + strings.TrimSpace(string(regex))
			before := finalReg

			if c.UseRE2 {
				finalReg = clean(finalReg)
				s.RegEx, errCompile = regexp.Compile(finalReg)
			} else {
				s.RegExDotNet, errCompile = regexp2.Compile(finalReg, 0) // regexp.RE2)
			}

			if errCompile != nil {
				if c.Debug {
					if c.UseRE2 {
						if before != finalReg {
							fmt.Println("before != finalReg:", before)
						}
						fmt.Println("failed to compile regex:", ansi.Yellow, s.Ident, ansi.Red, errCompile, ansi.White, finalReg, ansi.Reset) // stdlib regexp only logs the broken part of the regex. this logs the full regex string for debugging
					} else {
						fmt.Println("failed to compile regex:", ansi.Yellow, s.Ident, ansi.Red, errCompile, ansi.Reset)
						fmt.Println(ansi.White, line, ansi.Reset)
					}
				}
			} else {
				s.RegExRaw = finalReg
				serviceProbes = append(serviceProbes, s)
			}
		}
	}

	utils.DebugLog.Println("loaded", len(serviceProbes), "nmap service probes")

	return nil
}

func colorize(in string, num int) string {

	var out string

	for i, c := range in {
		if i == num-1 {
			out = in[:i] + ansi.Red + string(c) + ansi.Reset + in[i+1:]
			break
		}
	}

	return out
}

// DumpServiceProbes prints all loaded probes as JSON
func DumpServiceProbes() {
	for _, p := range serviceProbes {
		data, err := json.MarshalIndent(p, " ", "  ")
		if err == nil {
			fmt.Println(string(data))
		}
	}
}

// clean implements a simple state machine to replace all backtracking operations
// indicated by (?
// with a wildcard group match operation (.*)
// to ensure compatibility with the re2 engine
func clean(in string) string {
	var (
		r                     = bytes.NewReader([]byte(strings.ReplaceAll(in, "\\1", "(.*)")))
		out                   []byte
		check                 bool
		ignore                bool
		firstQuestionMark     = true
		stopCnt, startCount   = -1, -1
		resetEscaped, escaped bool
		lastchar              byte
		count                 int
		nextCloses            bool
		numIgnored            int
	)
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				break
			}
		}
		count++
		debug := func(args ...interface{}) {
			// TODO: make debug mode configurable
			//fmt.Println(string(lastchar), ansi.Blue, string(b), ansi.Red, startCount, stopCnt, ansi.Green, string(out), ansi.White, args, ansi.Reset, colorize(in, count), numIgnored)
		}
		if string(b) == "\\" && !escaped {
			debug("set escaped to true")
			escaped = true
		} else {
			if escaped {
				if resetEscaped {
					debug("reset escaped")
					// reset
					escaped = false
					resetEscaped = false
				} else {
					// reset escaped next round
					resetEscaped = true
				}
			}
		}
		if ignore {
			if string(b) == ")" {

				if !escaped {

					stopCnt++
					debug("stopCnt++")

					if startCount == stopCnt || nextCloses {

						ignore = false
						debug("stop ignore", "add missing )", numIgnored > 1 && stopCnt != 0)

						if numIgnored > 1 && stopCnt != 0 {
							missing := stopCnt - numIgnored
							debug("missing )", missing)
							if missing > 0 {
								for i := 0; i < missing; i++ {
									debug("add missing )", missing, numIgnored)
									out = append(out, byte(')'))
								}
							}
						}

						debug("add trailing )")
						out = append(out, byte(')'))
						check = false

						stopCnt = 0
						startCount = 0

						lastchar = b
						continue
					}
					debug("numIgnored++")
					numIgnored++
				} else {
					debug("ignoring because escaped")
				}
			}
			if string(b) == "(" {
				if !escaped && lastchar != '^' {
					startCount++
					debug("startCount++")
					nextCloses = false
				}
			}
			debug("ignore")

			lastchar = b
			continue
		}
		if string(b) == "(" {

			debug("got parentheses")
			if !escaped {
				startCount++
				debug("startCount++")
			}

			out = append(out, b)
			check = true

			lastchar = b
			continue
		}
		if check {
			if string(b) == "?" && lastchar == '(' {

				debug("found backtracking")
				if firstQuestionMark {
					firstQuestionMark = false
				} else {
					nextCloses = true
					debug("write .*")
					out = append(out, byte('.'))
					out = append(out, byte('*'))
					ignore = true

					lastchar = b
					continue
				}
			}
		}
		if string(b) == ")" {
			if !escaped {
				stopCnt++
				debug("stopCnt++")
			}
		}
		if string(b) == "(" {
			if !escaped {
				startCount++
				debug("startCount++")
			}
		}
		debug("collect")
		out = append(out, b)
		lastchar = b
	}
	return string(out)
}
