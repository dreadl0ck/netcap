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

package service

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/dlclark/regexp2"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"
	"github.com/umisama/go-cpe"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

var (
	// all initialized service probes at runtime.
	serviceProbes map[string][]*serviceProbe

	// ignored probes for RE2 engine (RE2 does not support backtracking
	// groups in regexes with backtracking will be replaced by wildcard groups).
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
		"smtp-proxy":         {}, // Contains non-capturing groups that clean() converts to .*, matching everything
	}

	// ignored probes for .NET compatible engine (supports backtracking).
	ignoredProbes = map[string]struct{}{
		"pc-duo-gw": {},
		"ventrilo":  {},
		"pc-duo":    {},
	}
)

func init() {
	decoderconfig.Instance = decoderconfig.DefaultConfig
	serviceLog = zap.NewNop()
}

const (
	debugRegexClean = false
)

// serviceProbe is a regex based probe to fingerprint a network service by looking at its banner
// the term banner refers to the first X bytes of data that have been sent by the server.
type serviceProbe struct {
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

func (s *serviceProbe) String() string {
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

	// b.WriteString("\nCPEs: ")
	// b.WriteString(s.CPEs)

	b.WriteString("\nCaseInsensitive: ")
	b.WriteString(strconv.FormatBool(s.CaseInsensitive))
	b.WriteString("\nIncludeNewlines: ")
	b.WriteString(strconv.FormatBool(s.IncludeNewlines))

	return b.String()
}

func writeSoftwareFromBanner(serv *service, ident, probeIdent string) {
	software.WriteSoftware([]*software.AtomicSoftware{
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

// MatchServiceProbes will check the service banner against the probes.
func MatchServiceProbes(serv *service, banner []byte, ident string) {
	var (
		expectedCategory string
		found            bool
		matched          int
	)

	// lookup expected identifier based on port
	switch serv.Protocol {
	case "TCP":
		expectedCategory = servicesByPortsTCP[serv.Port]
	case "UDP":
		expectedCategory = servicesByPortsUDP[serv.Port]
	}

	if expectedCategory != "" {
		if probes, ok := serviceProbes[expectedCategory]; ok {
			serviceLog.Debug("matching probes", zap.String("ident", ident), zap.String("expectedCategory", expectedCategory))
			found, matched = matchProbes(serv, probes, banner, ident)
		}
		if !found && decoderconfig.Instance.StopAfterServiceCategoryMiss {
			return
		}
	}

	// if no match was found OR stopping after a match is disabled
	if !found || !decoderconfig.Instance.StopAfterServiceProbeMatch {
		// match banner against ALL nmap service probes
		for category, probes := range serviceProbes {
			// exclude the category that was already searched
			if category == expectedCategory {
				continue
			}

			found, matched = matchProbes(serv, probes, banner, ident)
			if found && decoderconfig.Instance.StopAfterServiceProbeMatch {
				serviceLog.Info("service probe match found",
					zap.String("ident", ident),
					zap.Int("matched", matched),
					zap.Int("total", len(probes)),
					zap.String("expected", expectedCategory),
				)
				// Check if Product is still empty even after probe match - if so, try HTTP headers
				if serv.Product == "" {
					matchHTTPHeaders(serv, banner, ident)
				}
				return
			}
		}

		serviceLog.Debug("all probes tried", zap.String("ident", ident), zap.Bool("found", found), zap.Int("matched", matched))
	}

	// If no match was found, or if a match was found but Product field is still empty,
	// try to extract information from HTTP headers as a fallback
	if !found || serv.Product == "" {
		matchHTTPHeaders(serv, banner, ident)
	}
}

// matchHTTPHeaders attempts to extract service information from HTTP response headers
// when nmap service probes don't deliver results.
func matchHTTPHeaders(serv *service, banner []byte, ident string) {
	// Priority-ordered headers to check for service identification
	priorityHeaders := []string{
		"Server",              // Primary service identification
		"X-Powered-By",        // Framework/language detection
		"X-AspNet-Version",    // ASP.NET apps
		"X-AspNetMvc-Version", // ASP.NET MVC apps
		"X-Generator",         // CMS identification
		"Via",                 // Proxy detection
		"X-Cache",             // CDN detection
	}

	var detectedValue string
	var detectedHeader string

	// First, check if this looks like an HTTP response
	bannerStr := string(banner)
	if !strings.HasPrefix(bannerStr, "HTTP/") {
		return
	}

	// Try to parse as a complete HTTP response first
	// Note: http.ReadResponse requires headers to end with \r\n\r\n
	// For truncated banners, we'll fall back to manual extraction
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(banner)), nil)
	if err == nil {
		// Successfully parsed as HTTP response
		for _, headerName := range priorityHeaders {
			if value := resp.Header.Get(headerName); value != "" {
				detectedValue = value
				detectedHeader = headerName
				break
			}
		}
	}

	// If standard parsing failed or didn't find headers, try manual extraction
	// This handles truncated banners that don't have the \r\n\r\n terminator
	if detectedValue == "" {
		detectedHeader, detectedValue = extractHeaderManually(bannerStr, priorityHeaders)
	}

	if detectedValue == "" {
		// No relevant headers found
		return
	}

	// Parse the detected value to extract product, version, and vendor information
	parseHeaderValue(serv, detectedHeader, detectedValue, ident)

	serviceLog.Debug("HTTP header match",
		zap.String("ident", ident),
		zap.String("header", detectedHeader),
		zap.String("value", detectedValue),
		zap.String("product", serv.Product),
		zap.String("version", serv.Version),
	)
}

// extractHeaderManually extracts HTTP headers from a banner string manually.
// This is used as a fallback when http.ReadResponse fails due to truncated banners.
func extractHeaderManually(banner string, priorityHeaders []string) (headerName, headerValue string) {
	// Split by common line endings (handle both \r\n and \n)
	lines := strings.Split(banner, "\n")

	for _, targetHeader := range priorityHeaders {
		targetLower := strings.ToLower(targetHeader)
		for _, line := range lines {
			// Clean up the line (remove \r if present)
			line = strings.TrimRight(line, "\r")
			line = strings.TrimSpace(line)

			// Check if this line starts with the header name (case-insensitive)
			if len(line) > len(targetHeader)+1 && line[len(targetHeader)] == ':' {
				lineLower := strings.ToLower(line[:len(targetHeader)])
				if lineLower == targetLower {
					// Extract the value after the colon
					value := strings.TrimSpace(line[len(targetHeader)+1:])
					if value != "" {
						return targetHeader, value
					}
				}
			}
		}
	}

	return "", ""
}

// parseHeaderValue parses the header value to extract product, version, and vendor information.
func parseHeaderValue(serv *service, headerName, value, ident string) {
	var product, version, vendor string

	// Normalize the value
	value = strings.TrimSpace(value)

	switch headerName {
	case "Server":
		// Common formats: "Apache/2.4.41", "nginx/1.18.0", "Microsoft-IIS/10.0"
		product, version = parseServerHeader(value)
	case "X-Powered-By":
		// Common formats: "PHP/7.4.3", "ASP.NET", "Express"
		product, version = parseXPoweredByHeader(value)
	case "X-AspNet-Version":
		product = "ASP.NET"
		version = value
	case "X-AspNetMvc-Version":
		product = "ASP.NET MVC"
		version = value
	case "X-Generator":
		// Common formats: "WordPress 5.8", "Drupal 9", "Jekyll v4.2.0"
		product, version = parseGeneratorHeader(value)
	case "Via":
		product, version = parseViaHeader(value)
	case "X-Cache":
		product = "CDN/Cache: " + value
	}

	if product != "" {
		serv.Product = addInfo(serv.Product, product)
		serv.MatchedProbeID = "http-header-" + strings.ToLower(headerName)

		// Write software detection result
		software.WriteSoftware([]*software.AtomicSoftware{
			{
				Software: &types.Software{
					Timestamp:  serv.Timestamp,
					Product:    product,
					Vendor:     vendor,
					Version:    version,
					SourceName: "HTTP Header Match: " + headerName,
					Service:    serv.Name,
					Flows:      []string{ident},
					Notes:      "Header: " + headerName + " = " + value,
				},
			},
		}, nil)
	}

	if version != "" {
		serv.Version = addInfo(serv.Version, version)
	}

	if vendor != "" {
		serv.Vendor = addInfo(serv.Vendor, vendor)
	}
}

// parseServerHeader parses the Server header value.
// Examples: "Apache/2.4.41 (Ubuntu)", "nginx/1.18.0", "Microsoft-IIS/10.0"
func parseServerHeader(value string) (product, version string) {
	// Split by space to handle cases like "Apache/2.4.41 (Ubuntu)"
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return "", ""
	}

	// Parse the first part which usually contains product/version
	firstPart := parts[0]
	if idx := strings.Index(firstPart, "/"); idx != -1 {
		product = firstPart[:idx]
		version = firstPart[idx+1:]
	} else {
		product = firstPart
	}

	return product, version
}

// parseXPoweredByHeader parses the X-Powered-By header value.
// Examples: "PHP/7.4.3", "ASP.NET", "Express"
func parseXPoweredByHeader(value string) (product, version string) {
	if idx := strings.Index(value, "/"); idx != -1 {
		product = value[:idx]
		version = value[idx+1:]
	} else {
		product = value
	}

	return product, version
}

// parseGeneratorHeader parses the X-Generator header value.
// Examples: "WordPress 5.8", "Drupal 9 (https://www.drupal.org)", "Jekyll v4.2.0"
func parseGeneratorHeader(value string) (product, version string) {
	// Split by space to handle "WordPress 5.8" format
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return "", ""
	}

	product = parts[0]

	if len(parts) >= 2 {
		// Extract version, removing any leading 'v' if present
		version = strings.TrimPrefix(parts[1], "v")
	}

	return product, version
}

// parseViaHeader parses the Via header value.
// Examples: "1.1 varnish", "1.1 squid/4.10"
func parseViaHeader(value string) (product, version string) {
	// Via format: "protocol proxy-name"
	// Example: "1.1 varnish" or "1.1 squid/4.10"
	parts := strings.Fields(value)
	if len(parts) < 2 {
		product = "Proxy"
		return product, ""
	}

	proxyInfo := parts[1]
	if idx := strings.Index(proxyInfo, "/"); idx != -1 {
		product = proxyInfo[:idx]
		version = proxyInfo[idx+1:]
	} else {
		product = proxyInfo
	}

	return product, version
}

func matchProbes(serv *service, probes []*serviceProbe, banner []byte, ident string) (found bool, index int) {
	for i, probe := range probes {
		if decoderconfig.Instance.UseRE2 {
			// Skip probes with nil RegEx (may happen if probe was compiled with UseRE2=false)
			if probe.RegEx == nil {
				continue
			}
			if m := probe.RegEx.FindStringSubmatch(string(banner)); m != nil {

				// add initial values, may contain group identifiers ($1, $2 etc)
				product := extractGroup(&probe.Product, m)
				vendor := extractGroup(&probe.Vendor, m)
				hostname := extractGroup(&probe.Hostname, m)
				os := extractGroup(&probe.OS, m)
				version := extractGroup(&probe.Version, m)

				serv.Product = addInfo(serv.Product, product)
				serv.Vendor = addInfo(serv.Vendor, vendor)
				serv.Hostname = addInfo(serv.Hostname, hostname)
				serv.OS = addInfo(serv.OS, os)
				serv.Version = addInfo(serv.Version, version)

				// Store the matched probe ID for UI navigation
				if serv.MatchedProbeID == "" {
					serv.MatchedProbeID = probe.Ident
				}

				if decoderconfig.Instance.Debug { // prevent evaluating the log statement if not in debug mode
					serviceLog.Info("service probe match detail",
						zap.String("ident", ident),
						zap.String("probe", fmt.Sprintf("%+v", probe)),
						zap.String("service", proto.MarshalTextString(serv.Service)),
						zap.String("banner", hex.Dump(banner)),
					)
				}

				writeSoftwareFromBanner(serv, ident, probe.Ident)

				// return true if search shall be stopped after the first match
				if decoderconfig.Instance.StopAfterServiceProbeMatch {
					return true, i
				}

				// otherwise continue, but mark search as successful
				found = true
			}
		} else { // use the .NET compatible regex implementation
			// Skip probes with nil RegExDotNet (may happen if probe was compiled with UseRE2=true)
			if probe.RegExDotNet == nil {
				continue
			}
			if m, err := probe.RegExDotNet.FindStringMatch(string(banner)); err == nil && m != nil {

				// add initial values, may contain group identifiers ($1, $2 etc)
				product := extractGroupDotNet(&probe.Product, m)
				vendor := extractGroupDotNet(&probe.Vendor, m)
				hostname := extractGroupDotNet(&probe.Hostname, m)
				os := extractGroupDotNet(&probe.OS, m)
				version := extractGroupDotNet(&probe.Version, m)

				serv.Product = addInfo(serv.Product, product)
				serv.Vendor = addInfo(serv.Vendor, vendor)
				serv.Hostname = addInfo(serv.Hostname, hostname)
				serv.OS = addInfo(serv.OS, os)
				serv.Version = addInfo(serv.Version, version)

				// Store the matched probe ID for UI navigation
				if serv.MatchedProbeID == "" {
					serv.MatchedProbeID = probe.Ident
				}

				if decoderconfig.Instance.Debug { // prevent evaluating the log statement if not in debug mode
					serviceLog.Info("service probe match detail",
						zap.String("ident", ident),
						zap.String("probe", fmt.Sprintf("%+v", probe)),
						zap.String("service", proto.MarshalTextString(serv.Service)),
						zap.String("banner", hex.Dump(banner)),
					)
				}

				writeSoftwareFromBanner(serv, ident, probe.Ident)

				// return true if search shall be stopped after the first match
				if decoderconfig.Instance.StopAfterServiceProbeMatch {
					return true, i
				}

				// otherwise continue, but mark search as successful
				found = true
			}
		}
	}

	return found, len(probes)
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
// match amanda m|^220 ([-.\w]+) AMANDA index server \((\d[-.\w ]+)\) ready\.\r\n| p/Amanda backup system index server/ v/$2/ o/Unix/ h/$1/ cpe:/a:amanda:amanda:$2/
// match amanda m|^501 Could not read config file [^!\r\n]+!\r\n220 ([-.\w]+) AMANDA index server \(([-\w_.]+)\) ready\.\r\n| p/Amanda backup system index server/ v/$2/ i/broken: config file not found/ h/$1/ cpe:/a:amanda:amanda:$2/
// match amanda m|^ld\.so\.1: amandad: fatal: (libsunmath\.so\.1): open failed: No such file or directory\n$| p/Amanda backup system index server/ i/broken: $1 not found/ cpe:/a:amanda:amanda/
// match amanda m|^\n\*\* \(process:\d+\): CRITICAL \*\*: GLib version too old \(micro mismatch\): Amanda was compiled with glib-[\d.]+, but linking with ([\d.]+)\n| p/Amanda backup system index server/ i/broken: GLib $1 too old/ cpe:/a:amanda:amanda/

// parseVersionInfo uses the next read byte as a delimiter
// and reads everything into a buffer until the delimiter appears again
// it returns the final buffer and an error and advances the passed in *bytes.Reader to the.
func parseVersionInfo(r io.ByteReader) (string, error) {
	d, err := r.ReadByte()
	if err != nil {
		return "", err
	}

	var (
		res []byte
		b   byte
	)

	for {
		b, err = r.ReadByte()
		if err != nil {
			return "", err
		}

		if b == d {
			break
		}

		res = append(res, b)
	}

	// fmt.Println("parsed meta", string(res))
	return string(res), nil
}

var serviceProbeIdentEnums = make(map[string]int)

func enumerate(in string) string {
	if v, ok := serviceProbeIdentEnums[in]; ok {
		serviceProbeIdentEnums[in]++

		return in + "-" + strconv.Itoa(v+1)
	}

	serviceProbeIdentEnums[in] = 1

	return in + "-1"
}

// ResetProbeEnums clears the service probe enumeration map
// This should be called when resetting state between processing different files
func ResetProbeEnums() {
	serviceProbeIdentEnums = make(map[string]int)
}

func initServiceProbes() error {
	// load nmap service probes
	data, err := ioutil.ReadFile(filepath.Join(resolvers.DataBaseFolderPath, "nmap-service-probes"))
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	serviceProbes = make(map[string][]*serviceProbe, 0)

	for _, line := range lines {
		if len(line) == 0 || line == "\n" || strings.HasPrefix(line, "#") {
			// ignore comments and blanks
			continue
		}

		if strings.HasPrefix(line, "match") {

			// check if rule ident field has been excluded
			ident := strings.Fields(line)[1]
			if decoderconfig.Instance.UseRE2 {
				if _, ok := ignoredProbesRE2[ident]; ok {
					serviceLog.Debug("ignoring probe", zap.String("ident", ident))

					continue
				}
			} else {
				if _, ok := ignoredProbes[ident]; ok {
					serviceLog.Debug("ignoring probe", zap.String("ident", ident))

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
				s         = new(serviceProbe)
				b         byte
			)

			// enumerate the ident type (e.g: http -> http-1 for the first http banner probe)
			// useful to see which rule matched exactly, since multiple rules for the same protocol / service are usually present
			s.Ident = enumerate(ident)

			for {
				b, err = r.ReadByte()
				if errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					return err
				}

				if unicode.IsSpace(rune(b)) && !checkOpts {
					spaces++

					if delim != 0 {
						// collect whitespace when parsing the regex string
						regex = append(regex, b)
					}

					continue
				}
				// last part versionInfo: m/[regex]/[opts] [meta]
				// example: p/Amanda backup system index server/ i/broken: GLib $1 too old/ cpe:/a:amanda:amanda/
				if parseMeta { // skip over whitespace
					if unicode.IsSpace(rune(b)) {
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
									serviceLog.Error("error while parsing cpe tag for service probe",
										zap.Error(err),
										zap.String("probe", s.Ident),
									)

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

			if decoderconfig.Instance.UseRE2 {
				finalReg = clean(finalReg)
				s.RegEx, errCompile = regexp.Compile(finalReg)
			} else {
				s.RegExDotNet, errCompile = regexp2.Compile(finalReg, 0) // regexp.RE2)
			}

			if errCompile != nil {
				if decoderconfig.Instance.Debug {
					if decoderconfig.Instance.UseRE2 {
						if before != finalReg {
							serviceLog.Info("regex before != finalReg",
								zap.String("before", before),
							)
						}

						serviceLog.Info("failed to compile regex",
							zap.String("ident", s.Ident),
							zap.Error(errCompile),
							zap.String("regex", finalReg),
						) // stdlib regexp only logs the broken part of the regex. this logs the full regex string for debugging
					} else {
						serviceLog.Info("failed to compile regex",
							zap.String("ident", s.Ident),
							zap.Error(errCompile),
							zap.String("line", line),
						)
					}
				}
			} else {
				s.RegExRaw = finalReg
				if arr, ok := serviceProbes[ident]; ok {
					// MUST assign the result back to the map!
					// append() may create a new slice if capacity is exceeded
					serviceProbes[ident] = append(arr, s)
				} else {
					serviceProbes[ident] = []*serviceProbe{s}
				}
			}
		}
	}

	serviceLog.Info("loaded nmap service probes", zap.Int("total", len(serviceProbes)))

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

// dumpServiceProbes prints all loaded probes as JSON.
func dumpServiceProbes() {
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
// to ensure compatibility with the re2 engine.
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
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			fmt.Println(err)

			break
		}
		count++

		debug := func(args ...interface{}) {
			if !debugRegexClean {
				return
			}

			fmt.Println(string(lastchar), ansi.Blue, string(b), ansi.Red, startCount, stopCnt, ansi.Green, string(out), ansi.White, args, ansi.Reset, colorize(in, count), numIgnored)
		}

		if string(b) == "\\" && !escaped {
			debug("set escaped to true")

			escaped = true
		} else if escaped {
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

					out = append(out, byte('.'), byte('*'))
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
