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

package software

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/ua-parser/uap-go/uaparser"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/db"
	"github.com/dreadl0ck/netcap/decoder/stream/exploit"
	"github.com/dreadl0ck/netcap/decoder/stream/vulnerability"
	"github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

var softwareLog = zap.NewNop()

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_Software,
	Name:        "Software",
	Description: "A software product that was observed on the network",
	PostInit: func(d *decoder.AbstractDecoder) error {
		var err error
		softwareLog, _, err = logger.InitZapLogger(
			decoderconfig.Instance.Out,
			"software",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}

		if errInitUAParser != nil {
			return errInitUAParser
		}

		// Load the JSON database of SSH fingerprint signatures (legacy HASSH format)
		data, err := ioutil.ReadFile(filepath.Join(resolvers.DataBaseFolderPath, "hasshdb.json"))
		if err != nil {
			return err
		}

		// unpack JSON
		err = json.Unmarshal(data, &hasshDB)
		if err != nil {
			return err
		}

		HashDBMap = make(map[string][]sshSoftware)

		for _, v := range hasshDB {
			HashDBMap[v.Hash] = v.Software
		}

		softwareLog.Info("loaded SSH fingerprint digests", zap.Int("total", len(HashDBMap)))

		// read CMS db JSON
		err = loadCmsDB()
		if err != nil {
			return errors.Wrap(err, "failed to load CMS database")
		}

		softwareLog.Info("loaded CMS db", zap.Int("total", len(cmsDB)))

		// Build the optional Hyperscan prefilter for CMS header / cookie
		// regex matching. With the `hyperscan` build tag this populates
		// per-source HS databases used by generateSoftware to skip the
		// full cmsDB nested loop. Without the tag this is a no-op.
		buildCMSHSIndex()

		// Load vulnerabilities DB index
		indexName := filepath.Join(resolvers.DataBaseFolderPath, db.VulnerabilityDBName)
		db.VulnerabilitiesIndex, err = db.OpenBleve(indexName)
		if err != nil {
			// explicitly set to nil, otherwise it can't be determined whether the init succeeded later on
			db.VulnerabilitiesIndex = nil

			return errors.Wrap(err, "failed to open vulnerability bleve index at: "+indexName)
		}

		return nil
	},
	DeInit: func(e *decoder.AbstractDecoder) error {
		// TODO: make collecting and dumping unique user agents, server names and header fields configurable
		//httpStore.Lock()
		//var rows [][]string
		//for ip, ua := range httpStore.UserAgents {
		//	rows = append(rows, []string{ip, ua})
		//}
		//tui.Table(decoderLogFileHandle, []string{"IP", "UserAgents"}, rows)
		//rows = [][]string{}
		//for ip, sn := range httpStore.ServerNames {
		//	rows = append(rows, []string{ip, sn})
		//}
		//tui.Table(decoderLogFileHandle, []string{"IP", "ServerNames"}, rows)
		//httpStore.Unlock()

		// flush writer
		var err error

		// stable output order: Store.Items is a map
		idents := make([]string, 0, len(Store.Items))
		for ident := range Store.Items {
			idents = append(idents, ident)
		}
		sort.Strings(idents)

		for _, ident := range idents {
			item := Store.Items[ident]
			item.Lock()

			// Enhance software record with detection context and behavioral fields
			EnhanceSoftwareRecord(item.Software)

			// Update instance count based on number of flows
			item.Software.InstanceCount = int32(len(item.Software.Flows))

			err = e.Writer.Write(item.Software)
			if err != nil {
				softwareLog.Error("failed to flush software audit record", zap.Error(err))
			}

			atomic.AddInt64(&e.NumRecordsWritten, 1)
			item.Unlock()
		}

		db.CloseBleve(db.VulnerabilitiesIndex)

		return softwareLog.Sync()
	},
}

// header is a HTTP header structure.
type header struct {
	name  string
	value string
}

// cookie is a HTTP cookie structure.
type cookie struct {
	name  string
	value string
}

const (
	sourceHeader = "HTTP Header"
	sourceCookie = "HTTP Cookie"
)

// AtomicSoftware wraps a types.Software to provide atomic access.
type AtomicSoftware struct {
	sync.Mutex
	*types.Software
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicSoftwareMap struct {
	sync.Mutex
	// mapped product + version to software
	Items map[string]*AtomicSoftware
}

var (
	// UserAgentCache contains parsed user agents at runtime.
	UserAgentCache   = make(map[string]*userAgent)
	regExpServerName = regexp.MustCompile(`(.*?)(?:/(.*?))?(?:\s*?)(?:\((.*?)\))?$`)
	regexpXPoweredBy = regexp.MustCompile(`(.*?)(?:(?:\s|/)(.*?))?$`)
	cacheMutex       sync.Mutex

	// RegexGenericVersion is a regular expression for anything that could be a product / version indicator.
	RegexGenericVersion = regexp.MustCompile(`(?m)(?:^)(.*?)(\d+)\.(\d+)\.(\d+)(.*?)(?:$)`)

	// Used to store CMS related information, and to do the CMS lookup.
	cmsDB = make(map[string]*cmsInfo)
)

type cmsInfo struct {
	Cats    []int             `json:"cats"`
	Cpe     string            `json:"cpe"`
	HTML    []string          `json:"html"`
	Implies []string          `json:"implies"`
	Script  []string          `json:"script"`
	Icon    string            `json:"icon"`
	Js      map[string]string `json:"js"`
	Meta    map[string]string `json:"meta"`
	Website string            `json:"website"`

	Cookies map[string]*regexp.Regexp `json:"cookies"`
	Headers map[string]*regexp.Regexp `json:"headers"`
}

// Size returns the number of elements in the Items map.
func (a *atomicSoftwareMap) Size() int {
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

var (
	// Store SoftwareStore hold all connections.
	Store = &atomicSoftwareMap{
		Items: make(map[string]*AtomicSoftware),
	}

	parser, errInitUAParser = uaparser.New(filepath.Join(resolvers.DataBaseFolderPath, "regexes.yaml"))

	// UserAgentParserMutex ensures atomic access to the user agent parser.
	UserAgentParserMutex sync.Mutex

	hasshDB []sshHash
	// HashDBMap contains SSH fingerprint digests mapped to software products at runtime.
	HashDBMap map[string][]sshSoftware
)

// userAgent is a browser user agent.
type userAgent struct {
	Client  *uaparser.Client
	Product string
	Vendor  string
	Version string
	Full    string
	OS      string
}

type sshSoftware struct {
	Version    string `json:"name"`
	Likelihood string `json:"likelyhood"` // dont remove this typo, or the hasshdb.json cannot be read!
}

type sshHash struct {
	Hash     string        `json:"hash"`
	Software []sshSoftware `json:"softwares"` // dont remove this typo, or the hasshdb.json cannot be read!
}

// ParseUserAgent processes a raw user agent string and returned a structured instance.
func ParseUserAgent(ua string) *userAgent {

	if parser == nil {
		return nil
	}

	var (
		uaClient                       = parser.Parse(ua)
		full, product, vendor, version string
	)

	if uaClient.UserAgent != nil {
		vendor = uaClient.UserAgent.Family
		version = uaClient.UserAgent.Major
		if uaClient.UserAgent.Minor != "" {
			version += "." + uaClient.UserAgent.Minor
		}
		if uaClient.UserAgent.Patch != "" {
			version += "." + uaClient.UserAgent.Patch
		}
		full += " " + uaClient.UserAgent.Family
		full += " " + uaClient.UserAgent.Major
		full += " " + uaClient.UserAgent.Minor
		full += " " + uaClient.UserAgent.Patch

		if vendor == "Other" {
			vendor = ""
		}
	}
	if uaClient.Os != nil {
		full += " " + uaClient.Os.Family
		full += " " + uaClient.Os.Major
		full += " " + uaClient.Os.Minor
		full += " " + uaClient.Os.Patch
		full += " " + uaClient.Os.PatchMinor
	}
	if uaClient.Device != nil {
		product = uaClient.Device.Family
		full += " " + uaClient.Device.Family

		if product == "Other" {
			product = ""
		}
	}

	// if vendor could not be identified, try to determine based on product name
	if vendor == "" {
		vendor = determineVendor(product)
	}

	osName := uaClient.Os.ToString()
	if osName == "Other" {
		osName = ""
	}

	return &userAgent{
		Client:  uaClient,
		Product: product,
		Vendor:  vendor,
		Version: version,
		OS:      osName,
		Full:    strings.TrimSpace(full),
	}
}

// generic version harvester, scans the payload using a regular expression.
func softwareHarvester(data []byte, flowIdent string, ts time.Time, service string, dpIdent string, protos []string) (s []*AtomicSoftware) {
	matches := RegexGenericVersion.FindAll(data, -1)

	//fmt.Println("got", len(matches), "matches")
	//for _, m := range matches {
	//	fmt.Println(string(m))
	//}

	if len(matches) > 0 {
		for _, v := range matches {
			s = append(s, &AtomicSoftware{
				Software: &types.Software{
					Timestamp:      ts.UnixNano(),
					DeviceProfiles: []string{dpIdent},
					SourceName:     "Generic version harvester",
					SourceData:     string(data),
					Service:        service,
					DPIResults:     protos,
					Flows:          []string{flowIdent},
					Notes:          string(v),
				},
			})
		}
	}

	return s
}

// WhatSoftwareHTTP TODO: pass in the device profile.
func WhatSoftwareHTTP(flowIdent string, h *types.HTTP) (s []*AtomicSoftware) {
	// Get community ID from the HTTP record for correlation
	communityID := h.CommunityID

	// HTTP User Agents
	if h.UserAgent != "" && h.UserAgent != " " {

		UserAgentParserMutex.Lock()

		userInfo, ok := UserAgentCache[h.UserAgent]
		if !ok {
			userInfo = ParseUserAgent(h.UserAgent)
			if userInfo != nil {
				UserAgentCache[h.UserAgent] = userInfo
				softwareLog.Debug("UserAgent:", zap.String("userInfo", userInfo.Full))
			}
		}

		UserAgentParserMutex.Unlock()

		if userInfo != nil {
			if userInfo.Product != "" || userInfo.Vendor != "" || userInfo.Version != "" {
				var communityIDs []string
				if communityID != "" {
					communityIDs = []string{communityID}
				}
				s = append(s, &AtomicSoftware{
					Software: &types.Software{
						Timestamp: h.Timestamp,
						Product:   userInfo.Product,
						Vendor:    userInfo.Vendor,
						Version:   userInfo.Version,
						// DeviceProfiles: []string{dpIdent},
						SourceName:   "UserAgent",
						SourceData:   h.UserAgent,
						Service:      "HTTP",
						Flows:        []string{flowIdent},
						Notes:        userInfo.Full,
						OS:           userInfo.OS,
						CommunityIDs: communityIDs,
					},
				})
			}
		}
	}

	// HTTP Server Name
	if h.ServerName != "" && h.ServerName != " " {
		values := regExpServerName.FindStringSubmatch(h.ServerName)

		var communityIDs []string
		if communityID != "" {
			communityIDs = []string{communityID}
		}
		s = append(s, &AtomicSoftware{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   values[1], // Name of the server (Apache, Nginx, ...)
				Version:   values[2], // Version as found after the '/'
				OS:        values[3], // potentially operating system
				// DeviceProfiles: []string{dpIdent},
				SourceName:   "ServerName",
				SourceData:   h.ServerName,
				Service:      "HTTP",
				Flows:        []string{flowIdent},
				CommunityIDs: communityIDs,
			},
		})
	}

	// X-Powered-By HTTP Header
	if poweredBy, ok := h.ResponseHeader["X-Powered-By"]; ok {
		if poweredBy != "" && poweredBy != " " {
			values := regexpXPoweredBy.FindStringSubmatch(poweredBy)

			var communityIDs []string
			if communityID != "" {
				communityIDs = []string{communityID}
			}
			s = append(s, &AtomicSoftware{
				Software: &types.Software{
					Timestamp: h.Timestamp,
					Product:   values[1], // Name of the server (Apache, Nginx, ...)
					Version:   values[2], // Version as found after the '/'
					// DeviceProfiles: []string{dpIdent},
					SourceName:   "X-Powered-By",
					SourceData:   poweredBy,
					Service:      "HTTP",
					Flows:        []string{flowIdent},
					CommunityIDs: communityIDs,
				},
			})
		}
	}

	var (
		serverHeaders = make([]header, 0, len(h.ResponseHeader))
		serverCookies = make([]cookie, 0, len(h.ResCookies))
	)

	// Iterate over all response headers and collect values for known headers of frontend frameworks
	for key, val := range h.ResponseHeader {
		if _, ok := CMSHeaders[key]; ok {
			serverHeaders = append(serverHeaders, header{name: key, value: val})
		}
	}

	// Iterate over all response cookies and collect values for known cookies of frontend frameworks
	for _, co := range h.ResCookies {
		if _, ok := CMSCookies[co.Name]; ok {
			serverCookies = append(serverCookies, cookie{name: co.Name, value: co.Value})
		}
	}

	if len(serverCookies) == 0 && len(serverHeaders) == 0 {
		return s
	}

	var (
		sourceName string
		sourceData string
	)

	if len(serverHeaders) > 0 {
		// Optional Hyperscan prefilter: ask the per-source HS DB for the
		// union of products that any of the received headers/cookies
		// might match. Falls back to the full cmsDB sweep when HS is
		// disabled or returns nil for a particular (name, value) pair.
		candidates := cmsCandidateProducts(serverHeaders, serverCookies)

		productOrder := make([]string, 0, len(cmsDB))
		if candidates == nil {
			for product := range cmsDB {
				productOrder = append(productOrder, product)
			}
		} else {
			for product := range candidates {
				productOrder = append(productOrder, product)
			}
		}
		// Both sources are maps and the first match can end the scan, so the
		// reported product would otherwise change between runs.
		sort.Strings(productOrder)

		// for all items in the CMS db (or the prefiltered subset)
		for _, product := range productOrder {
			info, ok := cmsDB[product]
			if !ok {
				continue
			}

			// compare the known headers, in a stable order
			headerNames := make([]string, 0, len(info.Headers))
			for headerName := range info.Headers {
				headerNames = append(headerNames, headerName)
			}
			sort.Strings(headerNames)

			for _, headerName := range headerNames {
				re := info.Headers[headerName]

				matchesHeader := func() bool {
					// to each of the headers from the current response
					for _, receivedHeader := range serverHeaders {

						equal := strings.EqualFold(receivedHeader.name, headerName)

						// if header name matches and we have no regex to check the value against
						if equal && re == nil {
							sourceName = sourceHeader
							sourceData = "header name match"

							return true
						}

						if re != nil {
							// if the header name matches and the regex matches the value of the header
							if equal && re.MatchString(receivedHeader.value) {
								sourceName = sourceHeader
								sourceData = "regex match on value: " + receivedHeader.value

								// fmt.Println(receivedHeader.name, receivedHeader.value, "MATCH", sourceHeader, product)

								return true
							}
						}
					}
					return false
				}

				if matchesHeader() {

					// we found a match
					s = append(s, makeSoftware(h.Timestamp, product, info.Website, sourceName, sourceData, flowIdent, communityID))

					if decoderconfig.Instance.StopAfterServiceProbeMatch {
						return s
					}
				}
			}

			// compare known cookies, in a stable order
			cookieNames := make([]string, 0, len(info.Cookies))
			for cookieName := range info.Cookies {
				cookieNames = append(cookieNames, cookieName)
			}
			sort.Strings(cookieNames)

			for _, cookieName := range cookieNames {
				re := info.Cookies[cookieName]
				matchesCookie := func() bool {
					// to each of the cookies from the current response
					for _, receivedCookie := range serverCookies {

						equal := strings.EqualFold(receivedCookie.name, cookieName)
						if equal && re == nil {
							sourceName = sourceCookie
							sourceData = "cookie name match"

							return true
						}

						if re != nil {
							// or the regex matches the value of the header
							if equal && re.MatchString(receivedCookie.value) {
								sourceName = sourceCookie
								sourceData = "regex match on value: " + receivedCookie.value

								// fmt.Println(receivedCookie.name, receivedCookie.value, "MATCH", sourceCookie, product)

								return true
							}
						}
					}

					return false
				}

				if matchesCookie() {

					// we found a match
					s = append(s, makeSoftware(h.Timestamp, product, info.Website, sourceName, sourceData, flowIdent, communityID))

					if decoderconfig.Instance.StopAfterServiceProbeMatch {
						return s
					}
				}
			}
		}
	}

	return s
}

// cmsCandidateProducts unions the per-(name, value) candidate sets from
// the Hyperscan prefilter into a single product set. Returns nil when
// the prefilter is unavailable so the caller falls back to the full
// cmsDB iteration. Returning a non-nil empty map is meaningful: the
// prefilter examined every covered product and none matched.
func cmsCandidateProducts(headers []header, cookies []cookie) map[string]struct{} {
	var union map[string]struct{}
	merge := func(part map[string]struct{}) {
		if part == nil {
			// At least one (name, value) had no prefilter info → we
			// cannot safely shrink the iteration set; fall back.
			union = nil
			return
		}
		if union == nil {
			union = make(map[string]struct{}, len(part))
		}
		for p := range part {
			union[p] = struct{}{}
		}
	}

	probed := false
	for _, hh := range headers {
		c := cmsHeaderCandidates(hh.name, hh.value)
		if c == nil {
			return nil
		}
		probed = true
		merge(c)
		if union == nil {
			return nil
		}
	}
	for _, cc := range cookies {
		c := cmsCookieCandidates(cc.name, cc.value)
		if c == nil {
			return nil
		}
		probed = true
		merge(c)
		if union == nil {
			return nil
		}
	}
	if !probed {
		return nil
	}
	if union == nil {
		// All (name, value) calls returned non-nil empty maps.
		return map[string]struct{}{}
	}
	return union
}

// WriteSoftware can be used to write software to the software audit record writer.
func WriteSoftware(software []*AtomicSoftware, update func(s *AtomicSoftware)) {
	var newSoftwareProducts []*types.Software

	// add new audit records or update existing
	Store.Lock()
	for _, s := range software {
		if s == nil {
			continue
		}
		s.Lock()

		if s.Software == nil {
			s.Unlock()
			continue
		}

		ident := s.Product + "/" + s.Version

		// trim version field if its too long
		// likely a regex matched too much text
		if len(s.Version) > 15 {
			s.Version = s.Version[:15] + "..."
		}
		s.Unlock()
		if item, ok := Store.Items[ident]; ok {
			if update != nil {
				update(item)
			}
		} else {
			// fmt.Println(SoftwareStore.Items, s.Product, s.Version)
			Store.Items[ident] = s

			newSoftwareProducts = append(newSoftwareProducts, s.Software)
		}
	}
	Store.Unlock()

	if len(newSoftwareProducts) > 0 {
		// lookup known issues with identified software
		// NOTE: Do NOT spawn goroutine here - causes goroutine leak!
		// These lookups are fast enough to do synchronously
		for _, s := range newSoftwareProducts {
			vulnerability.VulnerabilitiesLookup(s)
			exploit.ExploitsLookup(s)
		}
	}
}

//// newSoftware creates a new device specific profile.
//func newSoftware(i *decoderutils.PacketInfo) *AtomicSoftware {
//	return &AtomicSoftware{
//		Software: &types.Software{
//			Timestamp: i.Timestamp,
//		},
//	}
//}
//
//func updateSoftwareAuditRecord(dp *packet.DeviceProfile, s *AtomicSoftware, i *decoderutils.PacketInfo) {
//	dpIdent := dp.MacAddr
//	if dp.DeviceManufacturer != "" {
//		dpIdent += " <" + dp.DeviceManufacturer + ">"
//	}
//
//	s.Lock()
//	for _, pr := range s.DeviceProfiles {
//		if pr == dpIdent {
//			s.Unlock()
//			return
//		}
//	}
//	s.DeviceProfiles = append(s.DeviceProfiles, dpIdent)
//	tl := i.Packet.TransportLayer()
//	if tl != nil {
//		s.Flows = append(s.Flows, utils.CreateFlowIdent(i.SrcIP, tl.TransportFlow().Src().String(), i.DstIP, tl.TransportFlow().Dst().String()))
//	} else {
//		// no transport layer
//		s.Flows = append(s.Flows, i.SrcIP+"->"+i.DstIP)
//	}
//	s.Unlock()
//}

// ResetCaches clears all global caches to prevent memory accumulation
// between multi-file processing runs.
// CRITICAL: This must be called between file processing to prevent unbounded memory growth.
func ResetCaches() {
	// Clear UserAgent cache
	cacheMutex.Lock()
	UserAgentCache = make(map[string]*userAgent)
	cacheMutex.Unlock()

	// CRITICAL: Clear software store - accumulates ALL software detections
	Store.Lock()
	Store.Items = make(map[string]*AtomicSoftware)
	Store.Unlock()

	// cmsDB is loaded once from file and should not be cleared
	// CMSCookies and CMSHeaders are also static configuration, not cleared
}
