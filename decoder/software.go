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

package decoder

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/blevesearch/bleve"
	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/ja3"
	"github.com/gogo/protobuf/proto"
	"github.com/ua-parser/uap-go/uaparser"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

const (
	protoTCP      = "TCP"
	protoUDP      = "UDP"
	serviceHTTP   = "HTTP"
	serviceSSH    = "SSH"
	servicePOP3   = "POP3"
	serviceTelnet = "Telnet"
	serviceFTP    = "FTP"

	sourceHeader = "HTTP Header"
	sourceCookie = "HTTP Cookie"
)

type software struct {
	*types.Software
	sync.Mutex
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicSoftwareMap struct {
	// mapped product + version to software
	Items map[string]*software
	sync.Mutex
}

var (
	userAgentCaching = make(map[string]*userAgent)
	regExpServerName = regexp.MustCompile(`(.*?)(?:/(.*?))?(?:\s*?)(?:\((.*?)\))?$`)
	regexpXPoweredBy = regexp.MustCompile(`(.*?)(?:(?:\s|/)(.*?))?$`)
	ja3Cache         = make(map[string]string)
	jaCacheMutex     sync.Mutex
	reGenericVersion = regexp.MustCompile(`(?m)(?:^)(.*?)(\d+)\.(\d+)\.(\d+)(.*?)(?:$)`)
	// Used to store CMS related information, and to do the CMS lookup.
	cmsDB                = make(map[string]*cmsInfo)
	vulnerabilitiesIndex bleve.Index
	exploitsIndex        bleve.Index
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
	// softwareStore hold all connections.
	softwareStore = &atomicSoftwareMap{
		Items: make(map[string]*software),
	}

	parser, errInitUAParser = uaparser.New(filepath.Join(resolvers.DataBaseSource, "regexes.yaml"))
	pMu                     sync.Mutex

	ja3db     ja3CombinationsDB
	hasshDB   []sshHash
	hashDBMap map[string][]sshSoftware
)

type userAgent struct {
	client  *uaparser.Client
	product string
	vendor  string
	version string
	full    string
	os      string
}

type process struct {
	Process string `json:"process"`
	JA3     string `json:"JA3"`
	JA3s    string `json:"JA3S"`
}

type client struct {
	Os        string    `json:"os"`
	Arch      string    `json:"arch"`
	Processes []process `json:"processes"`
}

type server struct {
	Server  string   `json:"server"`
	Clients []client `json:"clients"`
}

type ja3CombinationsDB struct {
	Servers []server `json:"servers"`
}

type sshSoftware struct {
	Version    string `json:"name"`
	Likelihood string `json:"likelyhood"` // dont remove this typo, or the hasshdb.json cannot be read!
}

type sshHash struct {
	Hash     string        `json:"hash"`
	Software []sshSoftware `json:"softwares"` // dont remove this typo, or the hasshdb.json cannot be read!
}

// process a raw user agent string and returned a structured instance.
func parseUserAgent(ua string) *userAgent {
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
		client:  uaClient,
		product: product,
		vendor:  vendor,
		version: version,
		os:      osName,
		full:    strings.TrimSpace(full),
	}
}

// determine vendor name based on product name
func determineVendor(product string) (vendor string) {
	switch product {
	case "Chrome", "Android":
		vendor = "Google"
	case "Firefox":
		vendor = "Mozilla"
	case "Internet Explorer", "IE":
		vendor = "Microsoft"
	case "Safari", "iOS", "macOS":
		vendor = "Apple"
	}
	return vendor
}

// generic version harvester, scans the payload using a regular expression.
func softwareHarvester(data []byte, flowIdent string, ts time.Time, service string, dpIdent string, protos []string) (s []*software) {
	matches := reGenericVersion.FindAll(data, -1)

	//fmt.Println("got", len(matches), "matches")
	//for _, m := range matches {
	//	fmt.Println(string(m))
	//}

	if len(matches) > 0 {
		for _, v := range matches {
			s = append(s, &software{
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

// tries to determine the kind of software and version
// based on the provided input data.
func whatSoftware(dp *deviceProfile, i *packetInfo, flowIdent, serviceNameSrc, serviceNameDst, JA3, JA3s string, protos []string) (s []*software) {
	var (
		serviceIdent string
		dpIdent      = dp.MacAddr
	)

	if serviceNameSrc != "" {
		serviceIdent = serviceNameSrc
	}

	if serviceNameDst != "" {
		serviceIdent = serviceNameDst
	}

	if dp.DeviceManufacturer != "" {
		dpIdent += " <" + dp.DeviceManufacturer + ">"
	}

	// Only do JA3 fingerprinting when both fingerprints for client and server are present
	// TODO: improve efficiency for this lookup
	if len(JA3) > 0 && len(JA3s) > 0 {
		// for each server
		for _, srv := range ja3db.Servers {
			// for each client
			for _, c := range srv.Clients {
				// for each process
				for _, p := range c.Processes {
					// if the process had both client and server fingerprints
					if p.JA3 == JA3 && p.JA3s == JA3s {
						values := regExpServerName.FindStringSubmatch(srv.Server)
						s = append(s, &software{
							Software: &types.Software{
								Timestamp:      i.timestamp,
								Product:        values[1], // Name of the server (Apache, Nginx, ...)
								Version:        values[2], // Version as found after the '/'
								Vendor:         values[3], // Often the operating system
								DeviceProfiles: []string{dpIdent},
								SourceName:     "JA3s",
								SourceData:     JA3s,
								Service:        serviceIdent,
								DPIResults:     protos,
								Flows:          []string{flowIdent},
							},
						}, &software{
							Software: &types.Software{
								Timestamp:      i.timestamp,
								Product:        p.Process,                 // Name of the browser, including version
								Vendor:         c.Os + "(" + c.Arch + ")", // Name of the OS
								Version:        "",                        // TODO parse client name
								DeviceProfiles: []string{dpIdent},
								SourceName:     "JA3",
								SourceData:     JA3,
								Service:        serviceIdent,
								DPIResults:     protos,
								Flows:          []string{flowIdent},
							},
						})
					}
				}
			}
		}
	}

	// if nothing was found with all above attempts, try to throw the generic version number harvester at it
	// and see if this delivers anything interesting
	if len(s) == 0 && !conf.DisableGenericVersionHarvester {
		return softwareHarvester(i.p.Data(), flowIdent, i.p.Metadata().CaptureInfo.Timestamp, serviceIdent, dpIdent, protos)
	}

	return s
}

// TODO: pass in the device profile.
func whatSoftwareHTTP(flowIdent string, h *types.HTTP) (s []*software) {
	// HTTP User Agents
	// TODO: check for userAgents retrieved by Ja3 lookup as well
	if h.UserAgent != "" && h.UserAgent != " " {

		pMu.Lock()

		userInfo, ok := userAgentCaching[h.UserAgent]
		if !ok {
			userInfo = parseUserAgent(h.UserAgent)
			userAgentCaching[h.UserAgent] = userInfo
			decoderLog.Debug("UserAgent:", zap.String("userInfo", userInfo.full))
		}

		pMu.Unlock()

		if userInfo.product != "" || userInfo.vendor != "" || userInfo.version != "" {
			s = append(s, &software{
				Software: &types.Software{
					Timestamp: h.Timestamp,
					Product:   userInfo.product,
					Vendor:    userInfo.vendor,
					Version:   userInfo.version,
					// DeviceProfiles: []string{dpIdent},
					SourceName: "UserAgent",
					SourceData: h.UserAgent,
					Service:    serviceHTTP,
					Flows:      []string{flowIdent},
					Notes:      userInfo.full,
					OS:         userInfo.os,
				},
			})
		}
	}

	// HTTP Server Name
	if h.ServerName != "" && h.ServerName != " " {
		values := regExpServerName.FindStringSubmatch(h.ServerName)

		s = append(s, &software{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   values[1], // Name of the server (Apache, Nginx, ...)
				Version:   values[2], // Version as found after the '/'
				OS:        values[3], // potentially operating system
				// DeviceProfiles: []string{dpIdent},
				SourceName: "ServerName",
				SourceData: h.ServerName,
				Service:    serviceHTTP,
				Flows:      []string{flowIdent},
			},
		})
	}

	// X-Powered-By HTTP Header
	if poweredBy, ok := h.ResponseHeader["X-Powered-By"]; ok {
		if poweredBy != "" && poweredBy != " " {
			values := regexpXPoweredBy.FindStringSubmatch(poweredBy)

			s = append(s, &software{
				Software: &types.Software{
					Timestamp: h.Timestamp,
					Product:   values[1], // Name of the server (Apache, Nginx, ...)
					Version:   values[2], // Version as found after the '/'
					// DeviceProfiles: []string{dpIdent},
					SourceName: "X-Powered-By",
					SourceData: poweredBy,
					Service:    serviceHTTP,
					Flows:      []string{flowIdent},
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
		if _, ok := cmsHeaders[key]; ok {
			serverHeaders = append(serverHeaders, header{name: key, value: val})
		}
	}

	// Iterate over all response cookies and collect values for known cookies of frontend frameworks
	for _, co := range h.ResCookies {
		if _, ok := cmsCookies[co.Name]; ok {
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
		// for all items in the CMS db
		for product, info := range cmsDB {

			// compare the known headers
			for headerName, re := range info.Headers {

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
					s = append(s, makeSoftware(h.Timestamp, product, info.Website, sourceName, sourceData, flowIdent))

					if conf.StopAfterServiceProbeMatch {
						return s
					}
				}
			}

			// compare known cookies
			for cookieName, re := range info.Cookies {
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
					s = append(s, makeSoftware(h.Timestamp, product, info.Website, sourceName, sourceData, flowIdent))

					if conf.StopAfterServiceProbeMatch {
						return s
					}
				}
			}
		}
	}

	return s
}

func makeSoftware(ts int64, product, website, sourceName, sourceData, flowIdent string) *software {
	return &software{
		Software: &types.Software{
			Timestamp:  ts,
			Product:    product,
			Notes:      "", // TODO: add info from implies field
			Website:    website,
			SourceName: sourceName,
			SourceData: sourceData,
			Service:    serviceHTTP,
			Flows:      []string{flowIdent},
		},
	}
}

// analyzeSoftware tries to identify software based on observations from the data
// this function first gathers as much data as possible and then calls into whatSoftware
// to determine what software the packet belongs to.
func analyzeSoftware(i *packetInfo) {
	var (
		serviceNameSrc, serviceNameDst string
		ja3Hash                        = ja3.DigestHexPacket(i.p)
		JA3s                           string
		JA3                            string
		protos                         []string
		f                              string
	)

	if ja3Hash == "" {
		ja3Hash = ja3.DigestHexPacketJa3s(i.p)
	}

	// Lookup Service For Port Numbers
	if tl := i.p.TransportLayer(); tl != nil { // set flow ident
		f = utils.CreateFlowIdent(i.srcIP, tl.TransportFlow().Src().String(), i.dstIP, tl.TransportFlow().Dst().String())

		// get source port and convert to integer
		src, err := strconv.Atoi(tl.TransportFlow().Src().String())
		if err == nil {
			switch tl.LayerType() {
			case layers.LayerTypeTCP:
				serviceNameSrc = resolvers.LookupServiceByPort(src, typeTCP)
			case layers.LayerTypeUDP:
				serviceNameSrc = resolvers.LookupServiceByPort(src, typeUDP)
			default:
			}
		}

		dst, err := strconv.Atoi(tl.TransportFlow().Dst().String())
		if err == nil {
			switch tl.LayerType() {
			case layers.LayerTypeTCP:
				serviceNameDst = resolvers.LookupServiceByPort(dst, typeTCP)
			case layers.LayerTypeUDP:
				serviceNameDst = resolvers.LookupServiceByPort(dst, typeUDP)
			default:
			}
		}
	} else {
		// no transport layer
		f = i.srcIP + "->" + i.dstIP
	}

	// Deep Packet Inspection
	results := dpi.GetProtocols(i.p)
	for p := range results {
		protos = append(protos, p)
	}

	// The underlying assumption is that we will always observe a client TLS Hello before seeing a server TLS Hello
	// Assuming the packet captured corresponds to the server Hello, first try to see if a client Hello (client being the
	// destination IP) was observed. If not, this is the client. Therefore add client ja3 signature to the store.
	if len(ja3Hash) > 0 {
		var ok bool
		jaCacheMutex.Lock()
		JA3, ok = ja3Cache[i.dstIP]
		jaCacheMutex.Unlock()
		if !ok {
			jaCacheMutex.Lock()
			ja3Cache[i.srcIP] = ja3Hash
			jaCacheMutex.Unlock()

			JA3 = ""
			JA3s = ""
		} else {
			JA3s = ja3Hash
		}
	}

	// fetch the associated device profile
	dp := getDeviceProfile(i.srcMAC, i)

	// now that we have some information at hands
	// try to determine what kind of software it is
	soft := whatSoftware(dp, i, f, serviceNameSrc, serviceNameDst, JA3, JA3s, protos)
	if len(soft) == 0 {
		return
	}

	writeSoftware(soft, func(s *software) {
		updateSoftwareAuditRecord(dp, s, i)
	})
}

func writeSoftware(software []*software, update func(s *software)) {
	var newSoftwareProducts []*types.Software

	// add new audit records or update existing
	softwareStore.Lock()
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
		if item, ok := softwareStore.Items[ident]; ok {
			if update != nil {
				update(item)
			}
		} else {
			// fmt.Println(SoftwareStore.Items, s.Product, s.Version)
			softwareStore.Items[ident] = s

			stats.Lock()
			stats.numSoftware++
			stats.Unlock()

			newSoftwareProducts = append(newSoftwareProducts, s.Software)
		}
	}
	softwareStore.Unlock()

	if len(newSoftwareProducts) > 0 {
		// lookup known issues with identified software in the background
		go func() {
			for _, s := range newSoftwareProducts {
				vulnerabilitiesLookup(s)
				exploitsLookup(s)
			}
		}()
	}
}

// newSoftware creates a new device specific profile.
func newSoftware(i *packetInfo) *software {
	return &software{
		Software: &types.Software{
			Timestamp: i.timestamp,
		},
	}
}

func updateSoftwareAuditRecord(dp *deviceProfile, s *software, i *packetInfo) {
	dpIdent := dp.MacAddr
	if dp.DeviceManufacturer != "" {
		dpIdent += " <" + dp.DeviceManufacturer + ">"
	}

	s.Lock()
	for _, pr := range s.DeviceProfiles {
		if pr == dpIdent {
			s.Unlock()
			return
		}
	}
	s.DeviceProfiles = append(s.DeviceProfiles, dpIdent)
	tl := i.p.TransportLayer()
	if tl != nil {
		s.Flows = append(s.Flows, utils.CreateFlowIdent(i.srcIP, tl.TransportFlow().Src().String(), i.dstIP, tl.TransportFlow().Dst().String()))
	} else {
		// no transport layer
		s.Flows = append(s.Flows, i.srcIP+"->"+i.dstIP)
	}
	s.Unlock()
}

var softwareDecoder = newCustomDecoder(
	types.Type_NC_Software,
	"Software",
	"A software product that was observed on the network",
	func(d *customDecoder) error {
		if errInitUAParser != nil {
			return errInitUAParser
		}

		// Load the JSON database of JA3/JA3S combinations into memory
		data, err := ioutil.ReadFile(filepath.Join(resolvers.DataBaseSource, "ja_3_3s.json"))
		if err != nil {
			return err
		}

		// unpack JSON
		err = json.Unmarshal(data, &ja3db.Servers)
		if err != nil {
			return err
		}

		// Load the JSON database of HASSH signaures
		data, err = ioutil.ReadFile(filepath.Join(resolvers.DataBaseSource, "hasshdb.json"))
		if err != nil {
			return err
		}

		// unpack JSON
		err = json.Unmarshal(data, &hasshDB)
		if err != nil {
			return err
		}

		hashDBMap = make(map[string][]sshSoftware)

		for _, v := range hasshDB {
			hashDBMap[v.Hash] = v.Software
		}

		decoderLog.Info("loaded HASSH digests", zap.Int("total", len(hashDBMap)))

		// read CMS db JSON
		err = loadCmsDB()
		if err != nil {
			return err
		}

		decoderLog.Info("loaded CMS db", zap.Int("total", len(cmsDB)))

		// Load vulnerabilities DB index
		indexName := filepath.Join(resolvers.DataBaseSource, vulnDBPath)
		vulnerabilitiesIndex, err = openBleve(indexName)
		if err != nil {
			return err
		}

		decoderLog.Info("loaded Ja3/ja3S database", zap.Int("total_records", len(ja3db.Servers)))

		return nil
	},
	func(p gopacket.Packet) proto.Message {
		// handle packet
		analyzeSoftware(newPacketInfo(p))

		return nil
	},
	func(e *customDecoder) error {
		// TODO: make collecting and dumping unique useragents, server names and header fields configurable
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
		for _, item := range softwareStore.Items {
			item.Lock()
			e.write(item.Software)
			item.Unlock()
		}

		closeBleve(vulnerabilitiesIndex)

		return nil
	},
)

// load JSON database for frontend frameworks from the file system
func loadCmsDB() error {
	// read CMS db JSON
	data, err := ioutil.ReadFile(filepath.Join(resolvers.DataBaseSource, "cmsdb.json"))
	if err != nil {
		return err
	}

	// use gabs to parse JSON because some fields have varying types...
	jsonParsed, err := gabs.ParseJSON(data)
	if err != nil {
		return err
	}

	// parse the contained regexes and add them to the cmsInfo datastructures
	for framework := range jsonParsed.ChildrenMap() {

		i := new(cmsInfo)

		// fmt.Printf("key: %v, value: %v\n", framework, child.Data().(map[string]interface{}))

		if s, ok := jsonParsed.Path(framework + ".icon").Data().(string); ok {
			i.Icon = s
		}
		if s, ok := jsonParsed.Path(framework + ".cpe").Data().(string); ok {
			i.Cpe = s
		}

		if s, ok := jsonParsed.Path(framework + ".headers").Data().(map[string]interface{}); ok {

			i.Headers = make(map[string]*regexp.Regexp)

			// process headers
			for name, re := range s {
				// add to map for lookups by name during runtime
				cmsHeaders[name] = struct{}{}

				// compile the supplied regex
				r, err := regexp.Compile(fmt.Sprint(re))
				if err != nil {
					decoderLog.Info("failed to compile regex from CMS db HEADER",
						zap.Error(err),
						zap.String("re", fmt.Sprint(re)),
						zap.String("framework", framework),
					)
				} else {
					i.Headers[name] = r
				}
			}
		}

		if s, ok := jsonParsed.Path(framework + ".cookies").Data().(map[string]interface{}); ok {

			i.Cookies = make(map[string]*regexp.Regexp)

			// process cookies
			for name, re := range s {
				// add to map for lookups by name during runtime
				cmsCookies[name] = struct{}{}

				// compile the supplied regex
				r, err := regexp.Compile(fmt.Sprint(re))
				if err != nil {
					decoderLog.Info("failed to compile regex from CMS db COOKIE",
						zap.Error(err),
						zap.String("re", fmt.Sprint(re)),
						zap.String("framework", framework),
					)
				} else {
					i.Cookies[name] = r
				}
			}
		}

		if s, ok := jsonParsed.Path(framework + ".js").Data().(map[string]interface{}); ok {
			m := make(map[string]string)
			for k, v := range s {
				m[k] = fmt.Sprint(v)
			}
			i.Js = m
		}

		if s, ok := jsonParsed.Path(framework + ".meta").Data().(map[string]interface{}); ok {
			m := make(map[string]string)
			for k, v := range s {
				m[k] = fmt.Sprint(v)
			}
			i.Meta = m
		}

		if s, ok := jsonParsed.Path(framework + ".website").Data().(string); ok {
			i.Website = s
		}

		if s, ok := jsonParsed.Path(framework + ".implies").Data().(string); ok {
			i.Implies = []string{s}
		}
		if s, ok := jsonParsed.Path(framework + ".implies").Data().([]string); ok {
			i.Implies = s
		}

		if s, ok := jsonParsed.Path(framework + ".script").Data().(string); ok {
			i.Script = []string{s}
		}
		if s, ok := jsonParsed.Path(framework + ".script").Data().([]string); ok {
			i.Script = s
		}

		if s, ok := jsonParsed.Path(framework + ".html").Data().(string); ok {
			i.HTML = []string{s}
		}
		if s, ok := jsonParsed.Path(framework + ".html").Data().([]string); ok {
			i.HTML = s
		}

		// spew.Dump(i)

		cmsDB[framework] = i
	}

	return nil
}

// writeDeviceProfile writes the profile.
func (cd *customDecoder) write(r types.AuditRecord) {
	if conf.ExportMetrics {

		// TODO: remove for production builds?
		defer func() {
			if errRecover := recover(); errRecover != nil {
				spew.Dump(r)
				fmt.Println("recovered from panic", errRecover)
			}
		}()

		r.Inc()
	}

	atomic.AddInt64(&cd.numRecords, 1)
	err := cd.writer.Write(r.(proto.Message))
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
