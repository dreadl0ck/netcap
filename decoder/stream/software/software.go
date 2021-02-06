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

package software

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"regexp"
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
	"github.com/dreadl0ck/netcap/logger"
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

		// Load the JSON database of JA3/JA3S combinations into memory
		data, err := ioutil.ReadFile(filepath.Join(resolvers.DataBaseFolderPath, "ja_3_3s.json"))
		if err != nil {
			return err
		}

		// unpack JSON
		err = json.Unmarshal(data, &ja3db.Servers)
		if err != nil {
			return err
		}

		// Load the JSON database of HASSH signatures
		data, err = ioutil.ReadFile(filepath.Join(resolvers.DataBaseFolderPath, "hasshdb.json"))
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

		softwareLog.Info("loaded HASSH digests", zap.Int("total", len(HashDBMap)))

		// read CMS db JSON
		err = loadCmsDB()
		if err != nil {
			return errors.Wrap(err, "failed to load CMS database")
		}

		softwareLog.Info("loaded CMS db", zap.Int("total", len(cmsDB)))

		// Load vulnerabilities DB index
		indexName := filepath.Join(resolvers.DataBaseFolderPath, db.VulnerabilityDBName)
		db.VulnerabilitiesIndex, err = db.OpenBleve(indexName)
		if err != nil {
			// explicitly set to nil, otherwise it can't be determined whether the init succeeded later on
			db.VulnerabilitiesIndex = nil

			return errors.Wrap(err, "failed to open vulnerability bleve index at: "+indexName)
		}

		softwareLog.Info("loaded Ja3/ja3S database", zap.Int("total_records", len(ja3db.Servers)))

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
		for _, item := range Store.Items {
			item.Lock()
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
	ja3Cache         = make(map[string]string)
	jaCacheMutex     sync.Mutex

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

	ja3db   ja3CombinationsDB
	hasshDB []sshHash
	// HashDBMap contains HASSH digests mapped to software products at runtime.
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

// TODO: cleanup
// tries to determine the kind of software and version
// based on the provided input data.
//func whatSoftware(dp *packet.DeviceProfile, i *decoderutils.PacketInfo, flowIdent, serviceNameSrc, serviceNameDst, JA3, JA3s string, protos []string) (s []*AtomicSoftware) {
//	var (
//		serviceIdent string
//		dpIdent      = dp.MacAddr
//	)
//
//	if serviceNameSrc != "" {
//		serviceIdent = serviceNameSrc
//	}
//
//	if serviceNameDst != "" {
//		serviceIdent = serviceNameDst
//	}
//
//	if dp.DeviceManufacturer != "" {
//		dpIdent += " <" + dp.DeviceManufacturer + ">"
//	}
//
//	// Only do JA3 fingerprinting when both fingerprints for client and server are present
//	// TODO: improve efficiency for this lookup
//	if len(JA3) > 0 && len(JA3s) > 0 {
//		// for each server
//		for _, srv := range ja3db.Servers {
//			// for each client
//			for _, c := range srv.Clients {
//				// for each process
//				for _, p := range c.Processes {
//					// if the process had both client and server fingerprints
//					if p.JA3 == JA3 && p.JA3s == JA3s {
//						values := regExpServerName.FindStringSubmatch(srv.Server)
//						s = append(s, &AtomicSoftware{
//							Software: &types.Software{
//								Timestamp:      i.Timestamp,
//								Product:        values[1], // Name of the server (Apache, Nginx, ...)
//								Version:        values[2], // Version as found after the '/'
//								Vendor:         values[3], // Often the operating system
//								DeviceProfiles: []string{dpIdent},
//								SourceName:     "JA3s",
//								SourceData:     JA3s,
//								Service:        serviceIdent,
//								DPIResults:     protos,
//								Flows:          []string{flowIdent},
//							},
//						}, &AtomicSoftware{
//							Software: &types.Software{
//								Timestamp:      i.Timestamp,
//								Product:        p.Process,                 // Name of the browser, including version
//								Vendor:         c.Os + "(" + c.Arch + ")", // Name of the OS
//								Version:        "",                        // TODO parse client name
//								DeviceProfiles: []string{dpIdent},
//								SourceName:     "JA3",
//								SourceData:     JA3,
//								Service:        serviceIdent,
//								DPIResults:     protos,
//								Flows:          []string{flowIdent},
//							},
//						})
//					}
//				}
//			}
//		}
//	}
//
//	// if nothing was found with all above attempts, try to throw the generic version number harvester at it
//	// and see if this delivers anything interesting
//	if len(s) == 0 && !decoderconfig.Instance.DisableGenericVersionHarvester {
//		return softwareHarvester(i.Packet.Data(), flowIdent, i.Packet.Metadata().CaptureInfo.Timestamp, serviceIdent, dpIdent, protos)
//	}
//
//	return s
//}

// WhatSoftwareHTTP TODO: pass in the device profile.
func WhatSoftwareHTTP(flowIdent string, h *types.HTTP) (s []*AtomicSoftware) {
	// HTTP User Agents
	// TODO: check for userAgents retrieved by Ja3 lookup as well
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
				s = append(s, &AtomicSoftware{
					Software: &types.Software{
						Timestamp: h.Timestamp,
						Product:   userInfo.Product,
						Vendor:    userInfo.Vendor,
						Version:   userInfo.Version,
						// DeviceProfiles: []string{dpIdent},
						SourceName: "UserAgent",
						SourceData: h.UserAgent,
						Service:    "HTTP",
						Flows:      []string{flowIdent},
						Notes:      userInfo.Full,
						OS:         userInfo.OS,
					},
				})
			}
		}
	}

	// HTTP Server Name
	if h.ServerName != "" && h.ServerName != " " {
		values := regExpServerName.FindStringSubmatch(h.ServerName)

		s = append(s, &AtomicSoftware{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   values[1], // Name of the server (Apache, Nginx, ...)
				Version:   values[2], // Version as found after the '/'
				OS:        values[3], // potentially operating system
				// DeviceProfiles: []string{dpIdent},
				SourceName: "ServerName",
				SourceData: h.ServerName,
				Service:    "HTTP",
				Flows:      []string{flowIdent},
			},
		})
	}

	// X-Powered-By HTTP Header
	if poweredBy, ok := h.ResponseHeader["X-Powered-By"]; ok {
		if poweredBy != "" && poweredBy != " " {
			values := regexpXPoweredBy.FindStringSubmatch(poweredBy)

			s = append(s, &AtomicSoftware{
				Software: &types.Software{
					Timestamp: h.Timestamp,
					Product:   values[1], // Name of the server (Apache, Nginx, ...)
					Version:   values[2], // Version as found after the '/'
					// DeviceProfiles: []string{dpIdent},
					SourceName: "X-Powered-By",
					SourceData: poweredBy,
					Service:    "HTTP",
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

					if decoderconfig.Instance.StopAfterServiceProbeMatch {
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

					if decoderconfig.Instance.StopAfterServiceProbeMatch {
						return s
					}
				}
			}
		}
	}

	return s
}

// TODO: deprecated - SSH and TLS fingerprinting should be done in the stream decoders from now on.
// TODO: DPI is already invoked for each packet with the ipProfile decoders.
// analyzeSoftware tries to identify software based on observations from the data
// this function first gathers as much data as possible and then calls into whatSoftware
// to determine what software the packet belongs to.
//func analyzeSoftware(i *decoderutils.PacketInfo) {
//	var (
//		serviceNameSrc, serviceNameDst string
//		ja3Hash                        = ja3.DigestHexPacket(i.Packet)
//		JA3s                           string
//		JA3                            string
//		protos                         []string
//		f                              string
//	)
//
//	if ja3Hash == "" {
//		ja3Hash = ja3.DigestHexPacketJa3s(i.Packet)
//	}
//
//	// Lookup Service For Port Numbers
//	if tl := i.Packet.TransportLayer(); tl != nil { // set flow ident
//		f = utils.CreateFlowIdent(i.SrcIP, tl.TransportFlow().Src().String(), i.DstIP, tl.TransportFlow().Dst().String())
//
//		// get source port and convert to integer
//		src, err := strconv.Atoi(tl.TransportFlow().Src().String())
//		if err == nil {
//			switch tl.LayerType() {
//			case layers.LayerTypeTCP:
//				serviceNameSrc = resolvers.LookupServiceByPort(src, stream.typeTCP)
//			case layers.LayerTypeUDP:
//				serviceNameSrc = resolvers.LookupServiceByPort(src, stream.typeUDP)
//			default:
//			}
//		}
//
//		dst, err := strconv.Atoi(tl.TransportFlow().Dst().String())
//		if err == nil {
//			switch tl.LayerType() {
//			case layers.LayerTypeTCP:
//				serviceNameDst = resolvers.LookupServiceByPort(dst, stream.typeTCP)
//			case layers.LayerTypeUDP:
//				serviceNameDst = resolvers.LookupServiceByPort(dst, stream.typeUDP)
//			default:
//			}
//		}
//	} else {
//		// no transport layer
//		f = i.SrcIP + "->" + i.DstIP
//	}
//
//	// Deep Packet Inspection
//	results := dpi.GetProtocols(i.Packet)
//	for p := range results {
//		protos = append(protos, p)
//	}
//
//	// The underlying assumption is that we will always observe a client TLS Hello before seeing a server TLS Hello
//	// Assuming the packet captured corresponds to the server Hello, first try to see if a client Hello (client being the
//	// destination IP) was observed. If not, this is the client. Therefore add client ja3 signature to the store.
//	if len(ja3Hash) > 0 {
//		var ok bool
//		jaCacheMutex.Lock()
//		JA3, ok = ja3Cache[i.DstIP]
//		jaCacheMutex.Unlock()
//		if !ok {
//			jaCacheMutex.Lock()
//			ja3Cache[i.SrcIP] = ja3Hash
//			jaCacheMutex.Unlock()
//
//			JA3 = ""
//			JA3s = ""
//		} else {
//			JA3s = ja3Hash
//		}
//	}
//
//	// fetch the associated device profile
//	dp := packet.GetDeviceProfile(i.SrcMAC, i)
//
//	// now that we have some information at hands
//	// try to determine what kind of software it is
//	soft := whatSoftware(dp, i, f, serviceNameSrc, serviceNameDst, JA3, JA3s, protos)
//	if len(soft) == 0 {
//		return
//	}
//
//	writeSoftware(soft, func(s *software) {
//		updateSoftwareAuditRecord(dp, s, i)
//	})
//}

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
		// lookup known issues with identified software in the background
		go func() {
			for _, s := range newSoftwareProducts {
				vulnerability.VulnerabilitiesLookup(s)
				exploit.ExploitsLookup(s)
			}
		}()
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
