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

package encoder

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blevesearch/bleve"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"

	deadlock "github.com/sasha-s/go-deadlock"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/ua-parser/uap-go/uaparser"
)

type Software struct {
	*types.Software
	deadlock.Mutex
}

// AtomicDeviceProfileMap contains all connections and provides synchronized access
type AtomicSoftwareMap struct {
	// mapped product + version to software
	Items map[string]*Software
	deadlock.Mutex
}

var (
	userAgentCaching = make(map[string]*userAgent)
	regExpServerName = regexp.MustCompile(`(.*?)(?:(?:/)(.*?))?(?:\s*?)(?:(?:\()(.*?)(?:\)))?$`)
	regexpXPoweredBy = regexp.MustCompile(`(.*?)(?:(?:/)(.*?))?$`)
	ja3Cache         = make(map[string]string)
	jaCacheMutex     deadlock.Mutex
	reGenericVersion = regexp.MustCompile(`(?m)(?:^)(.*?)([0-9]+)\.([0-9]+)\.([0-9]+)(.*?)(?:$)`)
	hasshMap         = make(map[string][]SSHSoftware)
	// Used to store CMS related information, and to do the CMS lookup
	cmsDB                = make(map[string]interface{})
	vulnerabilitiesIndex bleve.Index
)

// Size returns the number of elements in the Items map
func (a *AtomicSoftwareMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var (
	// SoftwareStore hold all connections
	SoftwareStore = &AtomicSoftwareMap{
		Items: make(map[string]*Software),
	}

	parser, errInitUAParser = uaparser.New("/usr/local/etc/netcap/dbs/regexes.yaml")
	pMu                     deadlock.Mutex

	ja3db     Ja3CombinationsDB
	hasshDB   []SSHHash
	hashDBMap map[string][]SSHSoftware
)

type userAgent struct {
	client  *uaparser.Client
	product string
	vendor  string
	version string
	full    string
}

type Process struct {
	Process string `json:"process"`
	JA3     string `json:"JA3"`
	JA3s    string `json:"JA3S"`
}

type Client struct {
	Os        string    `json:"os"`
	Arch      string    `json:"arch"`
	Processes []Process `json:"processes"`
}

type Server struct {
	Server  string   `json:"server"`
	Clients []Client `json:"clients"`
}

type Ja3CombinationsDB struct {
	Servers []Server `json:"servers"`
}

type SSHSoftware struct {
	Version    string `json:"name"`
	Likelyhood string `json:"likelyhood"`
}

type SSHHash struct {
	Hash      string        `json:"hash"`
	Softwares []SSHSoftware `json:"softwares"`
}

// process a raw user agent string and returned a structured instance
func parseUserAgent(ua string) *userAgent {
	var (
		client                         = parser.Parse(ua)
		full, product, vendor, version string
	)
	if client.UserAgent != nil {
		vendor = client.UserAgent.Family
		version = client.UserAgent.Major
		if client.UserAgent.Minor != "" {
			version += "." + client.UserAgent.Minor
		}
		if client.UserAgent.Patch != "" {
			version += "." + client.UserAgent.Patch
		}
		full += " " + client.UserAgent.Family
		full += " " + client.UserAgent.Major
		full += " " + client.UserAgent.Minor
		full += " " + client.UserAgent.Patch

		if vendor == "Other" {
			vendor = ""
		}
	}
	if client.Os != nil {
		full += " " + client.Os.Family
		full += " " + client.Os.Major
		full += " " + client.Os.Minor
		full += " " + client.Os.Patch
		full += " " + client.Os.PatchMinor
	}
	if client.Device != nil {
		product = client.Device.Family
		full += " " + client.Device.Family

		if product == "Other" {
			product = ""
		}
	}

	return &userAgent{
		client:  client,
		product: product,
		vendor:  vendor,
		version: version,
		full:    strings.TrimSpace(full),
	}
}

// Make the threshold configurable (Possibly), and changing the stdout output
func vulnerabilitiesLookup(s []*Software) {
	for _, software := range s {
		queryTerm := software.Product + " " + software.Version
		query := bleve.NewMatchQuery(queryTerm)
		search := bleve.NewSearchRequest(query)
		searchResults, err := vulnerabilitiesIndex.Search(search)
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, v := range searchResults.Hits {
			if v.Score > 3 {
				doc, _ := vulnerabilitiesIndex.Document(v.ID)
				fmt.Println(string(doc.Fields[2].Value()))
			}
		}
	}
}

// generic version harvester, scans the payload using a regular expression
func softwareHarvester(data []byte, flowIdent string, ts time.Time, service string, dpIdent string, protos []string) (software []*Software) {

	var s []*Software

	matches := reGenericVersion.FindAll(data, -1)

	if len(matches) > 0 {
		for _, v := range matches {
			s = append(s, &Software{
				Software: &types.Software{
					Timestamp:      ts.String(),
					DeviceProfiles: []string{dpIdent},
					SourceName:     "Generic version harvester",
					SourceData:     string(v),
					Service:        service,
					DPIResults:     protos,
					Flows:          []string{flowIdent},
				},
			})
		}
	}

	return s
}

// tries to determine the kind of software and version
// based on the provided input data
func whatSoftware(dp *DeviceProfile, i *packetInfo, flowIdent, serviceNameSrc, serviceNameDst, JA3, JA3s string, protos []string) (software []*Software) {

	var (
		service string
		s       []*Software
		dpIdent = dp.MacAddr
	)
	if serviceNameSrc != "" {
		service = serviceNameSrc
	}
	if serviceNameDst != "" {
		service = serviceNameDst
	}
	if dp.DeviceManufacturer != "" {
		dpIdent += " <" + dp.DeviceManufacturer + ">"
	}

	// Only do JA3 fingerprinting when both ja3 and ja3s are present, aka when the server Hello is captured
	if len(JA3) > 0 && len(JA3s) > 0 {
		for _, server := range ja3db.Servers {
			serverName := server.Server
			for _, client := range server.Clients {
				clientName := client.Os + "(" + client.Arch + ")"
				for _, process := range client.Processes {
					processName := process.Process
					if process.JA3 == JA3 && process.JA3s == JA3s {
						pMu.Lock()
						var values = regExpServerName.FindStringSubmatch(serverName)
						s = append(s, &Software{
							Software: &types.Software{
								Timestamp:      i.timestamp,
								Product:        values[1], // Name of the server (Apache, Nginx, ...)
								Vendor:         values[3], // Unfitting name, but operating system
								Version:        values[2], // Version as found after the '/'
								DeviceProfiles: []string{dpIdent},
								SourceName:     "JA3s",
								SourceData:     JA3s,
								Service:        service,
								DPIResults:     protos,
								Flows:          []string{flowIdent},
							},
						})
						s = append(s, &Software{
							Software: &types.Software{
								Timestamp:      i.timestamp,
								Product:        processName, // Name of the browser, including version
								Vendor:         clientName,  // Name of the OS
								Version:        "",          // TODO parse client name
								DeviceProfiles: []string{dpIdent},
								SourceName:     "JA3",
								SourceData:     JA3,
								Service:        service,
								DPIResults:     protos,
								Flows:          []string{flowIdent},
							},
						})
						pMu.Unlock()
					}
				}
			}
		}
	}

	// if nothing was found with all above attempts, try to throw the generic version number harvester at it
	// and see if this delivers anything interesting
	if len(s) == 0 {
		return softwareHarvester(i.p.Data(), flowIdent, i.p.Metadata().CaptureInfo.Timestamp, service, dpIdent, protos)
	}

	// Defining the variable here to avoid errors. This should be passed as a parameter and contain the hassh value
	return s
}

// TODO: pass in the device profile
func whatSoftwareHTTP(dp *DeviceProfile, flowIdent string, h *types.HTTP) (software []*Software) {

	var (
		s []*Software
		//dpIdent = dp.MacAddr
	)
	// if dp.DeviceManufacturer != "" {
	// 	dpIdent += " <" + dp.DeviceManufacturer + ">"
	// }

	// HTTP User Agents
	// TODO: check for userAgents retrieved by Ja3 lookup as well
	if len(h.UserAgent) != 0 && h.UserAgent != " " {

		pMu.Lock()
		userInfo, ok := userAgentCaching[h.UserAgent]
		if !ok {
			userInfo = parseUserAgent(h.UserAgent)
			userAgentCaching[h.UserAgent] = userInfo
			utils.DebugLog.Println("UserAgent:", userInfo.full)
		}
		pMu.Unlock()

		s = append(s, &Software{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   userInfo.product,
				Vendor:    userInfo.vendor,
				Version:   userInfo.version,
				//DeviceProfiles: []string{dpIdent},
				SourceName: "UserAgent",
				SourceData: h.UserAgent,
				Service:    "HTTP",
				Flows:      []string{flowIdent},
				Notes:      userInfo.full,
			},
		})
	}

	// HTTP Server Name
	if len(h.ServerName) != 0 && h.ServerName != " " {
		var values = regExpServerName.FindStringSubmatch(h.ServerName)
		s = append(s, &Software{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   values[1], // Name of the server (Apache, Nginx, ...)
				Vendor:    values[3], // Unfitting name, but operating system
				Version:   values[2], // Version as found after the '/'
				//DeviceProfiles: []string{dpIdent},
				SourceName: "ServerName",
				SourceData: h.ServerName,
				Service:    "HTTP",
				Flows:      []string{flowIdent},
			},
		})
	}

	// X-Powered-By HTTP Header
	if poweredBy, ok := h.RequestHeader["X-Powered-By"]; ok {
		if len(poweredBy) != 0 && poweredBy != " " {
			var values = regexpXPoweredBy.FindStringSubmatch(poweredBy)
			s = append(s, &Software{
				Software: &types.Software{
					Timestamp: h.Timestamp,
					Product:   values[1], // Name of the server (Apache, Nginx, ...)
					Version:   values[2], // Version as found after the '/'
					//DeviceProfiles: []string{dpIdent},
					SourceName: "X-Powered-By",
					SourceData: poweredBy,
					Service:    "HTTP",
					Flows:      []string{flowIdent},
				},
			})
		}
	}

	// Try to detect apps
	if receivedHeaders, ok := httpStore.CMSHeaders[h.DstIP]; ok {
		for k, v := range cmsDB {
			if headers, ok := v.(map[string]interface{}); ok {
				if hdrs, ok := headers["headers"]; ok {
					for key, val := range hdrs.(map[string]interface{}) {
						for _, receivedHeader := range receivedHeaders {
							re, err := regexp.Compile(val.(string))
							if err != nil {
								fmt.Println("Failed to compile:    " + val.(string))
							} else {
								if strings.ToLower(receivedHeader.HeaderName) == strings.ToLower(key) && (re.MatchString(receivedHeader.HeaderValue) || val == "") {
									s = append(s, &Software{
										Software: &types.Software{
											Timestamp:  h.Timestamp,
											Product:    k,
											Version:    "",
											SourceName: key,
											Service:    "HTTP",
											Flows:      []string{flowIdent},
										},
									})
								}
							}
						}
					}
				}
			}
		}
	}

	// Defining the variable here to avoid errors. This should be passed as a parameter and contain the hassh value
	vulnerabilitiesLookup(s)
	return s
}

// AnalyzeSoftware tries to identify software based on observations from the data
// this function first gathers as much data as possible and then calls into whatSoftware
// to determine what software the packet belongs to
func AnalyzeSoftware(i *packetInfo) {

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
	if tl := i.p.TransportLayer(); tl != nil {

		// set flow ident
		f = i.srcIP + ":" + tl.TransportFlow().Src().String() + "->" + i.dstIP + ":" + tl.TransportFlow().Dst().String()

		// get source port and convert to integer
		src, err := strconv.Atoi(tl.TransportFlow().Src().String())
		if err == nil {
			switch tl.LayerType() {
			case layers.LayerTypeTCP:
				serviceNameSrc = resolvers.LookupServiceByPort(src, "tcp")
			case layers.LayerTypeUDP:
				serviceNameSrc = resolvers.LookupServiceByPort(src, "udp")
			default:
			}
		}
		dst, err := strconv.Atoi(tl.TransportFlow().Dst().String())
		if err == nil {
			switch tl.LayerType() {
			case layers.LayerTypeTCP:
				serviceNameDst = resolvers.LookupServiceByPort(dst, "tcp")
			case layers.LayerTypeUDP:
				serviceNameDst = resolvers.LookupServiceByPort(dst, "udp")
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
	software := whatSoftware(dp, i, f, serviceNameSrc, serviceNameDst, JA3, JA3s, protos)
	if len(software) == 0 {
		return
	}

	// add new audit records or update existing
	SoftwareStore.Lock()
	for _, s := range software {
		if p, ok := SoftwareStore.Items[s.Product+"/"+s.Version]; ok {
			updateSoftwareAuditRecord(dp, p, i)
		} else {
			SoftwareStore.Items[s.Product+"/"+s.Version] = s
			statsMutex.Lock()
			reassemblyStats.numSoftware++
			statsMutex.Unlock()
		}
	}
	SoftwareStore.Unlock()
}

// NewDeviceProfile creates a new device specific profile
func NewSoftware(i *packetInfo) *Software {
	return &Software{
		Software: &types.Software{
			Timestamp: i.timestamp,
		},
	}
}

func updateSoftwareAuditRecord(dp *DeviceProfile, p *Software, i *packetInfo) {

	var (
		dpIdent = dp.MacAddr
	)
	if dp.DeviceManufacturer != "" {
		dpIdent += " <" + dp.DeviceManufacturer + ">"
	}

	p.Lock()
	for _, pr := range p.DeviceProfiles {
		if pr == dpIdent {
			p.Unlock()
			return
		}
	}
	p.DeviceProfiles = append(p.DeviceProfiles, dpIdent)
	tl := i.p.TransportLayer()
	if tl != nil {
		p.Flows = append(p.Flows, i.srcIP+":"+tl.TransportFlow().Src().String()+"->"+i.dstIP+":"+tl.TransportFlow().Dst().String())
	} else {
		// no transport layer
		p.Flows = append(p.Flows, i.srcIP+"->"+i.dstIP)
	}
	p.Unlock()
}

var softwareEncoder = CreateCustomEncoder(types.Type_NC_Software, "Software", func(d *CustomEncoder) error {

	if errInitUAParser != nil {
		return errInitUAParser
	}

	// Load the JSON database of JA3/JA3S combinations into memory
	data, err := ioutil.ReadFile("/usr/local/etc/netcap/dbs/ja_3_3s.json")
	if err != nil {
		return err
	}

	// unpack JSON
	err = json.Unmarshal(data, &ja3db.Servers)
	if err != nil {
		return err
	}

	// Load the JSON database of HASSH signaures
	data, err = ioutil.ReadFile("/usr/local/etc/netcap/dbs/hasshdb.json")
	if err != nil {
		return err
	}

	// unpack JSON
	err = json.Unmarshal(data, &hasshDB)
	if err != nil {
		return err
	}

	hashDBMap = make(map[string][]SSHSoftware)

	for _, v := range hasshDB {
		hashDBMap[v.Hash] = v.Softwares
	}

	data, err = ioutil.ReadFile("/usr/local/etc/netcap/dbs/cmsdbTest.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &cmsDB)
	if err != nil {
		return err
	}

	for _, entry := range hasshDB {
		hasshMap[entry.Hash] = entry.Softwares // Holds redundant info, but couldn't figure a more elegant way to do this
	}

	// Load vulnerabilities DB index
	indexName := "/usr/local/etc/netcap/dbs/exploits.bleve"
	vulnerabilitiesIndex, err = bleve.Open(indexName)
	if err != nil {
		return err
	}

	utils.DebugLog.Println("loaded Ja3/ja3S database, records:", len(ja3db.Servers))

	return nil
}, func(p gopacket.Packet) proto.Message {

	// handle packet
	AnalyzeSoftware(newPacketInfo(p))

	return nil
}, func(e *CustomEncoder) error {

	httpStore.Lock()
	var rows [][]string
	for ip, ua := range httpStore.UserAgents {
		rows = append(rows, []string{ip, ua})
	}
	tui.Table(utils.DebugLogFileHandle, []string{"IP", "UserAgents"}, rows)
	rows = [][]string{}
	for ip, sn := range httpStore.ServerNames {
		rows = append(rows, []string{ip, sn})
	}
	tui.Table(utils.DebugLogFileHandle, []string{"IP", "ServerNames"}, rows)
	httpStore.Unlock()

	// teardown DPI C libs
	dpi.Destroy()

	// flush writer
	if !e.writer.IsChanWriter {
		for _, c := range SoftwareStore.Items {
			c.Lock()
			e.write(c.Software)
			c.Unlock()
		}
	}
	return nil
})

// TODO: move into CustomEncoder and use in other places to remove unnecessary package level encoders
// writeProfile writes the profile
func (e *CustomEncoder) write(c types.AuditRecord) {

	if e.export {
		c.Inc()
	}

	atomic.AddInt64(&e.numRecords, 1)
	err := e.writer.Write(c.(proto.Message))
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
