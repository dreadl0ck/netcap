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
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"

	"sync"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/ua-parser/uap-go/uaparser"
)

type Software struct {
	*types.Software
	sync.Mutex
}

// AtomicDeviceProfileMap contains all connections and provides synchronized access
type AtomicSoftwareMap struct {
	// mapped product + version to software
	Items map[string]*Software
	sync.Mutex
}

var (
	userAgentCaching = make(map[string]*userAgent)
	regExpServerName = regexp.MustCompile(`(.*?)(?:(?:/)(.*?))?(?:\s*?)(?:(?:\()(.*?)(?:\)))?$`)
	regexpXPoweredBy = regexp.MustCompile(`(.*?)(?:(?:/)(.*?))?$`)
	ja3Caching       = make(map[string]string)
	reGenericVersion = regexp.MustCompile(`(?:[A-Za-z]*?)\s(?:[0-9]+)(?:\.)?(?:[0-9]+)?(?:\.)?(?:[0-9]+)?`)
	hasshMap         = make(map[string]SSHHash)
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
	pMu                     sync.Mutex

	ja3db   Ja3CombinationsDB
	hasshDB []SSHHash
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

type SSHHash struct {
	Image            string `json:"image"`
	ImageVersion     string `json:"imageVersion"`
	SSHClient        string `json:"sshClient"`
	SSHClientVersion string `json"sshClientVersion"`
	Hash             string `json:"hash"`
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

// generic version harvester, scans the payload using a regular expression
func softwareHarvester(data []byte, ident string, ts time.Time, service string, dpIdent string, protos []string) (software []*Software) {

	var s []*Software

	matches := reGenericVersion.FindStringSubmatch(string(data))

	if len(matches) > 0 {
		for _, v := range matches {
			var version string
			parsed := strings.Split(v, " ")
			if len(parsed) > 1 {
				version = parsed[1]
			}
			s = append(s, &Software{
				Software: &types.Software{
					Timestamp:      ts.String(),
					Product:        parsed[0],
					Service:        service,
					SourceName:     "Generic Version Format",
					SourceData:     string(data),
					Version:        version,
					Flows:          []string{ident},
					DeviceProfiles: []string{dpIdent},
					DPIResults:     protos,
				},
			})
		}
	}

	return s
}

// tries to determine the kind of software and version
// based on the provided input data
func whatSoftware(dp *DeviceProfile, i *packetInfo, f, serviceNameSrc, serviceNameDst, JA3, JA3s, userAgents, serverNames string, protos []string, vias string, xPoweredBy string) (software []*Software) {

	//fmt.Println(serviceNameSrc, serviceNameDst, manufacturer, ja3Result, userAgents, serverNames, protos)

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

	// HTTP User Agents
	// TODO: check for userAgents retrieved by Ja3 lookup as well
	for _, ua := range strings.Split(userAgents, "| ") {
		if len(ua) == 0 || ua == " " {
			continue
		}
		pMu.Lock()
		userInfo, ok := userAgentCaching[ua]
		if !ok {
			userInfo = parseUserAgent(ua)
			userAgentCaching[ua] = userInfo
			utils.DebugLog.Println("UserAgent:", userInfo.full)
		}
		pMu.Unlock()

		s = append(s, &Software{
			Software: &types.Software{
				Timestamp:      i.timestamp,
				Product:        userInfo.product,
				Vendor:         userInfo.vendor,
				Version:        userInfo.version,
				DeviceProfiles: []string{dpIdent},
				SourceName:     "UserAgent",
				SourceData:     ua,
				Service:        service,
				DPIResults:     protos,
				Flows:          []string{f},
				Notes:          userInfo.full,
			},
		})
	}

	// HTTP Server Name
	for _, sn := range strings.Split(serverNames, "| ") {
		if len(sn) == 0 || sn == " " {
			continue
		}
		pMu.Lock()
		var values = regExpServerName.FindStringSubmatch(sn)
		s = append(s, &Software{
			Software: &types.Software{
				Timestamp:      i.timestamp,
				Product:        values[1], // Name of the server (Apache, Nginx, ...)
				Vendor:         values[3], // Unfitting name, but operating system
				Version:        values[2], // Version as found after the '/'
				DeviceProfiles: []string{dpIdent},
				SourceName:     "ServerName",
				SourceData:     sn,
				Service:        service,
				DPIResults:     protos,
				Flows:          []string{f},
			},
		})
		pMu.Unlock()
	}

	// X-Powered-By HTTP Header
	for _, pb := range strings.Split(xPoweredBy, "| ") {
		if len(pb) == 0 || pb == " " {
			continue
		}
		pMu.Lock()
		var values = regexpXPoweredBy.FindStringSubmatch(pb)
		s = append(s, &Software{
			Software: &types.Software{
				Timestamp:      i.timestamp,
				Product:        values[1], // Name of the server (Apache, Nginx, ...)
				Version:        values[2], // Version as found after the '/'
				DeviceProfiles: []string{dpIdent},
				SourceName:     "X-Powered-By",
				SourceData:     pb,
				Service:        service,
				DPIResults:     protos,
				Flows:          []string{f},
			},
		})
		pMu.Unlock()
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
								Flows:          []string{f},
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
								Flows:          []string{f},
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
		return softwareHarvester(i.p.Data(), dpIdent, i.p.Metadata().CaptureInfo.Timestamp, service, dpIdent, protos)
	}

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
		userAgents, serverNames        string
		f                              string
		vias                           string
		xPoweredBy                     string
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

	// Check available HTTP meta infos
	httpStore.Lock()
	if val, ok := httpStore.UserAgents[i.srcIP]; ok {
		userAgents = val
	}
	if val, ok := httpStore.ServerNames[i.dstIP]; ok {
		serverNames = val
	}
	if val, ok := httpStore.Vias[i.dstIP]; ok {
		vias = val
	}
	if val, ok := httpStore.XPoweredBy[i.dstIP]; ok {
		xPoweredBy = val
	}
	httpStore.Unlock()

	// The underlying assumption is that we will always observe a client TLS Hello before seeing a server TLS Hello
	// Assuming the packet captured corresponds to the server Hello, first try to see if a client Hello (client being the
	// destination IP) was observed. If not, this is the client. Therefore add client ja3 signature to the store.
	if len(ja3Hash) > 0 {
		var ok bool
		JA3, ok = ja3Caching[i.dstIP]
		if !ok {
			ja3Caching[i.srcIP] = ja3Hash
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
	software := whatSoftware(dp, i, f, serviceNameSrc, serviceNameDst, JA3, JA3s, userAgents, serverNames, protos, vias, xPoweredBy)
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
	data, err = ioutil.ReadFile("/usr/local/etc/netcap/dbs/hassh.json")
	if err != nil {
		return err
	}

	// unpack JSON
	err = json.Unmarshal(data, &hasshDB)
	if err != nil {
		return err
	}

	for _, entry := range hasshDB {
		hasshMap[entry.Hash] = entry // Holds redundant info, but couldn't figure a more elegant way to do this
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
