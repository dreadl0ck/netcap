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

package maltego_test

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/utils"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
)

const (
	transformDebug      = false
	transformWorkingDir = "/usr/local"
)

// additional transforms
var transforms = []*maltego.TransformCoreInfo{
	{"ToApplicationCategories", "netcap.IPAddr", "Retrieve categories of classified applications"},
	{"ToApplications", "netcap.IPAddr", "Show all applications used by the selected host"},
	{"ToApplicationsForCategory", "netcap.ApplicationCategory", "Retrieve applications seen for a given category"},
	//{"ToCookiesForHost", "netcap.Host", "Retrieve cookies seen for the given host"},
	{"ToCookieValues", "netcap.HTTPCookie", "Retrieve values for a given cookie identifier"},
	{"ToHTTPHeaders", "netcap.IPAddr", "Retrieve headers seen for the given host"},
	{"ToHeaderValues", "netcap.HTTPHeader", "Retrieve values for a given header identifier"},
	{"ToDHCP", "netcap.IPAddr", "Fetch DHCP options for host"},
	{"ToDNSQuestions", "netcap.IPAddr", "Show all captured DNS questions for the selected host"},
	{"ToDestinationIPs", "netcap.Device", "Get destination hosts seen for the selected device"},
	{"ToSourceIPs", "netcap.Device", "Get all IPs that the device has been using"},

	{"ToSourcePorts", "netcap.IPAddr", "Retrieve all source ports seen for the selected host address"},
	{"ToDestinationPorts", "netcap.IPAddr", "Retrieve all destination ports seen for the selected host address"},
	{"ToContactedPorts", "netcap.IPAddr", "Retrieve all ports contacted by the selected host address"},

	{"ToFileType", "netcap.File", "Retrieve file type via unix file util"},
	{"ToFileTypes", "netcap.IPAddr", "Get all fille types for the selected IPAddr"},
	{"ToFiles", "netcap.IPAddr", "Get all files seen from the selected IP"},
	{"ToFilesForContentType", "netcap.ContentType", "Get all files for a given content type"},
	{"ToGeolocation", "netcap.IPAddr", "Retrieve the geolocation of an IP address"},
	{"ToHTTPContentTypes", "netcap.IPAddr", "Show all HTTP Content Types seen for the selected host"},
	{"ToHTTPCookies", "netcap.IPAddr", "Retrieve HTTP cookies"},
	{"ToHTTPHosts", "netcap.IPAddr", "Retrieve all hostnames seen via HTTP for the selected host"},
	{"ToHTTPHostsFiltered", "netcap.IPAddr", "Get a list of hosts filtered against a DNS whitelist"},
	{"ToHTTPParameters", "netcap.IPAddr", "Retrieve HTTP parameters"},
	{"ToHTTPServerNames", "netcap.IPAddr", "Retrieve the server names that have been contacted by the selected host"},
	{"ToHTTPStatusCodes", "netcap.IPAddr", "Show all HTTP status codes observed for the selected host"},
	{"ToHTTPUserAgents", "netcap.IPAddr", "Retrieve all HTTP user agents seen from the selected host"},
	{"ToIncomingConnsFiltered", "netcap.IPAddr", "Show all incoming flows filtered against the configured whitelist"},
	{"ToMailAuthTokens", "netcap.IPAddr", "Retrieve POP3 auth tokens"},
	{"ToMailFrom", "netcap.IPAddr", "Retrieve all email addresses from the 'From' field"},
	{"ToMailTo", "netcap.IPAddr", "Retrieve all email addresses from the 'To' field"},
	{"ToMailUserPassword", "maltego.Person", "Retrieve the password for a mail user"},
	{"ToMailUsers", "netcap.IPAddr", "Retrieve email users"},
	{"ToMails", "netcap.IPAddr", "Show mails fetched over POP3"},
	{"ToOutgoingConnsFiltered", "netcap.IPAddr", "Show all outgoing flows filtered against the configured whitelist"},
	{"ToParameterValues", "netcap.HTTPParameter", "Retrieve all values seen for an HTTP parameter"},
	{"ToServerNameIndicators", "netcap.IPAddr", "Retrieve the TLS Server Name Indicators seen for the selected host"},
	{"ToHTTPUniformResourceLocators", "netcap.IPAddr", "Retrieve all URLs seen for the selected host"},
	{"ToAuditRecords", "netcap.PCAP", "Transform PCAP file into audit records"},
	{"ToAuditRecordsUsingDPI", "netcap.PCAP", "Retrieve audit records with Deep Packet Inspection enabled"},
	{"ReloadAuditRecordsFromDisk", "netcap.PCAP", "Reload the audit records for the selected PCAP from disk"},
	{"StartCaptureProcess", "netcap.Interface", "Start network capture on the given interface"},
	{"ToDHCPClients", "netcap.DHCPv4AuditRecords", "Show all DHCP Clients"},
	{"ToDNSQuestions", "netcap.DNSAuditRecords", "Show all DNS questions"},
	{"ToDNSResponseCodes", "netcap.DNSAuditRecords", "Show all DNS response codes"},
	{"ToDNSFlagCombinations", "netcap.DNSAuditRecords", "Show all DNS flag combinations"},

	{"ToEmails", "netcap.MailAuditRecords", "Show extracted emails"},
	{"ToICMPV4ControlMessages", "netcap.ICMPv4AuditRecords", "Show ICMPv4 control messages"},
	{"ToICMPV6ControlMessages", "netcap.ICMPv6AuditRecords", "Show ICMPv6 control messages"},
	{"ToHosts", "netcap.POP3AuditRecords", "Show hosts that used the POP3 protocol"},

	{"ToFileTypes", "netcap.FileAuditRecords", "Show MIME types for extracted files"},
	{"ToHTTPHostnames", "netcap.HTTPAuditRecords", "Show all visited website hostnames"},
	{"ToIANAServices", "netcap.ConnectionAuditRecords", "Show all IANA services identified by the connection destination port"},
	{"ToLiveAuditRecords", "netcap.Interface", "Show current state of captured traffic"},
	{"ToLoginInformation", "netcap.CredentialsAuditRecords", "Show captured login credentials"},
	{"ToSoftwareProducts", "netcap.SoftwareAuditRecords", "Show software products and version information"},
	{"ToSSHClients", "netcap.SSHAuditRecords", "Show detected SSH client"},
	{"ToSSHServers", "netcap.SSHAuditRecords", "Show all SSH server software"},
	{"ToSoftwareExploits", "netcap.ExploitAuditRecords", "Show potential exploits "},
	{"ToSoftwareVulnerabilities", "netcap.VulnerabilityAuditRecords", "Show all discovered vulnerable software"},

	{"ToDevices", "netcap.DeviceProfileAuditRecords", "Show all discovered device audit records"},
	{"ToIPProfiles", "netcap.IPProfileAuditRecords", "Show all discovered ip hosts"},
	{"ToIPProfilesForSoftware", "netcap.Software", "Show all ip hosts for the selected software"},
	{"ToJA3Hashes", "netcap.TLSClientHelloAuditRecords", "Show all discovered ja3 client hashes"},
	{"ToJA3SHashes", "netcap.TLSServerHelloAuditRecords", "Show all discovered ja3 server hashes"},
	{"ToSMTPCommandTypes", "netcap.SMTPAuditRecords", "Show all SMTP command types"},
	{"ToDNSOpCodes", "netcap.DNSAuditRecords", "Show all DNS op codes"},

	{"ToConnectionsForService", "netcap.Service", "Show all connections for the selected service"},
	{"ToConnectionsForHost", "netcap.IPAddr", "Show all connections for the selected host"},
	{"ToConnectionsForPort", "netcap.Port", "Show all connections for the selected port"},

	{"OpenExploit", "netcap.Exploit", "Open the exploit source with the default system program for the filetype"},
	{"OpenFile", "netcap.File", "Opens a file with the default application"},
	{"OpenImage", "maltego.Image", "Opens an image file with the default application"},
	{"OpenFolder", "netcap.File", "Open the folder in which the file resides"},
	{"OpenNetcapFolder", "netcap.PCAP", "Open the storage folder for the selected PCAP file"},
	{"OpenNetcapFolderInTerminal", "netcap.PCAP", "Open the storage folder for the selected PCAP file in the terminal"},
	{"OpenVulnerability", "netcap.Vulnerability", "Open link to the vulnerability on NVD homepage"},
	{"OpenFilesFolder", "netcap.FileAuditRecords", "Open the storage folder for the extracted files"},
	{"OpenContentTypeFolder", "netcap.ContentType", "Open the storage folder for the selected content type"},

	{"OpenLiveNetcapFolder", "netcap.Interface", "Open the storage folder for the selected network interface"},
	{"OpenLiveNetcapFolderInTerminal", "netcap.Interface", "Open the storage folder for the selected network interface in the terminal"},

	{"ToHostsForService", "netcap.Service", "Show all hosts that have been contacting the service"},
	{"ToMD5HashesForFileName", "netcap.File", "Get the MD5 hashes for all files seen with the provided file name"},
	{"ToMD5HashesForImage", "maltego.Image", "Get the MD5 hashes associated with the image file"},
	{"ToExifDataForImage", "maltego.Image", "Get the exif data from the image file"},
	{"ToLinksFromFile", "netcap.File", "Extract all hyperlinks from the file"},
	{"ToDomainsFromFile", "netcap.File", "Extract all domain names from the file"},
	{"ToIPsFromFile", "netcap.File", "Extract all ips from the file"},
	{"ToEmailsFromFile", "netcap.File", "Extract all email addresses from the file"},
	{"ToPhoneNumbersFromFile", "netcap.File", "Extract all phone numbers from the file"},

	{"ToNetworkInterfaces", "netcap.Computer", "Show all available network interfaces"},
	{"LookupDHCPFingerprint", "netcap.DHCPClient", "Resolve the clients DHCP fingerprint via the fingerbank API"},
	{"StopCaptureProcess", "netcap.Interface", "stop the NETCAP capture process"},

	{"ToServices", "netcap.ServiceType", "Show detected network services for the given service type"},
	{"ToServiceTypes", "netcap.ServiceAuditRecords", "Show detected network service types"},

	{"ToSourceDevices", "netcap.IPProfile", "Show the source devices for the given ip profile"},
	{"ToJA3HashesForProfile", "netcap.IPProfile", "Show the ja3 hashes seen for the given ip profile"},

	{"ToVisitorsForURL", "netcap.URL", "Show all visitors for the selected URL"},
	{"ToVisitorsForHost", "netcap.Host", "Show all visitors for the selected website"},
	{"ToProviderIPProfilesForURL", "netcap.URL", "Show all ProviderIPProfiles for the selected URL"},
	{"ToProviderIPProfilesForHost", "netcap.Host", "Show all ProviderIPProfiles for the selected website"},

	{"ToTCPFlagCombinations", "netcap.TCPAuditRecords", "Show all TCP flag combinations seen"},
	{"ToEthernetTypes", "netcap.EthernetAuditRecords", "Show all Ethernet types"},
	{"ToIPV4Protocols", "netcap.IPv4AuditRecords", "Show all IPv4 protocol types"},
	{"ToIPV6TrafficClasses", "netcap.IPv6AuditRecords", "Show all IPv6 traffic classes"},
	{"ToLinkTypes", "netcap.ARPAuditRecords", "Show all ARP link types"},
	{"ToIGMPTypes", "netcap.IGMPAuditRecords", "Show all IGMP types"},
	{"ToIGMPGroupRecordTypes", "netcap.IGMPAuditRecords", "Show all IGMP group record types"},

	{"ToDHCPV6MessageTypes", "netcap.DHCPv6AuditRecords", "Show all DHCPv6 message types"},
	{"ToDHCPV6Options", "netcap.DHCPv6AuditRecords", "Show all DHCPv6 options"},

	{"ToUDPHosts", "netcap.UDPAuditRecords", "Show all hosts that communicated over UDP"},

	{"ToNTPHosts", "netcap.NTPAuditRecords", "Show all hosts that communicated via NTP"},
	{"ToNTPReferenceIDs", "netcap.NTPAuditRecords", "Show all NTP reference ids"},

	// Wireshark integration
	{"OpenConnectionInWireshark", "netcap.Connection", "Open the selected connection in wireshark"},
	{"OpenServiceInWireshark", "netcap.Service", "Open all traffic from and towards the selected service in wireshark"},
	{"OpenHostTrafficInWireshark", "netcap.IPProfile", "Open all traffic from and towards the selected host in wireshark"},
	{"OpenTrafficInWireshark", "netcap.IPAddr", "Open all traffic from and towards the selected host in wireshark"},
	{"OpenDeviceTrafficInWireshark", "netcap.Device", "Open all traffic from and towards the selected device in wireshark"},
	{"OpenSoftwareTrafficInWireshark", "netcap.Software", "Open traffic identified as the selected software in wireshark"},
	{"OpenVulnerabilityTrafficInWireshark", "netcap.Vulnerability", "Open the traffic indicating the selected vulnerability in wireshark"},
	{"OpenTrafficForPortInWireshark", "netcap.Port", "Open traffic for the selected port in wireshark"},

	{"OpenFileInDisassembler", "netcap.File", "Open binary file in disassembler for analysis"},
}

// generate all transforms and pack as archive
func TestGenerateFullMaltegoConfiguration(t *testing.T) {
	maltego.GenMaltegoArchive(netcapIdent, ident)

	var count int

	// generate entities for packet decoders
	// *AuditRecords entity and an entity for the actual audit record instance
	packet.ApplyActionToPacketDecoders(func(d packet.DecoderAPI) {
		createEntity(netcapIdent, d.GetName(), d.GetDescription(), &count)
	})

	// generate entities for gopacket decoders
	packet.ApplyActionToGoPacketDecoders(func(d *packet.GoPacketDecoder) {
		createEntity(netcapIdent, d.Layer.String(), d.Description, &count)
	})

	// generate stream decoder entities
	stream.ApplyActionToStreamDecoders(func(d core.StreamDecoderAPI) {
		createEntity(netcapIdent, d.GetName(), d.GetDescription(), &count)
	})

	// generate stream decoder entities
	stream.ApplyActionToAbstractDecoders(func(d core.DecoderAPI) {
		createEntity(netcapIdent, d.GetName(), d.GetDescription(), &count)
	})

	// generate additional entities after generating the others
	// this allows to overwrite entities for which we want a custom icon for example
	for _, e := range maltegoEntities {
		if e.Name == "PCAP" {
			maltego.GenEntity(svgIconPath, ident, netcapIdent, netcapPrefix, propsPrefix, netcapIdent, e.Name, e.Icon, e.Description, e.Parent, "black", &maltego.RegexConversion{
				Regex: "^(.+(\\/|\\\\)(.*)\\.pcap(ng)?)",
				Properties: []string{
					"path", // 1st group matches full path
					"",
					"properties.pcap", // 3rd group contains the pcap filename
				},
			}, e.Fields...)
		} else {
			maltego.GenEntity(svgIconPath, ident, netcapIdent, netcapPrefix, propsPrefix, netcapIdent, e.Name, e.Icon, e.Description, e.Parent, "black", nil, e.Fields...)
		}
	}

	for _, tr := range transforms {
		args := []string{"transform ", strings.ToLower(string(tr.ID[0])) + tr.ID[1:]}
		maltego.GenTransform(transformWorkingDir, org, author, netcapPrefix, netcapIdent, tr.ID, tr.Description, tr.InputEntity, netmaltego.ExecutablePath, args, transformDebug)
	}

	maltego.GenServerListing(netcapPrefix, netcapIdent, transforms)
	maltego.GenTransformSet("NETCAP", "Transformations on NETCAP audit records", netcapPrefix, netcapIdent, transforms)

	maltego.GenMachines(netcapIdent, netcapMachinePrefix)
	maltego.PackMaltegoArchive(netcapIdent)

	path := filepath.Join(os.Getenv("HOME"), "netcap.mtz")
	utils.CopyFile("netcap.mtz", path)

	fmt.Println("moved archive to", path)
}

// generate all transforms and pack as archive
func TestGenerateAllTransforms(t *testing.T) {
	maltego.GenTransformArchive()

	for _, tr := range transforms {
		args := []string{"transform ", strings.ToLower(string(tr.ID[0])) + tr.ID[1:]}
		maltego.GenTransform(transformWorkingDir, org, author, netcapPrefix, "transforms", tr.ID, tr.Description, tr.InputEntity, netmaltego.ExecutablePath, args, transformDebug)
	}

	maltego.GenServerListing(netcapPrefix, "transforms", transforms)
	maltego.GenTransformSet("NETCAP", "Transformations on NETCAP audit records", netcapPrefix, "transforms", transforms)
	maltego.PackTransformArchive()

	utils.CopyFile("transforms.mtz", filepath.Join(os.Getenv("HOME"), "transforms.mtz"))
}

func TestGenerateTransformServerListing(t *testing.T) {
	lastSync := time.Now().Format("2006-01-02 15:04:05.000 MST")
	// File: Servers/Local.tas
	expected := `<MaltegoServer name="Local" enabled="true" description="Local transforms hosted on this machine" url="http://localhost">
 <LastSync>` + lastSync + `</LastSync>
 <Protocol version="0.0"></Protocol>
 <Authentication type="none"></Authentication>
 <Transforms>
  <Transform name="netcap.ToAuditRecords"></Transform>
 </Transforms>
 <Seeds></Seeds>
</MaltegoServer>`

	srv := maltego.Server{
		Name:        "Local",
		Enabled:     true,
		Description: "Local transforms hosted on this machine",
		URL:         "http://localhost",
		LastSync:    lastSync,
		Protocol: struct {
			Text    string `xml:",chardata"`
			Version string `xml:"version,attr"`
		}{
			Version: "0.0",
		},
		Authentication: struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
		}{
			Type: "none",
		},
		Transforms: struct {
			Text      string `xml:",chardata"`
			Transform []struct {
				Text string `xml:",chardata"`
				Name string `xml:"name,attr"`
			} `xml:"Transform"`
		}{
			Text: "",
			Transform: []struct {
				Text string `xml:",chardata"`
				Name string `xml:"name,attr"`
			}{
				{
					Name: "netcap.ToAuditRecords",
				},
			},
		},
		Seeds: "",
	}

	data, err := xml.MarshalIndent(&srv, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	compareGeneratedXML(data, expected, t)
}

func TestGenerateTransformSettings(t *testing.T) {
	// File: TransformRepositories/Local/netcap.ToAuditRecords.transformsettings
	expected := `<TransformSettings enabled="true" disclaimerAccepted="false" showHelp="true" runWithAll="true" favorite="false">
 <Properties>
  <Property name="transform.local.command" type="string" popup="false">/usr/local/bin/net</Property>
  <Property name="transform.local.parameters" type="string" popup="false">transform ToAuditRecords</Property>
  <Property name="transform.local.working-directory" type="string" popup="false">/usr/local/</Property>
  <Property name="transform.local.debug" type="boolean" popup="false">true</Property>
 </Properties>
</TransformSettings>`

	tr := maltego.TransformSettings{
		Enabled:            true,
		DisclaimerAccepted: false,
		ShowHelp:           true,
		RunWithAll:         true,
		Favorite:           false,
		Property: maltego.TransformSettingProperties{
			Items: []maltego.TransformSettingProperty{
				{
					Name:  "transform.local.command",
					Type:  "string",
					Popup: false,
					Text:  netmaltego.ExecutablePath,
				},
				{
					Name:  "transform.local.parameters",
					Type:  "string",
					Popup: false,
					Text:  "transform ToAuditRecords",
				},
				{
					Name:  "transform.local.working-directory",
					Type:  "string",
					Popup: false,
					Text:  "/usr/local/",
				},
				{
					Name:  "transform.local.debug",
					Type:  "boolean",
					Popup: false,
					Text:  "true",
				},
			},
		},
	}

	data, err := xml.MarshalIndent(&tr, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	compareGeneratedXML(data, expected, t)
}

func TestGenerateTransform(t *testing.T) {
	// File: TransformRepositories/Local/netcap.ToAuditRecords.transform
	expected := `<MaltegoTransform name="netcap.ToAuditRecords" displayName="To Audit Records [NETCAP]" abstract="false" template="false" visibility="public" description="Transform PCAP file into audit records" author="Philipp Mieden" requireDisplayInfo="false">
 <TransformAdapter>com.paterva.maltego.transform.protocol.v2api.LocalTransformAdapterV2</TransformAdapter>
 <Properties>
  <Fields>
   <Property name="transform.local.command" type="string" nullable="false" hidden="false" readonly="false" description="The command to execute for this transform" popup="false" abstract="false" visibility="public" auth="false" displayName="Command line">
    <SampleValue></SampleValue>
   </Property>
   <Property name="transform.local.parameters" type="string" nullable="true" hidden="false" readonly="false" description="The parameters to pass to the transform command" popup="false" abstract="false" visibility="public" auth="false" displayName="Command parameters">
    <SampleValue></SampleValue>
   </Property>
   <Property name="transform.local.working-directory" type="string" nullable="true" hidden="false" readonly="false" description="The working directory used when invoking the executable" popup="false" abstract="false" visibility="public" auth="false" displayName="Working directory">
    <DefaultValue>/</DefaultValue>
    <SampleValue></SampleValue>
   </Property>
   <Property name="transform.local.debug" type="boolean" nullable="true" hidden="false" readonly="false" description="When this is set, the transform&amp;apos;s text output will be printed to the output window" popup="false" abstract="false" visibility="public" auth="false" displayName="Show debug info">
    <SampleValue>false</SampleValue>
   </Property>
  </Fields>
 </Properties>
 <InputConstraints>
  <Entity type="netcap.PCAP" min="1" max="1"></Entity>
 </InputConstraints>
 <OutputEntities></OutputEntities>
 <defaultSets>
  <Set name="NETCAP"></Set>
 </defaultSets>
 <StealthLevel>0</StealthLevel>
</MaltegoTransform>`

	id := "ToAuditRecords"

	tr := maltego.NewTransform(
		org,
		author,
		netcapPrefix,
		id,
		"Transform PCAP file into audit records",
		"netcap.PCAP",
	)

	data, err := xml.MarshalIndent(&tr, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	compareGeneratedXML(data, expected, t)
}
