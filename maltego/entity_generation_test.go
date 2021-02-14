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

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/utils"

	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream"
)

// additional entities that are not actual NETCAP audit records
var maltegoEntities = []maltego.EntityCoreInfo{
	{"ContentType", "category", "A MIME type describes different multi-media formats", "", nil},
	{"Email", "mail_outline", "An email message", "maltego.Email", nil},
	{"Interface", "router", "A network interface", "", []*maltego.PropertyField{maltego.NewRequiredStringField("properties.interface", "Name of the network interface"), maltego.NewStringField("snaplen", "snap length for ethernet frames in bytes, default: 1514"), maltego.NewStringField("bpf", "berkeley packet filter to apply")}},
	{"PCAP", "sd_storage", "A packet capture dump file", "", []*maltego.PropertyField{maltego.NewRequiredStringField("path", "Absolute path to the PCAP file")}},
	{"Device", "devices", "A device seen on the network", "", nil},
	{"FileType", "insert_chart", "The type of file based on its contents", "", nil},
	{"IPAddr", "router", "An internet protocol (IP) network address", "maltego.IPv4Address", nil},

	{"DNSFlagCombination", "outlined_flag", "A combination of DNS flags", "", nil},
	{"DNSResponseCode", "contact_support", "A DNS response code", "", nil},

	{"InternalSourceIP", "cloud_upload_outline", "An internal source address", "netcap.IPAddr", nil},
	{"ExternalSourceIP", "cloud_upload", "An external source address", "netcap.IPAddr", nil},
	{"InternalDestinationIP", "cloud_download_outline", "An internal destination address", "netcap.IPAddr", nil},
	{"ExternalDestinationIP", "cloud_download", "An external destination address", "netcap.IPAddr", nil},

	{"DHCPClient", "cast_connected", "A DHCP client", "", nil},
	{"DHCPResult", "fingerprint", "A DHCP fingerprint result", "", nil},

	{"Port", "device_hub", "A TCP / UDP destination port", "", nil},
	{"DestinationPort", "arrow_back", "A TCP / UDP destination port", "netcap.Port", nil},
	{"SourcePort", "arrow_forward", "A TCP / UDP source port", "netcap.Port", nil},
	{"ContactedPort", "arrow_upward", "A TCP / UDP contact port", "netcap.Port", nil},

	{"ICMPv4ControlMessageType", "settings_system_daydream", "An ICMPv4 Type Code", "", nil},
	{"ICMPv6ControlMessageType", "bubble_chart", "An ICMPv6 Type Code", "", nil},
	{"HTTPCookie", "copyright", "A HTTP cookie", "", nil},

	{"TCPFlag", "flag", "A TCP flag", "", nil},
	{"EthernetType", "title", "An Ethernet type", "", nil},
	{"IPProtocol", "multiple_stop", "An IP protocol", "", nil},
	{"IPv6TrafficClass", "class", "An IPv6 traffic class", "", nil},
	{"LinkType", "power_input", "An ARP Link Type", "", nil},
	{"IGMPType", "panorama_fish_eye", "An IGMP type", "", nil},
	{"IGMPGroupRecordType", "group", "An IGMPv3 group record type", "", nil},
	{"SMTPCommandType", "all_inbox", "A SMTP command type", "", nil},
	{"DNSOpCode", "api", "A DNS op code", "", nil},

	{"DHCPv6MessageType", "chat", "A DHCPv6 message type", "", nil},
	{"DHCPv6Option", "read_more", "A DHCPv6 option", "", nil},
	{"NTPReferenceID", "qr_code", "A NTP Reference ID", "", nil},

	{"HTTPHeader", "ballot", "A HTTP header", "", nil},
	{"HTTPHeaderValue", "pending", "A HTTP header value", "", nil},

	{"HTTPParameter", "live_help", "", "A HTTP request parameter name", nil},
	{"HTTPParameterValue", "settings_ethernet", "A HTTP request parameter value", "", nil},
	{"HTTPStatusCode", "highlight", "A HTTP server response code", "", nil},
	{"ServerName", "scanner", "A network server software name", "", nil},
	{"SSHClient", "call_made", "A Secure Shell Protocol Client", "", nil},
	{"SSHServer", "call_received", "A Secure Shell Protocol Server", "", nil},
	{"TCPService", "device_hub", "A TCP network service", "", nil},
	{"UDPService", "developer_board", "A UDP network service", "", nil},
	{"UserAgent", "supervisor_account", "A HTTP User Agent", "", nil},
	{"Host", "web", "A HTTP Hostname", "netcap.IPAddr", nil},
	{"DNSName", "chrome_reader_mode", "A DNS Name", "maltego.DNSName", nil},
	{"Domain", "domain", "A domain", "maltego.Domain", nil},
	{"Location", "location_on", "A location", "maltego.Location", nil},
	{"URL", "open_in_browser", "A Uniform Resource Identifier", "maltego.URL", nil},
	{"HTTPCookieValue", "info", "A HTTP cookie value", "", nil},
	{"ExifEntry", "info", "An Exif entry for an image file", "", nil},
	{"MD5Hash", "info", "An MD5 hash entry for an extracted file", "maltego.Hash", nil},
	{"PhoneNumber", "contact_phone", "A phone number", "maltego.PhoneNumber", nil},
	{"Computer", "dvr", "A computer host", "", nil},
	{"ServiceType", "import_export", "A network service type", "", nil},
	{"Application", "settings_applications", "An application discovered via DPI", "", nil},
	{"ApplicationCategory", "design_services", "An application category discovered via DPI", "", nil},

	// overwrites
	{"Credentials", "security", "Credentials for accessing services that require user authentication", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"File", "text_snippet", "A file", "maltego.File", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"Software", "apps", "A software product", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"Service", "miscellaneous_services", "A software product", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"InternalIPProfile", "contact_page_outline", "A behavior profile for an internal IP address", "netcap.IPAddr", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"ExternalIPProfile", "contact_page", "A behavior profile for an external IP address", "netcap.IPAddr", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"Vulnerability", "bug_report", "A software exploit", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"Exploit", "coronavirus", "A software vulnerability", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"Flow", "arrow_right_alt", "A undirectional network flow", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"Connection", "compare_arrows", "A bidirectional network connection", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"TLSClientHello", "call_made", "A TLS Client", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
	{"TLSServerHello", "call_received", "A TLS Server", "", []*maltego.PropertyField{maltego.NewStringField("path", "path to the audit records on disk")}},
}

// generate all entities and pack as archive
func TestGenerateAllEntities(t *testing.T) {
	maltego.GenEntityArchive(ident)

	var (
		count int
		out   = "entities"
	)

	// generate entities for audit records
	// *AuditRecords entity and an entity for the actual audit record instance
	packet.ApplyActionToPacketDecoders(func(d packet.DecoderAPI) {
		createEntity(out, d.GetName(), d.GetDescription(), &count)
	})

	packet.ApplyActionToGoPacketDecoders(func(d *packet.GoPacketDecoder) {
		createEntity(out, d.Layer.String(), d.Description, &count)
	})

	stream.ApplyActionToStreamDecoders(func(d core.StreamDecoderAPI) {
		createEntity(out, d.GetName(), d.GetDescription(), &count)
	})

	stream.ApplyActionToAbstractDecoders(func(d core.DecoderAPI) {
		createEntity(out, d.GetName(), d.GetDescription(), &count)
	})

	// generate additional entities after generating the others
	// this allows to overwrite entities for which we want a custom icon for example
	for _, e := range maltegoEntities {
		maltego.GenEntity(svgIconPath, ident, netcapIdent, netcapPrefix, propsPrefix, "entities", e.Name, e.Icon, e.Description, e.Parent, "black", nil, e.Fields...)
	}

	maltego.PackEntityArchive()

	utils.CopyFile("entities.mtz", filepath.Join(os.Getenv("HOME"), "entities.mtz"))
}

func TestGenerateAndPackVulnerabilityEntity(t *testing.T) {
	maltego.GenEntityArchive(ident)
	maltego.GenEntity(svgIconPath, ident, netcapIdent, netcapPrefix, propsPrefix, "entities", "Vulnerability", "Vulnerability", "A software vulnerability", "", "black", nil)
	maltego.PackEntityArchive()
}

func TestGenerateAndPackPCAPEntity(t *testing.T) {
	maltego.GenEntityArchive(ident)
	maltego.GenEntity(svgIconPath, ident, netcapIdent, netcapPrefix, propsPrefix, "entities", "PCAP", "sd_storage", "Packet capture file", "", "black", nil, maltego.NewStringField("path", "path to the audit records on disk"))
	maltego.PackEntityArchive()
}

func TestGenerateAndPackAuditRecordEntity(t *testing.T) {
	maltego.GenEntityArchive(ident)
	maltego.GenEntity(svgIconPath, ident, netcapIdent, netcapPrefix, propsPrefix, "entities", "IPv4", "IPv4", "IPv4 Audit Records", "", "black", nil, maltego.NewStringField("path", "path to the audit records on disk"))
	maltego.PackEntityArchive()
}

func TestGeneratePCAPXMLEntity(t *testing.T) {
	expected := `<MaltegoEntity id="netcap.PCAP" displayName="PCAP" displayNamePlural="PCAP" description="Packet capture file" category="Netcap" smallIconResource="General/SharkAttack" largeIconResource="General/SharkAttack" allowedRoot="true" conversionOrder="2147483647" visible="true">
 <Properties value="properties.pcap" displayValue="properties.pcap">
  <Groups></Groups>
  <Fields>
   <Field name="properties.pcap" type="string" nullable="true" hidden="false" readonly="false" description="" displayName="PCAP">
    <SampleValue>-</SampleValue>
   </Field>
   <Field name="path" type="string" nullable="true" hidden="false" readonly="false" description="path to the audit records on disk" displayName="Path">
    <SampleValue></SampleValue>
   </Field>
  </Fields>
 </Properties>
 <Converter>
  <Value>^(.+\/([^\/]+)[A-Za-z]*\.pcap)</Value>
  <RegexGroups>
   <RegexGroup property="path"></RegexGroup>
   <RegexGroup property="properties.pcap"></RegexGroup>
  </RegexGroups>
 </Converter>
</MaltegoEntity>`

	e := maltego.NewMaltegoEntity(ident, netcapIdent, netcapPrefix, propsPrefix, "PCAP", "General/SharkAttack", "Packet capture file", "", &maltego.RegexConversion{
		Regex: "^(.+\\/([^\\/]+)[A-Za-z]*\\.pcap)",
		Properties: []string{
			"path",
			"properties.pcap",
		},
	}, maltego.NewStringField("path", "path to the audit records on disk"))

	data, err := xml.MarshalIndent(e, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	compareGeneratedXML(data, expected, t)
}

func compareGeneratedXML(data []byte, expected string, t *testing.T) {

	if string(data) != expected {
		fmt.Println("-------------------RESULT--------------------------")
		fmt.Println(string(data))
		fmt.Println("------------------------------------------------")

		fmt.Println("-------------------EXPECTED--------------------------")
		fmt.Println(expected)
		fmt.Println("------------------------------------------------")

		resultArr := strings.Split(string(data), "\n")
		expectedArr := strings.Split(expected, "\n")

		fmt.Println(ansi.Red, "len(resultArr)", len(resultArr), ansi.Blue, "len(expectedArr)", len(expectedArr), ansi.Reset)

		for i, line := range expectedArr {
			if len(resultArr) <= i {
				break
			}
			if line != resultArr[i] {
				fmt.Println(ansi.Red, resultArr[i], ansi.Reset)
				fmt.Println(ansi.Blue, expectedArr[i], ansi.Reset)
			} else {
				fmt.Println(resultArr[i])
			}
		}

		t.Fatal("unexpected output")
	}
}

func TestGenerateDHCPClientXMLEntity(t *testing.T) {
	expected := `<MaltegoEntity id="netcap.DHCPClient" displayName="DHCPClient" displayNamePlural="DHCPClients" description="A DHCP client" category="Netcap" smallIconResource="Technology/WAN" largeIconResource="Technology/WAN" allowedRoot="true" conversionOrder="2147483647" visible="true">
 <Properties value="properties.dhcpclient" displayValue="properties.dhcpclient">
  <Groups></Groups>
  <Fields>
   <Field name="properties.dhcpclient" type="string" nullable="true" hidden="false" readonly="false" description="" displayName="DHCPClient">
    <SampleValue>-</SampleValue>
   </Field>
  </Fields>
 </Properties>
</MaltegoEntity>`
	e := maltego.MaltegoEntity{
		ID:                "netcap.DHCPClient",
		DisplayName:       "DHCPClient",
		DisplayNamePlural: "DHCPClients",
		Description:       "A DHCP client",
		Category:          "Netcap",
		SmallIconResource: "Technology/WAN",
		LargeIconResource: "Technology/WAN",
		AllowedRoot:       true,
		ConversionOrder:   "2147483647",
		Visible:           true,
		Properties: maltego.EntityProperties{
			Value:        "properties.dhcpclient",
			DisplayValue: "properties.dhcpclient",
			Fields: maltego.Fields{
				Items: []*maltego.PropertyField{
					{
						Name:        "properties.dhcpclient",
						Type:        "string",
						Nullable:    true,
						Hidden:      false,
						Readonly:    false,
						Description: "",
						DisplayName: "DHCPClient",
						SampleValue: "-",
					},
				},
			},
		},
	}

	data, err := xml.MarshalIndent(e, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	compareGeneratedXML(data, expected, t)
}

func createEntity(outpath string, name string, description string, count *int) {
	n := strings.ReplaceAll(name, "/", "")
	maltego.GenEntity(
		svgIconPath,
		identArchive,
		netcapIdent,
		netcapPrefix,
		propsPrefix,
		outpath,
		n+"AuditRecords",
		"insert_drive_file",
		"An archive of "+n+" audit records",
		"",
		colors[*count],
		&maltego.RegexConversion{
			Regex: "^(.+(\\/|\\\\)(" + n + ")\\.ncap(\\.gz)?)",
			Properties: []string{
				"path",
				"",
				propsPrefix + strings.ToLower(n+"AuditRecords"), // 3rd group contains the name
			},
		},
		maltego.NewStringField("path", "path to the audit records on disk"),
	)
	maltego.GenEntity(svgIconPath, ident, netcapIdent, netcapPrefix, propsPrefix, outpath, n, n, description, "", "black", nil)

	*count++
	if *count >= len(colors) {
		*count = 0
	}
}
