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

	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/decoder"
)

// additional entities that are not actual NETCAP audit records
var maltegoEntities = []entityCoreInfo{
	{"ContentType", "category", "A MIME type describes different multi-media formats", "", nil},
	{"Email", "mail_outline", "An email message", "maltego.Email", nil},
	{"Interface", "router", "A network interface", "", []propertyField{newRequiredStringField("properties.interface", "Name of the network interface"), newStringField("snaplen", "snap length for ethernet frames in bytes, default: 1514"), newStringField("bpf", "berkeley packet filter to apply")}},
	{"PCAP", "sd_storage", "A packet capture dump file", "", []propertyField{newRequiredStringField("path", "Absolute path to the PCAP file")}},
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
	{"Credentials", "security", "Credentials for accessing services that require user authentication", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"File", "text_snippet", "A file", "maltego.File", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"Software", "apps", "A software product", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"Service", "miscellaneous_services", "A software product", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"InternalIPProfile", "contact_page_outline", "A behavior profile for an internal IP address", "netcap.IPAddr", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"ExternalIPProfile", "contact_page", "A behavior profile for an external IP address", "netcap.IPAddr", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"Vulnerability", "bug_report", "A software exploit", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"Exploit", "coronavirus", "A software vulnerability", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"Flow", "arrow_right_alt", "A undirectional network flow", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"Connection", "compare_arrows", "A bidirectional network connection", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"TLSClientHello", "call_made", "A TLS Client", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
	{"TLSServerHello", "call_received", "A TLS Server", "", []propertyField{newStringField("path", "path to the audit records on disk")}},
}

// generate all entities and pack as archive
func TestGenerateAllEntities(t *testing.T) {
	genEntityArchive()

	var count int

	// generate entities for audit records
	// *AuditRecords entity and an entity for the actual audit record instance
	decoder.ApplyActionToCustomDecoders(func(d decoder.CustomDecoderAPI) {
		genEntity("entities", d.GetName()+"AuditRecords", "insert_drive_file", "An archive of "+d.GetName()+" audit records", "", true, colors[count], nil, newStringField("path", "path to the audit records on disk"))
		genEntity("entities", d.GetName(), d.GetName(), d.GetDescription(), "", false, "black", nil)
		count++

		if count >= len(colors) {
			count = 0
		}
	})

	decoder.ApplyActionToGoPacketDecoders(func(e *decoder.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		genEntity("entities", name+"AuditRecords", "insert_drive_file", "An archive of "+e.Layer.String()+" audit records", "", true, colors[count], nil, newStringField("path", "path to the audit records on disk"))
		genEntity("entities", name, name, e.Description, "", false, "black", nil)
		count++

		if count >= len(colors) {
			count = 0
		}
	})

	// generate additional entities after generating the others
	// this allows to overwrite entities for which we want a custom icon for example
	for _, e := range maltegoEntities {
		genEntity("entities", e.Name, e.Icon, e.Description, e.Parent, false, "black", nil, e.Fields...)
	}

	packEntityArchive()

	copyFile("entities.mtz", filepath.Join(os.Getenv("HOME"), "entities.mtz"))
}

func TestGenerateAndPackVulnerabilityEntity(t *testing.T) {
	genEntityArchive()
	genEntity("entities", "Vulnerability", "Vulnerability", "A software vulnerability", "", false, "black", nil)
	packEntityArchive()
}

func TestGenerateAndPackPCAPEntity(t *testing.T) {
	genEntityArchive()
	genEntity("entities", "PCAP", "sd_storage", "Packet capture file", "", false, "black", nil, newStringField("path", "path to the audit records on disk"))
	packEntityArchive()
}

func TestGenerateAndPackAuditRecordEntity(t *testing.T) {
	genEntityArchive()
	genEntity("entities", "IPv4", "IPv4", "IPv4 Audit Records", "", false, "black", nil, newStringField("path", "path to the audit records on disk"))
	packEntityArchive()
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
</MaltegoEntity>`

	e := newEntity("PCAP", "General/SharkAttack", "Packet capture file", "", false, &regexConversion{
		regex: "^(.+\\/([^\\/]+)[A-Za-z]*\\.pcap)",
		properties: []string{
			"path",
			"properties.pcap",
		},
	}, newStringField("path", "path to the audit records on disk"))

	data, err := xml.MarshalIndent(e, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	compareGeneratedXML(data, expected, t)
}

func compareGeneratedXML(data []byte, expected string, t *testing.T) {
	fmt.Println("-------------------RESULT--------------------------")
	fmt.Println(string(data))
	fmt.Println("------------------------------------------------")

	if string(data) != expected {

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
	e := XMLEntity{
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
		Properties: entityProperties{
			XMLName:      xml.Name{},
			Text:         "",
			Value:        "properties.dhcpclient",
			DisplayValue: "properties.dhcpclient",
			Fields: fields{
				Text: "",
				Items: []propertyField{
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
