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
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/maltego"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder"
)

// additional transforms
var transforms = []transformCoreInfo{
	{"ToApplicationCategories", "netcap.IPAddr", "Retrieve categories of classified applications"},
	{"ToApplications", "netcap.IPAddr", "Show all applications used by the selected host"},
	{"ToApplicationsForCategory", "netcap.ApplicationCategory", "Retrieve applications seen for a given category"},
	{"ToCookiesForHTTPHost", "netcap.Website", "Retrieve cookies seen for the given host"},
	{"ToCookieValues", "netcap.HTTPCookie", "Retrieve values for a given cookie identifier"},
	{"ToHeadersForHTTPHost", "netcap.Website", "Retrieve headers seen for the given host"},
	{"ToHeaderValues", "netcap.HTTPHeader", "Retrieve values for a given header identifier"},
	{"ToDHCP", "netcap.IPAddr", "Fetch DHCP options for host"},
	{"ToDNSQuestions", "netcap.IPAddr", "Show all captured DNS questions for the selected host"},
	{"ToDestinationIPs", "netcap.Device", "Get destination hosts seen for the selected device"},
	{"ToSourceIPs", "netcap.Device", "Get all IPs that the device has been using"},
	{"ToDstPorts", "netcap.IPAddr", "Retrieve all destination ports seen for the selected host"},
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
	{"ToIncomingFlowsFiltered", "netcap.IPAddr", "Show all incoming flows filtered against the configured whitelist"},
	{"ToMailAuthToken", "netcap.IPAddr", "Retrieve POP3 auth tokens"},
	{"ToMailFrom", "netcap.IPAddr", "Retrieve all email addresses from the 'From' field"},
	{"ToMailTo", "netcap.IPAddr", "Retrieve all email addresses from the 'To' field"},
	{"ToMailUserPassword", "maltego.Person", "Retrieve the password for a mail user"},
	{"ToMailUsers", "netcap.IPAddr", "Retrieve email users"},
	{"ToMails", "netcap.IPAddr", "Show mails fetched over POP3"},
	{"ToOutgoingFlowsFiltered", "netcap.IPAddr", "Show all outgoing flows filtered against the configured whitelist"},
	{"ToParameterValues", "netcap.HTTPParameter", "Retrieve all values seen for an HTTP parameter"},
	{"ToParametersForHTTPHost", "netcap.Website", "Retrieve HTTP params for a host"},
	{"ToServerNameIndicators", "netcap.IPAddr", "Retrieve the TLS Server Name Indicators seen for the selected host"},
	{"ToSrcPorts", "netcap.IPAddr", "Retrieve all source ports seen for the selected host"},
	{"ToURLsForHost", "netcap.IPAddr", "Retrieve all URLs seen for the selected host"},
	{"ToURLsForWebsite", "netcap.Website", "Retrieve all urls for a given host"},
	{"ToAuditRecords", "netcap.PCAP", "Transform PCAP file into audit records"},
	{"ToAuditRecordsWithDPI", "netcap.PCAP", "Retrieve audit records with Deep Packet Inspection enabled"},
	{"StartCaptureProcess", "netcap.Interface", "Start network capture on the given interface"},
	{"ToDHCPClients", "netcap.DHCPv4AuditRecords", "Show all DHCP Clients"},
	{"ToDNSQuestions", "netcap.DNSAuditRecords", "Show all DNS questions"},
	{"ToFetchedMails", "netcap.POP3AuditRecords", "Show emails fetched over POP3"},
	{"ToFileTypes", "netcap.FileAuditRecords", "Show MIME types for extracted files"},
	{"ToHTTPHostnames", "netcap.HTTPAuditRecords", "Show all visited website hostnames"},
	{"ToIANAServices", "netcap.FlowAuditRecords", "Show all IANA services identified by the flows destination port"},
	{"ToIANAServicesForConnections", "netcap.ConnectionAuditRecords", "Show all IANA services identified by the connection destination port"},
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
	{"ToFlowsForService", "netcap.Service", "Show all flows for the selected service"},
	{"ToConnectionsForService", "netcap.Service", "Show all connections for the selected service"},

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

	{"ToNetworkInterfaces", "netcap.Host", "Show all available network interfaces"},
	{"LookupDHCPFingerprint", "netcap.DHCPClient", "Resolve the clients DHCP fingerprint via the fingerbank API"},
	{"StopCaptureProcess", "netcap.Interface", "Stop the NETCAP capture process"},

	{"ToServices", "netcap.ServiceType", "Show detected network services for the given service type"},
	{"ToServiceTypes", "netcap.ServiceAuditRecords", "Show detected network service types"},

	{"ToSourceDevices", "netcap.IPProfile", "Show the source devices for the given ip profile"},
	{"ToApplicationsForProfile", "netcap.IPProfile", "Show the applications seen for the given ip profile"},
	{"ToSNIsForProfile", "netcap.IPProfile", "Show the server name indicator seen for the given ip profile"},
	{"ToJA3HashesForProfile", "netcap.IPProfile", "Show the ja3 hashes seen for the given ip profile"},

	{"ToVisitorsForURL", "netcap.URL", "Show all visitors for the selected URL"},
	{"ToVisitorsForWebsite", "netcap.Website", "Show all visitors for the selected website"},
	{"ToProvidersForURL", "netcap.URL", "Show all providers for the selected URL"},
	{"ToProvidersForWebsite", "netcap.Website", "Show all providers for the selected website"},

	// Wireshark integration
	{"OpenConnectionInWireshark", "netcap.Connection", "Open the selected connection in wireshark"},
	{"OpenFlowInWireshark", "netcap.Flow", "Open the selected flow in wireshark"},
	{"OpenServiceInWireshark", "netcap.Service", "Open all traffic from and towards the selected service in wireshark"},
	{"OpenHostTrafficInWireshark", "netcap.IPProfile", "Open all traffic from and towards the selected host in wireshark"},
	{"OpenTrafficInWireshark", "netcap.IPAddr", "Open all traffic from and towards the selected host in wireshark"},
	{"OpenDeviceTrafficInWireshark", "netcap.Device", "Open all traffic from and towards the selected device in wireshark"},
	{"OpenSoftwareTrafficInWireshark", "netcap.Software", "Open traffic identified as the selected software in wireshark"},
	{"OpenVulnerabilityTrafficInWireshark", "netcap.Vulnerability", "Open the traffic indicating the selected vulnerability in wireshark"},

	{"OpenFileInDisassembler", "netcap.File", "Open binary file in disassembler for analysis"},
}

func genFullConfigArchive() {
	// clean
	_ = os.RemoveAll(netcapIdent)

	// create directories
	_ = os.MkdirAll("netcap/Servers", 0o700)
	_ = os.MkdirAll("netcap/TransformRepositories/Local", 0o700)

	// create directories
	_ = os.MkdirAll("netcap/Entities", 0o700)
	_ = os.MkdirAll("netcap/EntityCategories", 0o700)
	_ = os.MkdirAll("netcap/Icons", 0o700)

	fVersion, err := os.Create("netcap/version.properties")
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if errClose := fVersion.Close(); errClose != nil {
			fmt.Println(errClose)
		}
	}()

	fCategory, err := os.Create("netcap/EntityCategories/netcap.category")
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if errClose := fCategory.Close(); errClose != nil {
			fmt.Println(errClose)
		}
	}()

	// Sat Jun 13 21:48:54 CEST 2020
	_, _ = fVersion.WriteString(`#
#` + time.Now().Format(time.UnixDate) + `
maltego.client.version=4.2.12
maltego.client.subtitle=
maltego.pandora.version=1.4.2
maltego.client.name=Maltego Classic Eval
maltego.mtz.version=1.0
maltego.graph.version=1.2`)

	_, _ = fCategory.WriteString("<EntityCategory name=\"Netcap\"/>")

	fmt.Println("bootstrapped netcap configuration archive for Maltego")
}

// generate all transforms and pack as archive
func TestGenerateFullMaltegoConfiguration(t *testing.T) {
	genFullConfigArchive()

	// generate entities for audit records
	// *AuditRecords entity and an entity for the actual audit record instance
	decoder.ApplyActionToCustomDecoders(func(d decoder.CustomDecoderAPI) {
		genEntity(
			netcapIdent,
			d.GetName()+"AuditRecords",
			"insert_drive_file",
			"An archive of "+d.GetName()+" audit records",
			"",
			true,
			newStringField("path", "path to the audit records on disk"),
		)
		genEntity(netcapIdent, d.GetName(), d.GetName(), d.GetDescription(), "", false)
	})

	decoder.ApplyActionToGoPacketDecoders(func(e *decoder.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		genEntity(
			netcapIdent,
			name+"AuditRecords",
			"insert_drive_file",
			"An archive of "+e.Layer.String()+" audit records",
			"",
			true,
			newStringField("path", "path to the audit records on disk"),
		)
		genEntity(netcapIdent, name, name, e.Description, "", false)
	})

	// generate additional entities after generating the others
	// this allows to overwrite entities for which we want a custom icon for example
	for _, e := range maltegoEntities {
		genEntity(netcapIdent, e.Name, e.Icon, e.Description, e.Parent, false, e.Fields...)
	}

	for _, tr := range transforms {
		genTransform(netcapIdent, tr.ID, tr.Description, tr.InputEntity)
	}

	genServerListing(netcapIdent)
	genTransformSet(netcapIdent)
	genMachines()
	packMaltegoArchive(netcapIdent)

	path := filepath.Join(os.Getenv("HOME"), "netcap.mtz")
	copyFile("netcap.mtz", path)

	fmt.Println("moved archive to", path)
}

func genMachines() {

	path := filepath.Join(netcapIdent, "Machines")

	err := os.Mkdir(path, defaults.DirectoryPermission)
	if err != nil {
		log.Fatal(err)
	}

	files, err := ioutil.ReadDir("machines")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {

		// Machine Properties
		propFile, err := os.Create(
			filepath.Join(
				path,
				netcapMachinePrefix+strings.Replace(
					filepath.Base(f.Name()),
					".machine",
					".properties",
					1,
				),
			),
		)
		if err != nil {
			log.Fatal(err)
		}

		_, _ = propFile.WriteString(`#` + time.Now().Format(time.UnixDate) + `
favorite=true
enabled=true`)

		err = propFile.Close()
		if err != nil {
			log.Fatal(err)
		}

		// Machine

		copyFile(
			filepath.Join("machines", f.Name()),
			filepath.Join(
				path,
				netcapMachinePrefix+filepath.Base(f.Name()),
			),
		)
	}
}

// generate all transforms and pack as archive
func TestGenerateAllTransforms(t *testing.T) {
	genTransformArchive()

	for _, tr := range transforms {
		genTransform("transforms", tr.ID, tr.Description, tr.InputEntity)
	}

	genServerListing("transforms")
	genTransformSet("transforms")
	packTransformArchive()

	copyFile("transforms.mtz", filepath.Join(os.Getenv("HOME"), "transforms.mtz"))
}

func TestToTransformDisplayName(t *testing.T) {
	res := toTransformDisplayName("ToTCPServices")
	if res != "To TCP Services [NETCAP]" {
		t.Fatal("unexpected result", res)
	}

	res = toTransformDisplayName("ToDHCP")
	if res != "To DHCP [NETCAP]" {
		t.Fatal("unexpected result", res)
	}

	res = toTransformDisplayName("ToServerNameIndicators")
	if res != "To Server Name Indicators [NETCAP]" {
		t.Fatal("unexpected result", res)
	}

	res = toTransformDisplayName("ToURLsForHost")
	if res != "To URLs For Host [NETCAP]" {
		t.Fatal("unexpected result", res)
	}

	res = toTransformDisplayName("ToSourceIPs")
	if res != "To Source IPs [NETCAP]" {
		t.Fatal("unexpected result", res)
	}
}

func genServerListing(outDir string) {
	srv := server{
		Name:        "Local",
		Enabled:     true,
		Description: "Local transforms hosted on this machine",
		URL:         "http://localhost",
		LastSync:    time.Now().Format("2006-01-02 15:04:05.000 MST"), // example: 2020-06-23 20:47:24.433 CEST"
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
		Seeds: "",
	}

	for _, t := range transforms {
		srv.Transforms.Transform = append(srv.Transforms.Transform, struct {
			Text string `xml:",chardata"`
			Name string `xml:"name,attr"`
		}{
			Name: netcapPrefix + t.ID,
		})
	}

	data, err := xml.MarshalIndent(srv, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(filepath.Join(outDir, "Servers", "Local.tas"))
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Write(data)
	if err != nil {
		log.Fatal(err)
	}

	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func genTransformSet(outDir string) {
	tSet := transformSet{
		Name:        "NETCAP",
		Description: "Transformations on NETCAP audit records",
	}

	for _, t := range transforms {
		tSet.Transforms.Transform = append(tSet.Transforms.Transform, struct {
			Text string `xml:",chardata"`
			Name string `xml:"name,attr"`
		}{
			Name: netcapPrefix + t.ID,
		})
	}

	data, err := xml.MarshalIndent(tSet, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	_ = os.MkdirAll(filepath.Join(outDir, "TransformSets"), 0o700)
	f, err := os.Create(filepath.Join(outDir, "TransformSets", "netcap.set"))
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Write(data)
	if err != nil {
		log.Fatal(err)
	}

	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}
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

	srv := server{
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

	tr := transformSettings{
		Enabled:            true,
		DisclaimerAccepted: false,
		ShowHelp:           true,
		RunWithAll:         true,
		Favorite:           false,
		Property: transformSettingProperties{
			Items: []transformSettingProperty{
				{
					Name:  "transform.local.command",
					Type:  "string",
					Popup: false,
					Text:  maltego.ExecutablePath,
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

	tr := newTransform(
		"ToAuditRecords",
		"Transform PCAP file into audit records",
		"netcap.PCAP")

	data, err := xml.MarshalIndent(&tr, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	compareGeneratedXML(data, expected, t)
}
