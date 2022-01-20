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

package transform

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/dreadl0ck/maltego"
)

// Run parses the subcommand flags and handles the arguments.
func Run() {
	if len(os.Args) < 3 {
		log.Fatal("expecting transform name")
	}

	log.Println("os.Args:", os.Args)
	initTransformTool()

	for _, f := range []func(){
		startCaptureProcess,
		stopCaptureProcess,
		toAuditRecords,
		toLiveAuditRecords,
		toAuditRecordsUsingDPI,
		openNetcapFolder,
		toFileTypesForIP,
		toSoftwareExploits,
		openExploit,
		toDHCPClients,
		lookupDHCPFingerprint,
		toSSHClients,
		toSSHServers,
		toSoftwareProducts,
		toIPProfilesForSoftware,
		toCredentialsByService,
		toLoginInformation,
		toHosts,
		toUDPHosts,
		toNTPHosts,
		toNTPReferenceIDs,
		toEmails,
		toICMPV4ControlMessages,
		toICMPV6ControlMessages,
		toHTTPHostnames,
		toSoftwareVulnerabilities,
		openVulnerability,
		toDNSQuestions,
		toDevices,
		toApplicationCategories,
		toApplications,
		toApplicationsForCategory,
		openFile,
		openFileInDisassembler,
		toCookieValues,
		toContactedPorts,
		toHTTPHeaders,
		toHeaderValues,
		toDHCP,
		toDHCPV6MessageTypes,
		toDHCPV6Options,
		toDNSOpCodes,
		toDNSFlagCombinations,
		toDNSResponseCodes,
		openFolder,
		toDestinationIPs,
		toSourceIPs,
		toSourceDevices,
		toHTTPHostsFiltered,
		toDestinationPorts,
		toIncomingConnsFiltered,
		toFileTypes,
		toFiles,
		toFileType,
		toFilesForContentType,
		toGeolocation,
		toIPProfiles,
		toJA3HashesForProfile,
		toParameterValues,
		toNetworkInterfaces,
		toHTTPContentTypes,
		toHTTPCookies,
		toHTTPHosts,
		toHTTPParameters,
		toHTTPServerNames,
		toHTTPStatusCodes,
		toHTTPUniformResourceLocators,
		toHTTPUserAgents,
		toMailAuthTokens,
		toTCPFlagCombinations,
		toEthernetTypes,
		toIPV4Protocols,
		toLinkTypes,
		toIGMPTypes,
		toIGMPGroupRecordTypes,
		toIPV6TrafficClasses,
		toMailFrom,
		toMailTo,
		toMailUserPassword,
		toMailUsers,
		toMails,
		toServerNameIndicators,
		toSourcePorts,
		toOutgoingConnsFiltered,
		toVisitorsForURL,
		toVisitorsForHost,
		toProviderIPProfilesForURL,
		toProviderIPProfilesForHost,
		openNetcapFolderInTerminal,
		openLiveNetcapFolder,
		openImage,
		openLiveNetcapFolderInTerminal,
		openFilesFolder,
		openContentTypeFolder,
		toMD5HashesForFileName,
		toLinksFromFile,
		toDomainsFromFile,
		toIPsFromFile,
		toEmailsFromFile,
		toPhoneNumbersFromFile,
		toMD5HashesForImage,
		toExifDataForImage,
		toHostsForService,
		toServices,
		toServiceTypes,
		toSMTPCommandTypes,
		toIANAServices,
		toConnectionsForService,
		toConnectionsForHost,
		toConnectionsForPort,
		toJA3Hashes,
		toJA3SHashes,
		openConnectionInWireshark,
		openFlowInWireshark,
		openHostTrafficInWireshark,
		openTrafficInWireshark,
		openDeviceTrafficInWireshark,
		openServiceInWireshark,
		openSoftwareTrafficInWireshark,
		openTrafficForPortInWireshark,
		openVulnerabilityTrafficInWireshark,
		reloadAuditRecordsFromDisk,
	} {
		if os.Args[2] == getFuncName(f) {
			f()

			return
		}
	}

	trx := &maltego.Transform{}
	trx.AddUIMessage("Unknown transform: "+os.Args[2], maltego.UIMessageFatal)
	fmt.Println(trx.ReturnOutput())
}

func getFuncName(f func()) string {
	return strings.TrimPrefix(filepath.Base(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()), "transform.")
}
