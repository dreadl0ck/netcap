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

	"github.com/dreadl0ck/netcap/maltego"
)

var outDirPermission os.FileMode = 0o755

// Run parses the subcommand flags and handles the arguments.
func Run() {
	if len(os.Args) < 3 {
		log.Fatal("expecting transform name")
	}

	log.Println("os.Args:", os.Args)

	for _, f := range []func(){
		toCaptureProcess,
		stopCaptureProcess,
		toAuditRecords,
		toLiveAuditRecords,
		toAuditRecordsWithDPI,
		openNetcapFolder,
		toFileTypesForIP,
		toSoftwareExploits,
		openExploit,
		toDHCPClients,
		lookupDHCPFingerprint,
		toSSHClients,
		toSSHServers,
		toProducts,
		toCredentialsByService,
		toLoginInformation,
		toFetchedMails,
		toHTTPHostNames,
		toSoftwareVulnerabilities,
		openVulnerability,
		toDNSQuestions,
		toIANAServices,
		toDevices,
		toHTTPHostNames,
		toApplicationCategories,
		toApplications,
		toApplicationsForCategory,
		openFile,
		toCookieValues,
		toCookiesForHTTPHost,
		toDHCP,
		openFolder,
		toDestinationIPs,
		toSourceIPs,
		toHTTPHostsFiltered,
		toDstPorts,
		toIncomingFlowsFiltered,
		toFileTypes,
		toFiles,
		toFileType,
		toFilesForContentType,
		toGeolocation,
		toParameterValues,
		toParametersForHTTPHost,
		toHTTPContentTypes,
		toHTTPCookies,
		toHTTPHosts,
		toHTTPParameters,
		toHTTPServerNames,
		toHTTPStatusCodes,
		toURLsForHost,
		toHTTPUserAgents,
		toMailAuthTokens,
		toMailFrom,
		toMailTo,
		toMailUserPassword,
		toMailUsers,
		toMails,
		toSNIs,
		toSrcPorts,
		toOutgoingFlowsFiltered,
		toURLsForWebsite,
		openNetcapFolderInTerminal,
		openFilesFolder,
		openContentTypeFolder,
		toMD5HashesForFile,
		toLinksFromFile,
		toEmailsFromFile,
		toPhoneNumbersFromFile,
		toMD5HashesForImage,
		toExifDataForImage,
		toHostsForService,
		toServices,
	} {
		if os.Args[2] == getFuncName(f) {
			f()

			return
		}
	}

	trx := maltego.Transform{}
	trx.AddUIMessage("Unknown transform: "+os.Args[2], maltego.UIMessageFatal)
	fmt.Println(trx.ReturnOutput())
}

func getFuncName(f func()) string {
	return strings.TrimPrefix(filepath.Base(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()), "transform.")
}
