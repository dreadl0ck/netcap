package transform

import (
	"fmt"
	"log"
	"os"

	"github.com/dreadl0ck/netcap/maltego"
)

var outDirPermission os.FileMode = 0o755

func Run() {
	if len(os.Args) < 3 {
		log.Fatal("expecting transform name")
	}

	log.Println("os.Args:", os.Args)
	switch os.Args[2] {

	// core
	case "toCaptureProcess":
		toCaptureProcess()
	case "stopCaptureProcess":
		stopCaptureProcess()
	case "toAuditRecords":
		toAuditRecords()
	case "toLiveAuditRecords":
		toLiveAuditRecords()
	case "ToDeviceProfilesWithDPI":
		toAuditRecordsWithDPI()
	case "openNetcapFolder":
		openNetcapFolder()

	case "toFileTypesForIP":
		toFileTypesForIP()

	// Exploits
	case "toSoftwareExploits":
		toSoftwareExploits()
	case "openExploit":
		openExploit()

	// DHCP
	case "toDHCPClients":
		toDHCPClients()
	case "lookupDHCPFingerprint":
		lookupDHCPFingerprint()

	// SSH
	case "toSSHClients":
		toSSHClients()
	case "toSSHServers":
		toSSHServers()

	// Software
	case "toProducts":
		toProducts()

	// Credentials
	case "toCredentialsByService":
		toCredentialsByService()
	case "toLoginInformation":
		toLoginInformation()

	// POP3
	case "toFetchedMails":
		toFetchedMails()

	// HTTP
	case "toHTTPHostNames":
		toHTTPHostNames()

	// Vulnerabilities
	case "toSoftwareVulnerabilities":
		toSoftwareVulnerabilities()
	case "openVulnerability":
		openVulnerability()

	// DNS
	case "toDNSQuestions":
		toDNSQuestions()

	// Flow
	case "toIANAServices":
		toIANAServices()
	// case "ToHighestVolumeFlows":
	// ToHighestVolumeFlows()

	// DeviceProfile
	case "toDevices":
		toDevices()

	case "ToHTTPHostnames":
		toHTTPHostNames()

	case "toApplicationCategories":
		toApplicationCategories()
	case "toApplications":
		toApplications()
	case "toApplicationsForCategory":
		toApplicationsForCategory()
	case "openFile":
		openFile()
	case "toCookieValues":
		toCookieValues()
	case "toCookiesForHTTPHost":
		toCookiesForHTTPHost()
	case "toDHCP":
		toDHCP()
	case "openFolder":
		openFolder()

	case "toDestinationIPs":
		toDestinationIPs()
	case "toSourceIPs":
		toSourceIPs()
	case "toHTTPHostsFiltered":
		toHTTPHostsFiltered()
	case "toDstPorts":
		toDstPorts()
	case "toIncomingFlowsFiltered":
		toIncomingFlowsFiltered()
	case "toFileTypes":
		toFileTypes()
	case "toFiles":
		toFiles()
	case "toFileType":
		toFileType()
	case "toFilesForContentType":
		toFilesForContentType()
	case "toGeolocation":
		toGeolocation()

	case "toParameterValues":
		toParameterValues()
	case "toParametersForHTTPHost":
		toParametersForHTTPHost()
	case "toHTTPContentTypes":
		toHTTPContentTypes()
	case "toHTTPCookies":
		toHTTPCookies()
	case "toHTTPHosts":
		toHTTPHosts()
	case "toHTTPParameters":
		toHTTPParameters()
	case "toHTTPServerNames":
		toHTTPServerNames()
	case "toHTTPStatusCodes":
		toHTTPStatusCodes()
	case "toURLsForHost":
		toURLsForHost()
	case "toHTTPUserAgents":
		toHTTPUserAgents()

	case "toMailAuthTokens":
		toMailAuthTokens()
	case "toMailFrom":
		toMailFrom()
	case "toMailTo":
		toMailTo()
	case "toMailUserPassword":
		toMailUserPassword()
	case "toMailUsers":
		toMailUsers()
	case "toMails":
		toMails()

	case "ToServerNameIndicators":
		toSNIs()
	case "toSrcPorts":
		toSrcPorts()
	case "toOutgoingFlowsFiltered":
		toOutgoingFlowsFiltered()
	case "toURLsForWebsite":
		toURLsForWebsite()
	case "openNetcapFolderInTerminal":
		openNetcapFolderInTerminal()
	case "openFilesFolder":
		openFilesFolder()
	case "openContentTypeFolder":
		openContentTypeFolder()

	case "toMD5HashesForFile":
		toMD5HashesForFile()

	case "toLinksFromFile":
		toLinksFromFile()
	case "toEmailsFromFile":
		toEmailsFromFile()
	case "toPhoneNumbersFromFile":
		toPhoneNumbersFromFile()
	case "toMD5HashesForImage":
		toMD5HashesForImage()

	case "toExifDataForImage":
		toExifDataForImage()
	case "toHostsForService":
		toHostsForService()
	case "toServices":
		toServices()

	default:
		trx := maltego.Transform{}
		trx.AddUIMessage("Unknown transform: "+os.Args[2], maltego.UIM_FATAL)
		fmt.Println(trx.ReturnOutput())
		// log.Fatal("unknown transform: ", os.Args[2])
		return
	}
}
