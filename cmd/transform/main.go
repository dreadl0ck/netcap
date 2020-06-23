package transform

import (
	"log"
	"os"
)

var (
	outDirPermission os.FileMode = 0755
)

func Run() {

	if len(os.Args) < 3 {
		log.Fatal("expecting transform name")
	}

	log.Println("os.Args:", os.Args)
	switch os.Args[2] {

	// core
	case "ToCaptureProcess":
		ToCaptureProcess()
	case "StopCaptureProcess":
		StopCaptureProcess()
	case "ToAuditRecords":
		ToAuditRecords()
	case "ToLiveAuditRecords":
		ToLiveAuditRecords()
	case "ToDeviceProfilesWithDPI":
		ToAuditRecordsWithDPI()
	case "OpenNetcapFolder":
		OpenNetcapFolder()

	case "ToFileTypesForIP":
		ToFileTypesForIP()

	// Exploits
	case "ToSoftwareExploits":
		ToSoftwareExploits()
	case "OpenExploit":
		OpenExploit()

	// DHCP
	case "ToDHCPClients":
		ToDHCPClients()
	case "LookupDHCPFingerprint":
		LookupDHCPFingerprint()

	// SSH
	case "ToSSHClients":
		ToSSHClients()
	case "ToSSHServers":
		ToSSHServers()

	// Software
	case "ToProducts":
		ToProducts()

	// Service
	case "ToUDPServices":
		ToUDPServices()
	case "ToTCPServices":
		ToTCPServices()

	// Credentials
	case "ToCredentialsByService":
		ToCredentialsByService()
	case "ToLoginInformation":
		ToLoginInformation()

	// POP3
	case "ToFetchedMails":
		ToFetchedMails()

	// HTTP
	case "ToHTTPHostNames":
		ToHTTPHostNames()

	// Vulnerabilities
	case "ToSoftwareVulnerabilities":
		ToSoftwareVulnerabilities()
	case "OpenVulnerability":
		OpenVulnerability()

	// DNS
	case "ToDNSQuestions":
		ToDNSQuestions()

	// Flow
	case "ToIANAServices":
		ToIANAServices()
	//case "ToHighestVolumeFlows":
	//ToHighestVolumeFlows()

	// DeviceProfile
	case "ToDevices":
		ToDevices()

	case "ToHTTPHostnames":
		ToHTTPHostNames()

	case "ToApplicationCategories":
		ToApplicationCategories()
	case "ToApplications":
		ToApplications()
	case "ToApplicationsForCategory":
		ToApplicationsForCategory()
	case "OpenFile":
		OpenFile()
	case "ToCookieValues":
		ToCookieValues()
	case "ToCookiesForHTTPHost":
		ToCookiesForHTTPHost()
	case "ToDHCP":
		ToDHCP()
	case "OpenFolder":
		OpenFolder()

	case "ToDeviceContacts":
		ToDeviceContacts()
	case "ToDeviceIPs":
		ToDeviceIPs()
	case "ToHTTPHostsFiltered":
		ToHTTPHostsFiltered()
	case "ToDstPorts":
		ToDstPorts()
	case "ToIncomingFlowsFiltered":
		ToIncomingFlowsFiltered()
	case "ToFileTypes":
		ToFileTypes()
	case "ToFiles":
		ToFiles()
	case "ToFileType":
		ToFileType()
	case "ToFilesForContentType":
		ToFilesForContentType()
	case "ToGeolocation":
		ToGeolocation()

	case "ToParameterValues":
		ToParameterValues()
	case "ToParametersForHTTPHost":
		ToParametersForHTTPHost()
	case "ToHTTPContentTypes":
		ToHTTPContentTypes()
	case "ToHTTPCookies":
		ToHTTPCookies()
	case "ToHTTPHosts":
		ToHTTPHosts()
	case "ToHTTPParameters":
		ToHTTPParameters()
	case "ToHTTPServerNames":
		ToHTTPServerNames()
	case "ToHTTPStatusCodes":
		ToHTTPStatusCodes()
	case "ToHTTPURLs":
		ToHTTPURLs()
	case "ToHTTPUserAgents":
		ToHTTPUserAgents()

	case "ToMailAuthTokens":
		ToMailAuthTokens()
	case "ToMailFrom":
		ToMailFrom()
	case "ToMailTo":
		ToMailTo()
	case "ToMailUserPassword":
		ToMailUserPassword()
	case "ToMailUsers":
		ToMailUsers()
	case "ToMails":
		ToMails()

	case "ToSNIs":
		ToSNIs()
	case "ToSrcPorts":
		ToSrcPorts()
	case "ToOutgoingFlowsFiltered":
		ToOutgoingFlowsFiltered()
	case "ToURLsForHTTPHost":
		ToURLsForHTTPHost()
	default:
		log.Fatal("unknown transform: ", os.Args[2])
	}
}
