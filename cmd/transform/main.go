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
	case "GetDeviceProfilesWithDPI":
		ToAuditRecordsWithDPI()
	case "OpenNetcapFolder":
		OpenNetcapFolder()

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

	// File
	case "ToFileTypes":
		ToFileTypes()

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

	case "GetApplicationCategories":
		GetApplicationCategories()
	case "GetApplications":
		GetApplications()
	case "GetApplicationsForCategory":
		GetApplicationsForCategory()
	case "OpenFile":
		OpenFile()
	case "GetCookieValues":
		GetCookieValues()
	case "GetCookiesForHTTPHost":
		GetCookiesForHTTPHost()
	case "GetDHCP":
		GetDHCP()
	case "OpenFolder":
		OpenFolder()
	case "GetDNSQuestions":
		GetDNSQuestions()
	case "GetDeviceContacts":
		GetDeviceContacts()
	case "GetDeviceIPs":
		GetDeviceIPs()
	case "GetHTTPHostsFiltered":
		GetHTTPHostsFiltered()
	case "GetDstPorts":
		GetDstPorts()
	case "GetIncomingFlowsFiltered":
		GetIncomingFlowsFiltered()
	case "GetFileTypes":
		GetFileTypes()
	case "GetFiles":
		GetFiles()
	case "GetFileType":
		GetFileType()
	case "GetFilesForContentType":
		GetFilesForContentType()
	case "GetGeolocation":
		GetGeolocation()

	case "GetParameterValues":
		GetParameterValues()
	case "GetParametersForHTTPHost":
		GetParametersForHTTPHost()
	case "GetHTTPContentTypes":
		GetHTTPContentTypes()
	case "GetHTTPCookies":
		GetHTTPCookies()
	case "GetHTTPHosts":
		GetHTTPHosts()
	case "GetHTTPParameters":
		GetHTTPParameters()
	case "GetHTTPServerNames":
		GetHTTPServerNames()
	case "GetHTTPStatusCodes":
		GetHTTPStatusCodes()
	case "GetHTTPURLs":
		GetHTTPURLs()
	case "GetHTTPUserAgents":
		GetHTTPUserAgents()

	case "GetMailAuthTokens":
		GetMailAuthTokens()
	case "GetMailFrom":
		GetMailFrom()
	case "GetMailTo":
		GetMailTo()
	case "GetMailUserPassword":
		GetMailUserPassword()
	case "GetMailUsers":
		GetMailUsers()
	case "GetMails":
		GetMails()

	case "GetSNIs":
		GetSNIs()
	case "GetSrcPorts":
		GetSrcPorts()
	case "GetOutgoingFlowsFiltered":
		GetOutgoingFlowsFiltered()
	case "GetURLsForHTTPHost":
		GetURLsForHTTPHost()
	default:
		log.Fatal("unknown transform: ", os.Args[2])
	}
}
