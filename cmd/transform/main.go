package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
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

	case "ToDestinationIPs":
		ToDestinationIPs()
	case "ToSourceIPs":
		ToSourceIPs()
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
	case "ToURLsForHost":
		ToURLsForHost()
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

	case "ToServerNameIndicators":
		ToSNIs()
	case "ToSrcPorts":
		ToSrcPorts()
	case "ToOutgoingFlowsFiltered":
		ToOutgoingFlowsFiltered()
	case "ToURLsForWebsite":
		ToURLsForWebsite()
	default:
		trx := maltego.MaltegoTransform{}
		trx.AddUIMessage("Unknown transform: "+os.Args[2], maltego.UIM_FATAL)
		fmt.Println(trx.ReturnOutput())
		//log.Fatal("unknown transform: ", os.Args[2])
		return
	}
}
