package main

import (
	"flag"
	"fmt"
	"github.com/dreadl0ck/netcap"
	"log"
	"os"
)

var (
	flagVersion = flag.Bool("version", false, "print version and exit")
)

func main() {

	flag.Parse()

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		log.Fatal("expecting transform name")
	}

	log.Println(os.Args)
	switch os.Args[1] {
		case "GetApplicationCategories":
			GetApplicationCategories()
		case "GetApplications":
			GetApplications()
		case "GetApplicationsForCategory":
			GetApplicationsForCategory()
		case "GetCookieValues":
			GetCookieValues()
		case "GetCookiesForHTTPHost":
			GetCookiesForHTTPHost()
		case "GetDHCP":
			GetDHCP()
		case "GetDNSQuestions":
			GetDNSQuestions()
		case "GetDeviceContacts":
			GetDeviceContacts()
		case "GetDeviceIPs":
			GetDeviceIPs()
		case "GetDeviceProfiles":
			GetDeviceProfiles()
		case "GetHTTPHostsFiltered":
			GetHTTPHostsFiltered()
		case "GetDevices":
			GetDevices()
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
		case "GetParameterValues":
			GetParameterValues()
		case "GetParametersForHTTPHost":
			GetParametersForHTTPHost()
		case "GetSNIs":
			GetSNIs()
		case "GetSrcPorts":
			GetSrcPorts()
		case "GetOutgoingFlowsFiltered":
			GetOutgoingFlowsFiltered()
		case "GetURLsForHTTPHost":
				GetURLsForHTTPHost()
	}
}
