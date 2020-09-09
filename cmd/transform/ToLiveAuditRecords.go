package transform

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/utils"
)

func toLiveAuditRecords() {
	var (
		lt    = maltego.ParseLocalArguments(os.Args[1:])
		path  = lt.Values["path"]
		iface = lt.Values["iface"]
	)

	log.Println("path:", path)
	writeLiveAuditRecords(path, iface, time.Now())
}

func writeLiveAuditRecords(outDir string, iface string, start time.Time) {
	// generate maltego transform
	trx := maltego.Transform{}
	for _, name := range allDecoders {
		path := filepath.Join(outDir, name+defaults.FileExtension)

		// stat generated profiles
		stat, err := os.Stat(path)
		if err != nil {
			log.Println("invalid path: ", err)

			continue
		}
		if stat.IsDir() {
			log.Println("not a file: ", err)

			continue
		}

		// TODO: return structure from collect invocation
		// that contains the number of records per type
		// to avoid opening the file again
		numRecords, errCount := io.Count(path)
		if errCount != nil {
			log.Println("failed to count audit records:", errCount)

			continue
		}

		if numRecords == 0 {
			log.Println("no records in", path)
			continue
		}

		ent := trx.AddEntityWithPath("netcap."+name+"AuditRecords", utils.Pluralize(name), path)

		ent.AddProperty("description", "Description", "strict", name+defaults.FileExtension)

		ent.SetLinkLabel(strconv.Itoa(int(numRecords)))

		// add notes for specific audit records here
		switch name {
		//case "DeviceProfile":
		//	di := "<h3>Device Profile</h3><p>Timestamp: " + time.Now().UTC().String() + "</p>"
		//	ent.AddDisplayInformation(di, "Netcap Info")
		//
		//	num, errCountRecords := io.Count(path)
		//	if errCountRecords != nil {
		//		log.Println("failed to count audit records:", errCountRecords)
		//	}
		//
		//	ent.SetNote("Storage Path: " + outDir + "\nFile Size: " + humanize.Bytes(uint64(stat.Size())) + "\nNum Profiles: " + strconv.FormatInt(num, 10) + "\nInterface: " + iface + "\nStart Time: " + start.String())
		}
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

// TODO: this should be generated not hardcoded!
var allDecoders = []string{
	"TLSClientHello",
	"TLSServerHello",
	"HTTP",
	"Flow",
	"Connection",
	"DeviceProfile",
	"File",
	"POP3",
	"Software",
	"Service",
	"Credentials",
	"SSH",
	"Vulnerability",
	"Exploit",
	"TCP",
	"UDP",
	"IPv4",
	"IPv6",
	"DHCPv4",
	"DHCPv6",
	"ICMPv4",
	"ICMPv6",
	"ICMPv6Echo",
	"ICMPv6NeighborSolicitation",
	"ICMPv6RouterSolicitation",
	"DNS",
	"ARP",
	"Ethernet",
	"Dot1Q",
	"Dot11",
	"NTP",
	"SIP",
	"IGMP",
	"LLC",
	"IPv6HopByHop",
	"SCTP",
	"SNAP",
	"LinkLayerDiscovery",
	"ICMPv6NeighborAdvertisement",
	"ICMPv6RouterAdvertisement",
	"EthernetCTP",
	"EthernetCTPReply",
	"LinkLayerDiscoveryInfo",
	"IPSecAH",
	"IPSecESP",
	"Geneve",
	"IPv6Fragment",
	"VXLAN",
	"USB",
	"LCM",
	"MPLS",
	"Modbus",
	"OSPF",
	"OSPF",
	"BFD",
	"GRE",
	"FDDI",
	"EAP",
	"VRRP",
	"EAPOL",
	"EAPOLKey",
	"CiscoDiscovery",
	"CiscoDiscoveryInfo",
	"USBRequestBlockSetup",
	"NortelDiscovery",
	"CIP",
	"EthernetIP",
	"SMTP",
	"Diameter",
	"IPProfile",
}
