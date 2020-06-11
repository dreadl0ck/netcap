package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func ToLiveAuditRecords() {

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
	trx := maltego.MaltegoTransform{}
	for _, name := range allEncoders {

		ident := filepath.Join(outDir, name+".ncap")

		// stat generated profiles
		stat, err := os.Stat(ident)
		if err != nil {
			utils.DebugLog.Println("invalid path: ", err)
			continue
		}
		if stat.IsDir() {
			utils.DebugLog.Println("not a file: ", err)
			continue
		}

		// TODO: return structure from collect invocation
		// that contains the number of records per type
		// to avoid opening the file again
		numRecords := netcap.Count(ident)

		if numRecords == 0 {
			continue
		}

		ent := trx.AddEntity("netcap."+name+"AuditRecords", ident)
		ent.SetType("netcap." + name + "AuditRecords")

		displayName := name
		if strings.HasSuffix(name, "e") || strings.HasSuffix(name, "w") {
			if name != "Software" {
				displayName += "s"
			}
		}
		if strings.HasSuffix(name, "y") {
			displayName = name[:len(name)-1] + "ies"
		}
		if strings.HasSuffix(displayName, "t") {
			displayName += "s"
		}
		ent.SetValue(displayName)

		ent.AddProperty("path", "Path", "strict", ident)
		ent.AddProperty("description", "Description", "strict", name+".ncap.gz")

		ent.SetLinkLabel(strconv.Itoa(int(numRecords)))
		ent.SetLinkColor("#000000")

		// add notes for specific audit records here
		switch name {
		case "DeviceProfile":
			di := "<h3>Device Profile</h3><p>Timestamp: " + time.Now().UTC().String() + "</p>"
			ent.AddDisplayInformation(di, "Netcap Info")
			ent.SetNote("Storage Path: " + outDir + "\nFile Size: " + humanize.Bytes(uint64(stat.Size())) + "\nNum Profiles: " + strconv.FormatInt(netcap.Count(ident), 10) + "\nInterface: " + iface + "\nStart Time: " + start.String())
		}
	}

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}

var allEncoders = []string{
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
}
