package webui

import (
	"fmt"

	"github.com/gopacket/gopacket/pcap"
)

func liveInterfaces() ([]NetworkInterfaceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("list capture devices (Npcap is required): %w", err)
	}
	results := make([]NetworkInterfaceInfo, 0, len(devices))
	for _, dev := range devices {
		nic := NetworkInterfaceInfo{Name: dev.Name, Description: dev.Description}
		for _, addr := range dev.Addresses {
			if addr.IP != nil {
				nic.Addrs = append(nic.Addrs, addr.IP.String())
			}
		}
		results = append(results, nic)
	}
	return results, nil
}
