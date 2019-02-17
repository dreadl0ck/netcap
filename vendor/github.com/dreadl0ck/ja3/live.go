package ja3

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ReadInterfaceCSV reads packets from the named interface
// and prints as CSV to the supplied io.Writer
func ReadInterfaceCSV(iface string, out io.Writer, separator string) {

	h, err := pcap.OpenLive(iface, 1024, true, -1)
	if err != nil {
		panic(err)
	}
	defer h.Close()

	columns := []string{"timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "ja3_digest"}
	out.Write([]byte(strings.Join(columns, separator) + "\n"))

	count := 0
	for {
		// read packet data
		data, ci, err := h.ReadPacketData()
		if err == io.EOF {
			if Debug {
				fmt.Println(count, "fingeprints.")
			}
			return
		} else if err != nil {
			panic(err)
		}

		var (
			// create gopacket
			p = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)
			// get JA3 if possible
			digest = DigestHexPacket(p)
		)

		// check if we got a result
		if digest != "" {

			count++

			var (
				b  strings.Builder
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			// got an a digest but no transport or network layer
			if tl == nil || nl == nil {
				if Debug {
					fmt.Println("got a nil layer: ", nl, tl, p.Dump(), digest)
				}
				continue
			}

			b.WriteString(timeToString(ci.Timestamp))
			b.WriteString(separator)
			b.WriteString(nl.NetworkFlow().Src().String())
			b.WriteString(separator)
			b.WriteString(tl.TransportFlow().Src().String())
			b.WriteString(separator)
			b.WriteString(nl.NetworkFlow().Dst().String())
			b.WriteString(separator)
			b.WriteString(tl.TransportFlow().Dst().String())
			b.WriteString(separator)
			b.WriteString(digest)
			b.WriteString("\n")

			_, err := out.Write([]byte(b.String()))
			if err != nil {
				panic(err)
			}
		}
	}
}
