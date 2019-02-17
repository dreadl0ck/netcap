package ja3

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// PacketSource means we can read Packets.
type PacketSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func openPcap(file string) (PacketSource, *os.File, error) {

	// get file handle
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	var (
		r       PacketSource
		errPcap error
	)

	// try to create pcap reader
	r, errPcap = pcapgo.NewReader(f)
	if errPcap != nil {

		// maybe its a PCAPNG
		// reopen file, otherwise offsets will be wrong
		err = f.Close()
		if err != nil {
			panic(err)
		}
		f, err = os.Open(file)
		if err != nil {
			panic(err)
		}

		// try to create pcapng reader
		var errPcapNg error
		r, errPcapNg = pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			// nope
			fmt.Println("pcap error:", errPcap)
			fmt.Println("pcap-ng error:", errPcapNg)
			panic("cannot open PCAP file")
		}
	}

	return r, f, err
}
