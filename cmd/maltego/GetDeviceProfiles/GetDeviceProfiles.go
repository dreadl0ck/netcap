package main

import (
	"flag"
	"fmt"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/utils"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	flagVersion = flag.Bool("version", false, "print version and exit")
)

func main() {

	lt := maltego.ParseLocalArguments(os.Args)
	//inputFile := lt.Value
	inputFile := lt.Values["path"]

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	baseDir := strings.TrimSuffix(inputFile, ".pcap")
	os.MkdirAll(baseDir, 0700)

	stdout := os.Stdout
	os.Stdout = os.Stderr

	// init collector
	c := collector.New(collector.Config{
		Live:                false,
		Workers:             1000,
		PacketBufferSize:    100,
		WriteUnknownPackets: false,
		Promisc:             false,
		SnapLen:             1514,
		EncoderConfig: encoder.Config{
			Buffer:          true,
			Compression:     true,
			CSV:             false,
			IncludeEncoders: "DeviceProfile",
			ExcludeEncoders: "",
			Out:             baseDir,
			Source:          inputFile,
			Version:         netcap.Version,
			IncludePayloads: false,
			Export:          false,
			AddContext:      true,
			MemBufferSize:   netcap.DefaultBufferSize,
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("lazy"),
	})

	// if not, use native pcapgo version
	isPcap, err := collector.IsPcap(inputFile)
	if err != nil {
		// invalid path
		fmt.Println("failed to open file:", err)
		os.Exit(1)
	}

	// logic is split for both types here
	// because the pcapng reader offers ZeroCopyReadPacketData()
	if isPcap {
		if err := c.CollectPcap(inputFile); err != nil {
			log.Fatal("failed to collect audit records from pcap file: ", err)
		}
	} else {
		if err := c.CollectPcapNG(inputFile); err != nil {
			log.Fatal("failed to collect audit records from pcapng file: ", err)
		}
	}

	os.Stdout = stdout

	TRX := maltego.MaltegoTransform{}

	ident := filepath.Join(baseDir, "DeviceProfile.ncap.gz")

	NewEnt := TRX.AddEntity("netcap.DeviceProfiles", ident)
	NewEnt.SetType("netcap.DeviceProfiles")
	NewEnt.SetValue("DeviceProfile.ncap.gz")

	di := "<h3>Heading</h3><p>Timestamp: " + time.Now().UTC().String() + "</p>"
	NewEnt.AddDisplayInformation(di, "Other")

	NewEnt.AddProperty("path", "Path", "strict", ident)
	NewEnt.AddProperty("description", "Description", "strict", "DeviceProfile.ncap.gz")

	NewEnt.SetLinkLabel("GetDeviceProfiles") // TODO: add num profiles here?
	NewEnt.SetLinkColor("#000000")
	NewEnt.SetNote(ident)

	TRX.AddUIMessage("completed!","Inform")
	fmt.Println(TRX.ReturnOutput())
}