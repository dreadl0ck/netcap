package main

import (
	"flag"
	"fmt"
	"github.com/dreadl0ck/gopacket/pcap"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	flagVersion = flag.Bool("version", false, "print version and exit")
)

func main() {

	var (
		lt = maltego.ParseLocalArguments(os.Args)
		inputFile = lt.Values["path"]
	)

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	// redirect stdout filedescriptor to stderr
	// since all stdout get interpreted as XML from maltego
	stdout := os.Stdout
	os.Stdout = os.Stderr

	// create storage path for audit records
	start := time.Now()
	baseDir := strings.TrimSuffix(inputFile, ".pcap")

	// TODO: error ignored, files will be overwritten if there are any
	os.MkdirAll(baseDir, 0700)

	// init collector
	c := collector.New(collector.Config{
		Live:                false,
		Workers:             1000,
		PacketBufferSize:    100,
		WriteUnknownPackets: false,
		Promisc:             false,
		SnapLen:             1514,
		FileStorage: 		 filepath.Join(baseDir, "files"),
		EncoderConfig: encoder.Config{
			Buffer:          true,
			Compression:     true,
			CSV:             false,
			IncludeEncoders: "DeviceProfile,File,HTTP,DNS",
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
		Quiet: false,
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

	// open PCAP file
	r, err := pcap.OpenOffline(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	ident := filepath.Join(baseDir, "DeviceProfile.ncap.gz")

	// stat generated profiles
	stat, err := os.Stat(ident)
	if err != nil {
		log.Fatal("invalid path: ", err)
	}

	// restore stdout
	os.Stdout = stdout

	// generate maltego transform
	trx := maltego.MaltegoTransform{}
	ent := trx.AddEntity("netcap.DeviceProfiles", ident)
	ent.SetType("netcap.DeviceProfiles")
	ent.SetValue("DeviceProfile.ncap.gz")

	di := "<h3>Device Profile</h3><p>Timestamp: " + time.Now().UTC().String() + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.AddProperty("path", "Path", "strict", ident)
	ent.AddProperty("description", "Description", "strict", "DeviceProfile.ncap.gz")

	ent.SetLinkLabel("DeviceProfiles")
	ent.SetLinkColor("#000000")
	ent.SetNote("Storage Path: " + baseDir + "\nFile Size: " +  humanize.Bytes(uint64(stat.Size())) + "\nNum Profiles: " + strconv.FormatInt(netcap.Count(ident), 10) + "\nSource File: " + inputFile + "\nLink Type: " + r.LinkType().String() + "\nParsing Time: " + time.Since(start).String())

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}