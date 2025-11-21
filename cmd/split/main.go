package split

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/dustin/go-humanize"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/collector"
)

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Create a new CLI app just for parsing flags
	cmd := &cli.Command{
		Name:  "split",
		Usage: "split pcap files",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the split command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	flagInput := c.String("read")

	// stat input file
	stat, err := os.Stat(flagInput)
	if err != nil {
		log.Fatal("failed to open pcap:", err)
	}

	// file exists.
	println("opening", flagInput+" | size:", humanize.Bytes(uint64(stat.Size())))

	// TODO: display progress
	// display total packet count
	//print("counting packets...")
	//start := time.Now()
	//c.numPackets, err = countPackets(path)
	//if err != nil {
	//	return err
	//}
	//clearLine()
	//fmt.Println("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := collector.OpenPCAP(flagInput)
	if err != nil {
		log.Fatal("failed to open pcap:", err)
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	fmt.Println("detected link type:", r.LinkType())

	var (
		data []byte
		ci   gopacket.CaptureInfo
	)

	print("processing packets... ")

	for {
		// fetch the next packetdata and packetheader
		// for pcap, currently ZeroCopyReadPacketData() is not supported
		data, ci, err = r.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			log.Fatal("reading pcaps failed: ", err)
		}

		// TODO: parse timestamp from ci
		//  create a directory for each day
		//  and write the corresponding packets there
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Lazy)
		fmt.Println(p, ci)

		// If using pool mode, dispose of the packet to return it to the pool
		if pooledPkt, ok := p.(gopacket.PooledPacket); ok {
			pooledPkt.Dispose()
		}
	}

	return nil
}
