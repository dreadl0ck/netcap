package dump

import (
	"fmt"

	"github.com/dreadl0ck/netcap/io"
)

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("dump tool usage examples:")
	fmt.Println("	$ net dump -read TCP.ncap.gz")
	fmt.Println("	$ net dump -fields -read TCP.ncap.gz")
	fmt.Println("	$ net dump -read TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv")
	fmt.Println()
}

// usage prints the use.
func printUsage() {
	printHeader()
	fs.PrintDefaults()
}
