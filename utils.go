package netcap

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"
	"github.com/gogo/protobuf/proto"
)

var logo = `                       / |
 _______    ______   _10 |_     _______   ______    ______
/     / \  /    / \ / 01/  |   /     / | /    / \  /    / \
0010100 /|/011010 /|101010/   /0101010/  001010  |/100110  |
01 |  00 |00    00 |  10 | __ 00 |       /    10 |00 |  01 |
10 |  01 |01001010/   00 |/  |01 \_____ /0101000 |00 |__10/|
10 |  00 |00/    / |  10  00/ 00/    / |00    00 |00/   00/
00/   10/  0101000/    0010/   0010010/  0010100/ 1010100/
                                                  00 |
Network Protocol Analysis Framework               00 |
created by Philipp Mieden, 2018                   00/
` + Version

// PrintLogo prints the netcap logo
func PrintLogo() {
	utils.ClearScreen()
	fmt.Println(logo)
}

// Dump reads the specified netcap file
// and dumps the output according to the configuration to stdout
func Dump(path string, separator string, tsv bool, structured bool, table bool, selection string, utc bool, fields bool) {

	var (
		count  = 0
		r, err = Open(path)
	)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	if separator == "\\t" || tsv {
		separator = "\t"
	}

	var (
		header = r.ReadHeader()
		record = InitRecord(header.Type)
		// rows for table print
		rows [][]string
	)

	types.Select(record, selection)
	types.UTC = utc

	if !structured && !table {

		if p, ok := record.(types.CSV); ok {
			fmt.Println(strings.Join(p.CSVHeader(), separator))
		} else {
			log.Fatal("netcap type does not implement the types.CSV interface!")
		}

		if fields {
			os.Exit(0)
		}
	}

	for {
		err := r.Next(record)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}
		count++

		if structured {
			os.Stdout.WriteString(header.Type.String() + "\n")
			os.Stdout.WriteString(proto.MarshalTextString(record) + "\n")
			continue
		}

		if p, ok := record.(types.CSV); ok {
			if table {
				rows = append(rows, p.CSVRecord())

				if count%100 == 0 {
					tui.Table(os.Stdout, p.CSVHeader(), rows)
					rows = [][]string{}
				}
				continue
			}
			os.Stdout.WriteString(strings.Join(p.CSVRecord(), separator) + "\n")
		} else {
			log.Fatal("netcap type does not implement the types.CSV interface!")
		}

	}

	if table {
		if p, ok := record.(types.CSV); ok {
			tui.Table(os.Stdout, p.CSVHeader(), rows)
			fmt.Println()
		} else {
			log.Fatal("netcap type does not implement the types.CSV interface!")
		}
	}

	fmt.Println(count, "records.")
}
