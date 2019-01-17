package netcap

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/dreadl0ck/netcap/types"
	"github.com/evilsocket/islazy/tui"
	"github.com/gogo/protobuf/proto"
)

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

// uses reflection to return a list of all fields of a struct
// func allValues(in interface{}) []string {

// 	var (
// 		v      = reflect.ValueOf(in)
// 		values = make([]string, v.NumField())
// 	)

// 	for i := 0; i < v.NumField(); i++ {
// 		values[i] = fmt.Sprint(v.Field(i).Interface())
// 	}

// 	return values
// }
