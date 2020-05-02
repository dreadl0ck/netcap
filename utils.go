/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package netcap

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/mgutz/ansi"
	"github.com/namsral/flag"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"compress/gzip"

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

// PrintLogo prints the netcap logo
func FPrintLogo(w io.Writer) {
	fmt.Fprintln(w, logo)
}

// PrintBuildInfo displays build information related to netcap to stdout
func PrintBuildInfo() {
	FPrintBuildInfo(os.Stdout)
}

// PrintBuildInfo displays build information related to netcap to the specified io Writer
func FPrintBuildInfo(w io.Writer) {

	FPrintLogo(w)

	fmt.Fprintln(w, "\n> Date of execution:", time.Now().UTC())
	fmt.Fprintln(w, "> NETCAP build commit:", Commit)
	fmt.Fprintln(w, "> go runtime version:", runtime.Version())
	fmt.Fprintln(w, "> running with:", runtime.NumCPU(), "cores")

	b, ok := debug.ReadBuildInfo()
	if ok {
		for _, d := range b.Deps {
			if path.Base(d.Path) == "gopacket" {
				fmt.Fprintln(w, "> gopacket:", d.Path, "version:", d.Version)
			}
		}
	}
}

// DumpConfig contains all possible settings for dumping an audit records
type DumpConfig struct {
	Path          string
	Separator     string
	TabSeparated  bool
	Structured    bool
	Table         bool
	Selection     string
	UTC           bool
	Fields        bool
	JSON          bool
	MemBufferSize int
	CSV           bool
}

// Dump reads the specified netcap file
// and dumps the output according to the configuration to stdout
func Dump(c DumpConfig) {

	var (
		isTTY  = terminal.IsTerminal(int(os.Stdout.Fd()))
		count  = 0
		r, err = Open(c.Path, c.MemBufferSize)
	)
	if err != nil {
		log.Fatal("failed to open audit record file: ", err)
	}
	defer r.Close()

	if c.Separator == "\\t" || c.TabSeparated {
		c.Separator = "\t"
	}

	var (
		header = r.ReadHeader()
		record = InitRecord(header.Type)
		// rows for table print
		rows [][]string
		colorMap map[string]string
	)

	types.Select(record, c.Selection)
	types.UTC = c.UTC

	if !c.Structured && !c.Table && !c.JSON {

		if p, ok := record.(types.AuditRecord); ok {
			fmt.Println(strings.Join(p.CSVHeader(), c.Separator))
		} else {
			fmt.Printf("type: %#v\n", record)
			log.Fatal("type does not implement the types.AuditRecord interface")
		}

		if c.Fields {
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

		if p, ok := record.(types.AuditRecord); ok {

			// JSON
			if c.JSON {
				marshaled, err := json.MarshalIndent(p, "  ", " ")
				if err != nil {
					log.Fatal("failed to marshal json:", err)
				}
				os.Stdout.WriteString(string(marshaled))
				os.Stdout.WriteString("\n")
				continue
			}

			// Table View
			if c.Table {
				rows = append(rows, p.CSVRecord())

				if count%100 == 0 {
					tui.Table(os.Stdout, p.CSVHeader(), rows)
					rows = [][]string{}
				}
				continue
			}

			// CSV
			if c.CSV {
				os.Stdout.WriteString(strings.Join(p.CSVRecord(), c.Separator) + "\n")
				continue
			}

			// default: structured
			if isTTY {
				os.Stdout.WriteString(ansi.White)
				os.Stdout.WriteString(header.Type.String())
				os.Stdout.WriteString(ansi.Reset)
				os.Stdout.WriteString("\n")
				os.Stdout.WriteString(colorizeProto(proto.MarshalTextString(record), colorMap))
			} else {
				os.Stdout.WriteString(header.Type.String())
				os.Stdout.WriteString("\n")
				os.Stdout.WriteString(proto.MarshalTextString(record))
			}

			os.Stdout.WriteString("\n")
		} else {
			fmt.Printf("type: %#v\n", record)
			log.Fatal("type does not implement the types.AuditRecord interface")
		}
	}

	// in table mode: dump remaining
	if c.Table {
		if p, ok := record.(types.AuditRecord); ok {
			tui.Table(os.Stdout, p.CSVHeader(), rows)
			fmt.Println()
		} else {
			fmt.Printf("type: %#v\n", record)
			log.Fatal("type does not implement the types.AuditRecord interface")
		}
	}

	// avoid breaking JSON parsers by appending number of records
	if !c.JSON {
		fmt.Println(count, "records.")
	}
}

// CloseFile closes the netcap file handle
// and removes files that do only contain a header but no audit records
func CloseFile(outDir string, file *os.File, typ string) (name string, size int64) {

	i, err := file.Stat()
	if err != nil {
		fmt.Println("[ERROR] failed to stat file:", err, "type", typ)
		return "", 0
	}

	var (
		errSync  = file.Sync()
		errClose = file.Close()
	)
	if errSync != nil || errClose != nil {
		fmt.Println("error while closing", i.Name(), "errSync", errSync, "errClose", errClose)
	}

	return i.Name(), RemoveAuditRecordFileIfEmpty(filepath.Join(outDir, i.Name()))
}

// CreateFile is a wrapper to create new audit record file
func CreateFile(name, ext string) *os.File {
	f, err := os.Create(name + ext)
	if err != nil {
		panic(err)
	}
	return f
}

// RemoveAuditRecordFileIfEmpty removes the audit record file if it does not contain audit records
func RemoveAuditRecordFileIfEmpty(name string) (size int64) {

	if strings.HasSuffix(name, ".csv") || strings.HasSuffix(name, ".csv.gz") {
		f, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		var r *bufio.Reader
		if strings.HasSuffix(name, ".csv.gz") {
			gr, err := gzip.NewReader(f)
			if err != nil {
				panic(err)
			}
			r = bufio.NewReader(gr)
		} else {
			r = bufio.NewReader(f)
		}

		count := 0
		for {
			_, _, err := r.ReadLine()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}
			count++
			if count > 1 {
				break
			}
		}

		if count < 2 {
			// remove file
			err = os.Remove(name)
			if err != nil {
				fmt.Println("failed to remove file", err)
			}

			// return file size of zero
			return 0
		}

		// dont remove file
		// return final file size
		s, err := os.Stat(name)
		if err != nil {
			fmt.Println("failed to stat file:", name, err)
			return
		}
		return s.Size()
	}

	// Check if audit record file contains records
	// Open, read header and the first audit record and return
	r, err := Open(name, DefaultBufferSize)
	if err != nil {

		// suppress errors for OSPF because the file handle will be closed twice
		// since both v2 and v3 have the same gopacket.LayerType == "OSPF"
		if !strings.HasPrefix(name, "OSPF") {
			fmt.Println("unable to open file:", name, "error", err)
		}
		return 0
	}
	defer r.Close()

	var (
		header = r.ReadHeader()
		record = InitRecord(header.Type)
	)

	err = r.Next(record)
	if err != nil {
		// remove file
		err = os.Remove(name)
		if err != nil {
			fmt.Println("failed to remove file", err)

			// return file size of zero
			return 0
		}
		return
	}

	// dont remove file, it contains audit records
	// return final file size
	s, err := os.Stat(name)
	if err != nil {
		fmt.Println("failed to stat file:", name, err)
		return
	}
	return s.Size()
}

// NewHeader creates and returns a new netcap audit file header
func NewHeader(t types.Type, source, version string, includesPayloads bool) *types.Header {

	// init header
	header := new(types.Header)
	header.Type = t
	header.Created = utils.TimeToString(time.Now())
	header.InputSource = source
	header.Version = version
	header.ContainsPayloads = includesPayloads

	return header
}

func GenerateConfig(fs *flag.FlagSet, tool string) {
	fmt.Println("# NETCAP config for " + tool + " tool")
	fmt.Println("# Generated by NETCAP " + Version)
	fmt.Println()
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name != "gen-config" {
			fmt.Println("#", f.Usage)
			fmt.Println(f.Name, f.DefValue)
			fmt.Println()
		}
	})
	os.Exit(0)
}


var (
	colors = []string{ansi.Yellow,ansi.Blue,ansi.Green,ansi.Cyan,ansi.Magenta,ansi.Red,ansi.LightBlue,ansi.LightRed,ansi.LightGreen,ansi.LightYellow,ansi.LightCyan}
	numColors = len(colors)
	max int
)

func colorizeProto(in string, colorMap map[string]string) string {

	var (
		b     strings.Builder
		index int
	)

	if colorMap == nil {
		colorMap = make(map[string]string)

		for i, line := range strings.Split(in, "\n") {
			if len(line) == 0 {
				continue
			}
			if line == "\n" {
				b.WriteString("\n")
				continue
			}

			if i >= numColors {
				index = i % numColors
			} else {
				index = i
			}

			parts := strings.Split(line, ":")

			length := len(parts[0])
			if length > max {
				max = length
			}

			colorMap[parts[0]] = colors[index]
		}
	}

	for i, line := range strings.Split(in, "\n") {

		if len(line) == 0 {
			continue
		}
		if line == "\n" {
			b.WriteString("\n")
			continue
		}

		if i >= numColors {
			index = i % numColors
		} else {
			index = i
		}

		parts := strings.Split(line, ":")
		if len(parts) > 1 {
			b.WriteString(colorMap[parts[0]])
			if strings.Contains(line, "<") {
				b.WriteString(utils.Pad(parts[0], max-1))
			} else {
				b.WriteString(utils.Pad(parts[0], max))
			}
			b.WriteString(ansi.Reset)
			if !strings.Contains(line, "<") {
				b.WriteString(":")
			}
			b.WriteString(strings.Join(parts[1:], ":"))
			b.WriteString("\n")
		} else {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}