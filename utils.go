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
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/evilsocket/islazy/tui"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"
	"github.com/namsral/flag"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
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

// PrintLogo prints the netcap logo.
func PrintLogo() {
	utils.ClearScreen()
	fmt.Println(logo)
}

// FPrintLogo PrintLogo prints the netcap logo.
func FPrintLogo(w io.Writer) {
	fmt.Fprintln(w, logo)
}

// PrintBuildInfo displays build information related to netcap to stdout.
func PrintBuildInfo() {
	FPrintLogo(os.Stdout)
	FPrintBuildInfo(os.Stdout)
}

// FPrintBuildInfo PrintBuildInfo displays build information related to netcap to the specified io Writer.
func FPrintBuildInfo(w io.Writer) {
	fmt.Fprintln(w, "\n> Date of execution:", time.Now().UTC())
	fmt.Fprintln(w, "> NETCAP build commit:", commit)
	fmt.Fprintln(w, "> go runtime version:", runtime.Version())
	fmt.Fprintln(w, "> number of cores:", runtime.NumCPU(), "cores")

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
// this structure has an optimized field order to avoid excessive padding.
type DumpConfig struct {
	Path          string
	Separator     string
	Selection     string
	MemBufferSize int
	JSON          bool
	Table         bool
	UTC           bool
	Fields        bool
	TabSeparated  bool
	Structured    bool
	CSV           bool
	ForceColors   bool
}

// Dump reads the specified netcap file
// and dumps the output according to the configuration to the specified *io.File.
func Dump(w *os.File, c DumpConfig) error {
	var (
		isTTY  = terminal.IsTerminal(int(w.Fd())) || c.ForceColors
		count  = 0
		r, err = Open(c.Path, c.MemBufferSize)
	)
	if err != nil {
		return fmt.Errorf("failed to open audit record file: %s", err)
	}
	defer r.Close()

	if c.Separator == "\\t" || c.TabSeparated {
		c.Separator = "\t"
	}

	var (
		header, errFileHeader = r.ReadHeader()
		record                = InitRecord(header.Type)
		// rows for table print
		rows     [][]string
		colorMap map[string]string
	)
	if errFileHeader != nil {
		return errFileHeader
	}

	types.Select(record, c.Selection)
	types.UTC = c.UTC

	if !c.Structured && !c.Table && !c.JSON {
		if p, ok := record.(types.AuditRecord); ok {
			w.WriteString(strings.Join(p.CSVHeader(), c.Separator))
		} else {
			return fmt.Errorf("type does not implement the types.AuditRecord interface: %#v", record)
		}

		if c.Fields {
			os.Exit(0)
		}
	}

	for {
		err = r.Next(record)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read next audit record: %s", err)
		}
		count++

		if p, ok := record.(types.AuditRecord); ok {

			// JSON
			if c.JSON {
				marshaled, errMarshal := json.Marshal(p)
				if errMarshal != nil {
					return fmt.Errorf("failed to marshal json: %s", errMarshal)
				}

				w.WriteString(string(marshaled))
				w.WriteString("\n")

				continue
			}

			// Table View
			if c.Table {
				rows = append(rows, p.CSVRecord())

				if count%100 == 0 {
					tui.Table(w, p.CSVHeader(), rows)
					rows = [][]string{}
				}
				continue
			}

			// CSV
			if c.CSV {
				w.WriteString(strings.Join(p.CSVRecord(), c.Separator) + "\n")
				continue
			}

			// default: if TTY, dump structured with colors
			if isTTY {
				w.WriteString(ansi.White)
				w.WriteString(header.Type.String())
				w.WriteString(ansi.Reset)
				w.WriteString("\n")
				w.WriteString(colorizeProto(proto.MarshalTextString(record), colorMap))
			} else { // structured without colors
				w.WriteString(header.Type.String())
				w.WriteString("\n")
				w.WriteString(proto.MarshalTextString(record))
			}

			w.WriteString("\n")
		} else {
			return fmt.Errorf("type does not implement the types.AuditRecord interface: %#v", record)
		}
	}

	// in table mode: dump remaining
	if c.Table {
		if p, ok := record.(types.AuditRecord); ok {
			tui.Table(w, p.CSVHeader(), rows)
			fmt.Println()
		} else {
			return fmt.Errorf("type does not implement the types.AuditRecord interface: %#v", record)
		}
	}

	// avoid breaking JSON parsers by appending number of records
	if !c.JSON {
		w.WriteString(strconv.Itoa(count) + " records.")
	}

	return nil
}

// CloseFile closes the netcap file handle
// and removes files that do only contain a header but no audit records.
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

// CreateFile is a wrapper to create new audit record file.
func CreateFile(name, ext string) *os.File {
	f, err := os.Create(name + ext)
	if err != nil {
		panic(err)
	}
	return f
}

// RemoveAuditRecordFileIfEmpty removes the audit record file if it does not contain audit records.
func RemoveAuditRecordFileIfEmpty(name string) (size int64) {
	if strings.HasSuffix(name, ".csv") || strings.HasSuffix(name, ".csv.gz") {
		f, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		var r *bufio.Reader
		if strings.HasSuffix(name, ".csv.gz") {
			var gr *gzip.Reader
			gr, err = gzip.NewReader(f)
			if err != nil {
				panic(err)
			}
			r = bufio.NewReader(gr)
		} else {
			r = bufio.NewReader(f)
		}

		count := 0
		for {
			_, _, err = r.ReadLine()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
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
	if err != nil { // TODO: cleanup
		// suppress errors for OSPF because the file handle will be closed twice
		// since both v2 and v3 have the same gopacket.LayerType == "OSPF"
		if !strings.HasPrefix(name, "OSPF") {
			fmt.Println("unable to open file:", name, "error", err)
		}
		return 0
	}
	defer r.Close()

	var (
		header, errFileHeader = r.ReadHeader()
		record                = InitRecord(header.Type)
	)
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}

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

// NewHeader creates and returns a new netcap audit file header.
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
	colors    = []string{ansi.Yellow, ansi.LightRed, ansi.Cyan, ansi.Magenta, ansi.Blue, ansi.LightGreen, ansi.LightCyan, ansi.LightMagenta, ansi.LightYellow, ansi.Green, ansi.LightBlue, ansi.Red}
	numColors = len(colors)
	max       int
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
			//if !strings.Contains(line, "<") {
			//	b.WriteString(":")
			//}
			b.WriteString(strings.Join(parts[1:], ":"))
			b.WriteString("\n")
		} else {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}
