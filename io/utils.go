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

package io

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
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

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

const newline = "\n"

var errMissingInterface = errors.New("type does not implement the types.AuditRecord interface")

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
` + netcap.Version

// PrintLogo prints the netcap logo.
func PrintLogo() {
	utils.ClearScreen()
	fmt.Println(logo)
}

// FPrintLogo PrintLogo prints the netcap logo.
func FPrintLogo(w io.Writer) {
	_, _ = fmt.Fprintln(w, logo)
}

// PrintBuildInfo displays build information related to netcap to stdout.
func PrintBuildInfo() {
	FPrintLogo(os.Stdout)
	FPrintBuildInfo(os.Stdout)
}

// FPrintBuildInfo PrintBuildInfo displays build information related to netcap to the specified io protoWriter.
func FPrintBuildInfo(w io.Writer) {
	_, _ = fmt.Fprintln(w, "\n> Date of execution:", time.Now().UTC())
	_, _ = fmt.Fprintln(w, "> NETCAP build commit:", netcap.Commit)
	_, _ = fmt.Fprintln(w, "> go runtime version:", runtime.Version())
	_, _ = fmt.Fprintln(w, "> number of cores:", runtime.NumCPU(), "cores")

	b, ok := debug.ReadBuildInfo()
	if ok {
		for _, d := range b.Deps {
			if path.Base(d.Path) == "gopacket" {
				_, _ = fmt.Fprintln(w, "> gopacket:", d.Path, "version:", d.Version)
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
		return fmt.Errorf("failed to open audit record file: %w", err)
	}

	defer func() {
		errClose := r.Close()
		if errClose != nil {
			fmt.Println("failed to close file", errClose)
		}
	}()

	if c.Separator == "\\t" || c.TabSeparated {
		c.Separator = "\t"
		c.CSV = true
	}

	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		return errFileHeader
	}

	var (
		record = InitRecord(header.Type)
		// rows for table print
		rows     [][]string
		colorMap map[string]string
	)

	// disable structured dumping explicitly, since its enabled by default.
	if c.CSV || c.JSON || c.Table {
		c.Structured = false
	}

	types.Select(record, c.Selection)
	types.UTC = c.UTC

	if !c.Structured && !c.Table && !c.JSON {
		if p, ok := record.(types.AuditRecord); ok {
			_, _ = w.WriteString(strings.Join(p.CSVHeader(), c.Separator) + "\n")
		} else {
			return fmt.Errorf("%w, invalid type: %#v", errMissingInterface, record)
		}

		if c.Fields {
			return nil
		}
	}

	for {
		err = r.Next(record)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read next audit record: %w", err)
		}
		count++

		if p, ok := record.(types.AuditRecord); ok {

			// JSON
			if c.JSON {
				marshaled, errMarshal := json.Marshal(p)
				if errMarshal != nil {
					return fmt.Errorf("failed to marshal json: %w", errMarshal)
				}

				_, _ = w.WriteString(string(marshaled))
				_, _ = w.WriteString(newline)

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
				_, _ = w.WriteString(strings.Join(p.CSVRecord(), c.Separator) + newline)

				continue
			}

			// default: if TTY, dump structured with colors
			if isTTY {
				_, _ = w.WriteString(ansi.White)
				_, _ = w.WriteString(header.Type.String())
				_, _ = w.WriteString(ansi.Reset)
				_, _ = w.WriteString(newline)
				_, _ = w.WriteString(colorizeProto(proto.MarshalTextString(record), colorMap, &c))
			} else { // structured without colors
				_, _ = w.WriteString(header.Type.String())
				_, _ = w.WriteString(newline)
				_, _ = w.WriteString(proto.MarshalTextString(record))
			}

			_, _ = w.WriteString(newline)
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

	// print number of records when dumping structured
	if c.Structured || c.Table {
		_, _ = w.WriteString(strconv.Itoa(count) + " records.\n")
	}

	return nil
}

// GenerateConfig generates a default configuration for the given flag set.
func GenerateConfig(fs *flag.FlagSet, tool string) {
	fmt.Println("# NETCAP config for " + tool + " tool")
	fmt.Println("# Generated by NETCAP " + netcap.Version)
	fmt.Println("# You can regenerate an up to date default configuration with:")
	fmt.Println("# 	$ net <tool> -gen-config > net.<tool>.conf")
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

func colorizeProto(in string, colorMap map[string]string, c *DumpConfig) string {
	var (
		b     strings.Builder
		index int
	)

	if colorMap == nil {
		colorMap = make(map[string]string)

		for i, line := range strings.Split(in, newline) {
			if line == "" {
				continue
			}

			if line == newline {
				b.WriteString(newline)

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

	for _, line := range strings.Split(in, newline) {
		if line == "" {
			continue
		}

		if line == newline {
			b.WriteString(newline)

			continue
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

			// if !strings.Contains(line, "<") {
			// 	b.WriteString(":")
			// }

			if parts[0] == "Timestamp" && c.UTC {
				ts, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err != nil {
					log.Fatal("invalid value for timestamp:", parts)
				}

				b.WriteString(" ")
				b.WriteString(utils.UnixTimeToUTC(int64(ts)))
			} else {
				b.WriteString(strings.Join(parts[1:], ":"))
			}

			b.WriteString(newline)
		} else {
			b.WriteString(line)
			b.WriteString(newline)
		}
	}

	return b.String()
}

// NewHeader creates and returns a new netcap audit file header.
func NewHeader(t types.Type, source, version string, includesPayloads bool, ti time.Time) *types.Header {
	// init header
	header := new(types.Header)
	header.Type = t
	header.Created = ti.UnixNano()
	header.InputSource = source
	header.Version = version
	header.ContainsPayloads = includesPayloads

	return header
}
