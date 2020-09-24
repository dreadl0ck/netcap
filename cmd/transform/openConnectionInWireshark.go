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

package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	wiresharkPath = "/usr/local/bin/wireshark"
	tcpdumpPath   = "tcpdump"
)

func init() {
	if runtime.GOOS == platformWindows {
		tcpdumpPath = "tcpdump.exe"
		wiresharkPath = "C:\\Program Files\\Wireshark\\Wireshark.exe"
	}
}

// TODO: refactor this method, last three params are only used for the software transform atm
func makeOutFilePath(in, bpf string, lt maltego.LocalTransform, flows bool, bpfSummary string) (name string, exists bool) {

	// output the files to an directory inside the netcap folder
	outPath := filepath.Join(in+".net", "extractedStreams")
	_ = os.Mkdir(outPath, defaults.DirectoryPermission)

	// the base of the input string is the pcap filename, strip the extensions
	fileName := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(in), ".pcap"),
		".pcapng",
	)

	// join the out path with the new file name
	if flows {
		// group multiple flows so the filename does not grow too long
		name = filepath.Join(
			outPath,
			fileName+"-software-"+lt.Values["product"]+"-"+bpfSummary+".pcap",
		)
	} else {
		// replace all whitespace in the bpf with dashes
		name = filepath.Join(
			outPath,
			fileName+"-"+strings.ReplaceAll(bpf, " ", "-")+".pcap",
		)
	}

	_, err := os.Stat(name)
	if err == nil {
		// no error, file exists
		return name, true
	}
	return name, false
}

func openConnectionInWireshark() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		in              = strings.TrimSuffix(filepath.Dir(lt.Values["path"]), ".net")
		bpf             = makeConnectionBPF(lt)
		outFile, exists = makeOutFilePath(in, bpf, lt, false, "")
		args            = []string{"-r", in, "-w", outFile, bpf}
	)

	if !exists {
		log.Println(tcpdumpPath, args)

		out, err := exec.Command(tcpdumpPath, args...).CombinedOutput()
		if err != nil {
			die(err.Error(), "open file failed:\n"+string(out))
		}

		log.Println(string(out))
	}

	log.Println(wiresharkPath, outFile)

	out, err := exec.Command(wiresharkPath, outFile).CombinedOutput()
	if err != nil {
		die(err.Error(), "open file failed:\n"+string(out))
	}

	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

// creates a bpf to filter for traffic of a single connection
// defined by two hosts and two ports
// eg: "(host 192.168.1.14 and port 56988) and (host 224.0.0.252 and port 5355)"
func makeConnectionBPF(lt maltego.LocalTransform) string {
	var b strings.Builder

	b.WriteString("(host ")
	b.WriteString(lt.Values["srcip"])
	b.WriteString(" and port ")
	b.WriteString(lt.Values["srcport"])
	b.WriteString(") and (host ")
	b.WriteString(lt.Values["dstip"])
	b.WriteString(" and port ")
	b.WriteString(lt.Values["dstport"])
	b.WriteString(")")

	return b.String()
}
