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
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/utils"
)

func openSoftwareTrafficInWireshark() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		in              = strings.TrimSuffix(filepath.Dir(strings.TrimPrefix(lt.Values["path"], "file://")), ".net")
		bpf, name       = makeFlowsBPF(lt)
		outFile, exists = makeOutFilePath(in, bpf, lt, true, name)
		args            = []string{"-r", in, "-w", outFile, bpf}
	)

	if !exists {
		log.Println(tcpdump, args)

		out, err := exec.Command(findExecutable(tcpdump, false), args...).CombinedOutput()
		if err != nil {
			maltego.Die(err.Error(), "open file failed:\n"+string(out))
		}

		log.Println(string(out))
	}

	log.Println(wireshark, outFile)

	out, err := exec.Command(findExecutable(wireshark, false), outFile).CombinedOutput()
	if err != nil {
		maltego.Die(err.Error(), "open file failed:\n"+string(out))
	}

	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

// creates a bpf to filter for traffic of a single connection
// defined by two hosts and two ports
// eg: "(host 192.168.1.14 and port 56988) and (host 224.0.0.252 and port 5355)"
func makeConnectionBPFFrom4Tuple(srcIP, srcPort, dstIP, dstPort string) string {
	var b strings.Builder

	b.WriteString("(host ")
	b.WriteString(srcIP)
	b.WriteString(" and port ")
	b.WriteString(srcPort)
	b.WriteString(") and (host ")
	b.WriteString(dstIP)
	b.WriteString(" and port ")
	b.WriteString(dstPort)
	b.WriteString(")")

	return b.String()
}

// creates a bpf to filter for traffic of a specific software that might have been seen in multiple flows
func makeFlowsBPF(lt maltego.LocalTransform) (bpf string, name string) {
	var (
		b      strings.Builder
		srcIPs = make(map[string]struct{})
		dstIPs = make(map[string]struct{})
	)

	for i, flow := range strings.Split(lt.Values["flows"], " | ") {
		if i > 0 {
			b.WriteString(" or ")
		}

		srcIP, srcPort, dstIP, dstPort := utils.ParseFlowIdent(flow)

		b.WriteString("(")
		b.WriteString(makeConnectionBPFFrom4Tuple(srcIP, srcPort, dstIP, dstPort))
		b.WriteString(")")

		srcIPs[srcIP] = struct{}{}
		dstIPs[dstIP] = struct{}{}
	}

	for h := range srcIPs {
		name += h + "-"
	}

	name += "-"

	for h := range dstIPs {
		name += h + "-"
	}

	return b.String(), strings.TrimSuffix(name, "-")
}
