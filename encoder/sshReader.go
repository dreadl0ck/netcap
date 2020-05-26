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

package encoder

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/sshx"
	"github.com/dreadl0ck/netcap/types"
	"github.com/sasha-s/go-deadlock"
)

/*
 * SSH - The Secure Shell Protocol
 */

type sshReader struct {
	parent        *tcpConnection
	clientIdent   string
	serverIdent   string
	clientKexInit *sshx.KexInitMsg
	serverKexInit *sshx.KexInitMsg
	software      []*types.Software
}

func (h *sshReader) Decode(s2c Stream, c2s Stream) {

	// parse conversation
	var (
		buf         bytes.Buffer
		previousDir reassembly.TCPFlowDirection
	)
	if len(h.parent.merged) > 0 {
		previousDir = h.parent.merged[0].dir
	}

	for _, d := range h.parent.merged {

		if d.dir == previousDir {
			buf.Write(d.raw)
		} else {
			h.searchKexInit(bufio.NewReader(&buf), previousDir)
			buf.Reset()

			previousDir = d.dir
			buf.Write(d.raw)
			continue
		}
	}
	h.searchKexInit(bufio.NewReader(&buf), previousDir)
	if len(h.software) == 0 {
		return
	}

	// add new audit records or update existing
	SoftwareStore.Lock()
	for _, s := range h.software {
		if _, ok := SoftwareStore.Items[s.Product+"/"+s.Version]; ok {
			// TODO updateSoftwareAuditRecord(dp, p, i)
		} else {
			SoftwareStore.Items[s.Product+"/"+s.Version] = &Software{
				s,
				deadlock.Mutex{},
			}
			statsMutex.Lock()
			reassemblyStats.numSoftware++
			statsMutex.Unlock()
		}
	}
	SoftwareStore.Unlock()
}

func (h *sshReader) processSSHIdent(ident string, entity string) {
	i := parseSSHIdent(ident)
	if i != nil {
		writeSoftware([]*Software{
			{
				Software: &types.Software{
					Timestamp:      h.parent.firstPacket.String(),
					Product:        i.productName,
					Version:        i.productVersion,
					SourceName:     "SSH " + entity + " Ident",
					Service:        "SSH",
					Flows:          []string{h.parent.ident},
					Notes:          "SSH version: " + i.sshVersion + " OS: " + i.os,
					SourceData:     h.serverIdent,
				},
			},
		}, nil)
	}
}

func (h *sshReader) searchKexInit(r *bufio.Reader, dir reassembly.TCPFlowDirection) {

	if h.serverKexInit != nil && h.clientKexInit != nil {
		return
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(data) == 0 {
		return
	}

	if h.clientIdent == "" || h.serverIdent == "" {

		if dir == reassembly.TCPDirClientToServer {
			h.clientIdent = string(data)
			h.processSSHIdent(h.clientIdent, "client")
		} else {
			h.serverIdent = string(data)
			h.processSSHIdent(h.serverIdent, "server")
		}

		return
	}

	for i, b := range data {

		if b == 0x14 { // Marks the beginning of the KexInitMsg // TODO: stop checking after X bytes, and after we already have server and client hashes

			if i == 0 {
				break
			}

			if len(data[:i-1]) != 4 {
				break
			}

			length := int(binary.BigEndian.Uint32(data[:i-1]))
			padding := int(data[i-1])
			if len(data) < i+length-padding-1 {
				break
			}

			//fmt.Println("padding", padding, "length", length)
			//fmt.Println(hex.Dump(data[i:i+length-padding-1]))

			var init sshx.KexInitMsg
			err := sshx.Unmarshal(data[i:i+length-padding-1], &init)
			if err != nil {
				fmt.Println(err)
			}

			//spew.Dump("found SSH KexInit", h.parent.ident, init)
			hash, raw := computeHASSH(init)
			if dir == reassembly.TCPDirClientToServer {
				sshEncoder.write(&types.SSH{
					Timestamp:  h.parent.client.FirstPacket().String(),
					HASSH:      hash,
					Flow:       h.parent.ident,
					Ident:      h.clientIdent,
					Algorithms: raw,
					IsClient:   true,
				})
				h.clientKexInit = &init
			} else {
				sshEncoder.write(&types.SSH{
					Timestamp:  h.parent.client.FirstPacket().String(),
					HASSH:      hash,
					Flow:       reverseIdent(h.parent.ident),
					Ident:      h.serverIdent,
					Algorithms: raw,
					IsClient:   false,
				})
				h.serverKexInit = &init
			}

			// TODO fetch device profile
			for _, soft := range hashDBMap[hash] {
				sshVersion, product, version, os := parseSSHInfoFromHasshDB(soft.Version)
				h.software = append(h.software, &types.Software{
					Timestamp: h.parent.client.FirstPacket().String(),
					Product:   product,
					Vendor:    "", // do not set the vendor for now
					Version:   version,
					//DeviceProfiles: []string{dpIdent},
					SourceName: "HASSH Lookup",
					SourceData: hash,
					Service:    "SSH",
					//DPIResults:     protos,
					Flows: []string{h.parent.ident},
					Notes: "Likelyhood: " + soft.Likelyhood + " Possible OS: " + os + "SSH Version: " + sshVersion,
				})
			}
			break
		}
	}
}

func parseSSHInfoFromHasshDB(soft string) (sshVersion string, product string, version string, os string) {

	var (
		firstSplit = strings.Split(soft, " ? ")
		sshVersionTmp = firstSplit[0]
		sshVersionArr = strings.Split(sshVersionTmp, " | ")
		vendorVersion = strings.Split(sshVersionArr[1], " ")
	)

	if len(firstSplit) > 1 {
		os = firstSplit[len(firstSplit)-1]
		return sshVersionArr[0], vendorVersion[0], vendorVersion[1], os
	}
	return sshVersionArr[0], vendorVersion[0], vendorVersion[1], os
}

type sshVersionInfo struct {
	sshVersion string
	productName string
	productVersion string
	os string
}

var regSSHIdent = regexp.MustCompile("^(SSH-[0-9]\\.?[0-9]?)-(.*[[:word:]]*)_([0-9]\\.[0-9]?\\.?[[:alnum:]]?[[:alnum:]]?)[[:space:]]?([[:alnum:]]*)")
func parseSSHIdent(ident string) *sshVersionInfo {
	if m := regSSHIdent.FindStringSubmatch(ident); len(m) > 0 {

		var os string
		if len(m) > 4 {
			os = m[4]
		}
		return &sshVersionInfo{
			sshVersion:     m[1],
			productName:    m[2],
			productVersion: m[3],
			os:             os,
		}
	}
	return nil
}

// HASSH SSH Fingerprint
// TODO: move this functionality into standalone package
func computeHASSH(init sshx.KexInitMsg) (hash string, raw string) {

	var b strings.Builder
	b.WriteString(strings.Join(init.KexAlgos, ","))
	b.WriteString(";")
	b.WriteString(strings.Join(init.CiphersClientServer, ","))
	b.WriteString(";")
	b.WriteString(strings.Join(init.MACsClientServer, ","))
	b.WriteString(";")
	b.WriteString(strings.Join(init.CompressionClientServer, ","))

	return fmt.Sprintf("%x", md5.Sum([]byte(b.String()))), b.String()
}
