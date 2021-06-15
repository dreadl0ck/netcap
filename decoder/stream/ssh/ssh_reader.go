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

package ssh

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

/*
 * SSH - The Secure Shell Protocol
 */

type sshReader struct {
	conversation *core.ConversationInfo

	clientIdent   string
	serverIdent   string
	clientKexInit *KexInitMsg
	serverKexInit *KexInitMsg
	software      []*types.Software
}

// New returns a new SSH reader.
func (h *sshReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &sshReader{
		conversation: conversation,
	}
}

// Decode parses the stream according to the SSH protocol.
func (h *sshReader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		return
	}

	var (
		serverBuf bytes.Buffer
		clientBuf bytes.Buffer
	)

	for _, d := range h.conversation.Data {
		if d.Direction() == reassembly.TCPDirClientToServer {
			// 2255k bytes should be enough to capture ident (max 255 bytes) + kexInit (usually ~1200-1700 bytes)
			if clientBuf.Len() < 2255 {
				clientBuf.Write(d.Raw())
			}
		} else {
			// 2255k bytes should be enough to capture ident (max 255 bytes) + kexInit (usually ~1200-1700 bytes)
			if serverBuf.Len() < 2255 {
				serverBuf.Write(d.Raw())
			}
		}
	}

	h.searchKexInit(bufio.NewReader(&clientBuf), reassembly.TCPDirClientToServer)
	h.searchKexInit(bufio.NewReader(&serverBuf), reassembly.TCPDirServerToClient)

	if len(h.software) == 0 {
		return
	}

	// add new audit records or update existing
	software.Store.Lock()
	for _, s := range h.software {
		if _, ok := software.Store.Items[s.Product+"/"+s.Version]; ok {
			// TODO updateSoftwareAuditRecord(dp, p, i)
		} else {
			software.Store.Items[s.Product+"/"+s.Version] = &software.AtomicSoftware{
				Software: s,
				Mutex:    sync.Mutex{},
			}
			streamutils.Stats.Lock()
			streamutils.Stats.NumSoftware++
			streamutils.Stats.Unlock()
		}
	}
	software.Store.Unlock()
}

func (h *sshReader) processSSHIdent(ident string, entity string) {
	i := parseSSHIdent(ident)
	if i != nil {
		software.WriteSoftware([]*software.AtomicSoftware{
			{
				Software: &types.Software{
					Timestamp:  h.conversation.FirstClientPacket.UnixNano(),
					Product:    i.productName,
					Version:    i.productVersion,
					SourceName: "SSH " + entity + " Ident",
					Service:    serviceSSH,
					Flows:      []string{h.conversation.Ident},
					Notes:      "SSH version: " + i.sshVersion + " OS: " + i.os,
					SourceData: h.serverIdent,
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
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Println(err)

		return
	}
	// fmt.Println(dir, len(data), "\n", hex.Dump(data))

	if len(data) == 0 {
		return
	}

	// length of the ident if it was found
	offset := 0

	if h.clientIdent == "" || h.serverIdent == "" { // read the SSH ident from the buffer
		var (
			br       = bytes.NewReader(data)
			b        byte
			ident    []byte
			lastByte byte
		)

		for {
			b, err = br.ReadByte()
			if errors.Is(err, io.EOF) {
				break
			}

			if lastByte == 0x0d && b == 0x0a {
				offset = len(ident) + 1

				break
			}

			lastByte = b
			ident = append(ident, b)
		}

		if dir == reassembly.TCPDirClientToServer {
			h.clientIdent = strings.TrimSpace(string(ident))
			h.processSSHIdent(h.clientIdent, "client")
		} else {
			h.serverIdent = strings.TrimSpace(string(ident))
			h.processSSHIdent(h.serverIdent, "server")
		}
	}

	// search the entire data fragment for the KexInit
	for i, b := range data {
		// 0x14 marks the beginning of the SSH KexInitMsg
		if !(b == 0x14) {
			continue
		}

		// fmt.Println(dir, offset, len(data), i-1, "data[",offset,":",i-1,"]")
		// fmt.Println(hex.Dump(data))

		// check if length would have correct length
		if (i-1)-offset != 4 {
			break
		}

		// check if array access is safe
		if offset > i-1 || len(data) <= i-1 {
			break
		}

		length := int(binary.BigEndian.Uint32(data[offset : i-1]))
		padding := int(data[i-1])

		if len(data) < i+length-padding-1 {
			// fmt.Println("break: len(data) < i+length-padding-1")
			break
		}

		// fmt.Println("padding", padding, "length", length)
		// fmt.Println(hex.Dump(data[i:i+length-padding-1]))

		var init KexInitMsg

		err = Unmarshal(data[i:i+length-padding-1], &init)
		if err != nil {
			fmt.Println(err)
		}

		// spew.Dump("found SSH KexInit", h.parent.ident, init)
		hash, raw := computeHASSH(init)

		if dir == reassembly.TCPDirClientToServer {
			err = Decoder.Writer.Write(&types.SSH{
				Timestamp:  h.conversation.FirstClientPacket.UnixNano(),
				HASSH:      hash,
				Flow:       h.conversation.Ident,
				Ident:      h.clientIdent,
				Algorithms: raw,
				IsClient:   true,
			})
			if err != nil {
				sshLog.Error("failed to flush ssh audit record", zap.Error(err))
			}

			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

			h.clientKexInit = &init

			sshLog.Info("found clientKexInit", zap.String("ident", h.conversation.Ident))
		} else {
			err = Decoder.Writer.Write(&types.SSH{
				Timestamp:  h.conversation.FirstServerPacket.UnixNano(),
				HASSH:      hash,
				Flow:       utils.ReverseFlowIdent(h.conversation.Ident),
				Ident:      h.serverIdent,
				Algorithms: raw,
				IsClient:   false,
			})
			if err != nil {
				sshLog.Error("failed to flush ssh audit record", zap.Error(err))
			}

			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

			h.serverKexInit = &init

			sshLog.Info("found serverKexInit", zap.String("ident", h.conversation.Ident))
		}

		// TODO fetch device profile
		for _, soft := range software.HashDBMap[hash] {
			sshVersion, product, version, os := parseSSHInfoFromHasshDB(soft.Version)

			h.software = append(h.software, &types.Software{
				Timestamp: h.conversation.FirstClientPacket.UnixNano(),
				Product:   product,
				Vendor:    "", // do not set the vendor for now
				Version:   version,
				// DeviceProfiles: []string{dpIdent},
				SourceName: "HASSH Lookup",
				SourceData: hash,
				Service:    serviceSSH,
				// DPIResults:     protos,
				Flows: []string{h.conversation.Ident},
				Notes: "Likelihood: " + soft.Likelihood + " Possible OS: " + os + "SSH Version: " + sshVersion,
			})
		}

		break
	}
}

func parseSSHInfoFromHasshDB(soft string) (sshVersion string, product string, version string, os string) {
	var (
		firstSplit    = strings.Split(soft, " ? ")
		sshVersionTmp = firstSplit[0]
		sshVersionArr = strings.Split(sshVersionTmp, " | ")
		vendorVersion = strings.Split(sshVersionArr[1], " ")
	)

	if len(firstSplit) > 1 {
		os = firstSplit[len(firstSplit)-1]

		return sshVersionArr[0], vendorVersion[0], vendorVersion[1], os
	}

	if len(vendorVersion) > 1 {
		version = vendorVersion[1]
	}

	return sshVersionArr[0], vendorVersion[0], version, os
}

type sshVersionInfo struct {
	sshVersion     string
	productName    string
	productVersion string
	os             string
}

var regSSHIdent = regexp.MustCompile(`^(SSH-[0-9]\.?[0-9]?)-(.*[[:word:]]*)_([0-9]\.[0-9]?\.?[[:alnum:]]?[[:alnum:]]?)[[:space:]]?([[:alnum:]]*)`)

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
// TODO: move this functionality into standalone package.
func computeHASSH(init KexInitMsg) (hash string, raw string) {
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
