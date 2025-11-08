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
	sshLog.Info("SSH Decode() called",
		zap.String("ident", h.conversation.Ident),
		zap.Int("dataFragments", len(h.conversation.Data)),
		zap.String("clientIP", h.conversation.ClientIP),
		zap.String("serverIP", h.conversation.ServerIP),
		zap.Int("clientPort", int(h.conversation.ClientPort)),
		zap.Int("serverPort", int(h.conversation.ServerPort)),
	)
	
	// prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		sshLog.Error("SSH Decoder.Writer is nil - cannot write SSH audit records!")
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

	sshLog.Info("SSH decode complete",
		zap.String("ident", h.conversation.Ident),
		zap.Int("softwareRecords", len(h.software)),
		zap.String("clientIdent", h.clientIdent),
		zap.String("serverIdent", h.serverIdent),
		zap.Bool("clientKexInit", h.clientKexInit != nil),
		zap.Bool("serverKexInit", h.serverKexInit != nil),
	)

	// If we have idents but no KexInit, create audit records for incomplete handshakes
	if h.clientKexInit == nil && h.serverKexInit == nil {
		// Create audit records for ident-only connections (incomplete handshakes)
		if h.clientIdent != "" {
			err := Decoder.Writer.Write(&types.SSH{
				Timestamp: h.conversation.FirstClientPacket.UnixNano(),
				HASSH:     "", // No HASSH without KexInit
				Flow:      h.conversation.Ident,
				Ident:     h.clientIdent,
				Algorithms: "", // No algorithms without KexInit
				IsClient:   true,
				Notes:      "Incomplete handshake - no KexInit",
			})
			if err != nil {
				sshLog.Error("failed to write SSH audit record for client ident", zap.Error(err))
			} else {
				sshLog.Info("SSH audit record written (client ident-only)",
					zap.String("ident", h.conversation.Ident),
					zap.String("clientIdent", h.clientIdent),
				)
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}

		if h.serverIdent != "" {
			err := Decoder.Writer.Write(&types.SSH{
				Timestamp: h.conversation.FirstServerPacket.UnixNano(),
				HASSH:     "", // No HASSH without KexInit
				Flow:      utils.ReverseFlowIdent(h.conversation.Ident),
				Ident:     h.serverIdent,
				Algorithms: "", // No algorithms without KexInit
				IsClient:   false,
				Notes:      "Incomplete handshake - no KexInit",
			})
			if err != nil {
				sshLog.Error("failed to write SSH audit record for server ident", zap.Error(err))
			} else {
				sshLog.Info("SSH audit record written (server ident-only)",
					zap.String("ident", h.conversation.Ident),
					zap.String("serverIdent", h.serverIdent),
				)
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}
	}

	if len(h.software) == 0 {
		sshLog.Debug("No SSH software records generated",
			zap.String("ident", h.conversation.Ident),
		)
		// Don't return early anymore - we may have written ident-only audit records
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
	dirStr := "client"
	if dir != reassembly.TCPDirClientToServer {
		dirStr = "server"
	}
	
	sshLog.Debug("searchKexInit called",
		zap.String("ident", h.conversation.Ident),
		zap.String("direction", dirStr),
		zap.Bool("serverKexInitAlreadySet", h.serverKexInit != nil),
		zap.Bool("clientKexInitAlreadySet", h.clientKexInit != nil),
	)
	
	if h.serverKexInit != nil && h.clientKexInit != nil {
		sshLog.Debug("Both KexInit already set, skipping",
			zap.String("ident", h.conversation.Ident),
		)
		return
	}

	data, err := ioutil.ReadAll(r)
	if err != nil && !errors.Is(err, io.EOF) {
		sshLog.Warn("Failed to read data from buffer",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
			zap.Error(err),
		)
		fmt.Println(err)

		return
	}
	// fmt.Println(dir, len(data), "\n", hex.Dump(data))

	if len(data) == 0 {
		sshLog.Debug("No data to parse",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
		)
		return
	}
	
	sshLog.Debug("Read data from buffer",
		zap.String("ident", h.conversation.Ident),
		zap.String("direction", dirStr),
		zap.Int("dataLen", len(data)),
	)

	// length of the ident if it was found
	offset := 0

	if h.clientIdent == "" || h.serverIdent == "" { // read the SSH ident from the buffer
		sshLog.Debug("Parsing SSH ident",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
		)
		
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

			// SSH ident can end with either \n or \r\n
			// Check for \n (LF) alone
			if b == 0x0a {
				offset = len(ident) + 1
				// Don't include the \r if it was the last byte
				if lastByte == 0x0d && len(ident) > 0 {
					ident = ident[:len(ident)-1]
					offset = len(ident) + 2 // +2 because we consumed \r\n
				}
				break
			}

			lastByte = b
			ident = append(ident, b)
		}

		if dir == reassembly.TCPDirClientToServer {
			h.clientIdent = strings.TrimSpace(string(ident))
			sshLog.Info("Parsed client SSH ident",
				zap.String("ident", h.conversation.Ident),
				zap.String("sshIdent", h.clientIdent),
				zap.Int("offset", offset),
			)
			h.processSSHIdent(h.clientIdent, "client")
		} else {
			h.serverIdent = strings.TrimSpace(string(ident))
			sshLog.Info("Parsed server SSH ident",
				zap.String("ident", h.conversation.Ident),
				zap.String("sshIdent", h.serverIdent),
				zap.Int("offset", offset),
			)
			h.processSSHIdent(h.serverIdent, "server")
		}
	}

	// search the entire data fragment for the KexInit
	kexInitFound := false
	for i, b := range data {
		// 0x14 marks the beginning of the SSH KexInitMsg
		if !(b == 0x14) {
			continue
		}

		sshLog.Debug("Found KexInit marker (0x14)",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
			zap.Int("position", i),
			zap.Int("offset", offset),
		)

		// fmt.Println(dir, offset, len(data), i-1, "data[",offset,":",i-1,"]")
		// fmt.Println(hex.Dump(data))

		// check if length would have correct length
		if (i-1)-offset != 4 {
			sshLog.Debug("Invalid length field size",
				zap.String("ident", h.conversation.Ident),
				zap.String("direction", dirStr),
				zap.Int("lengthFieldSize", (i-1)-offset),
				zap.Int("expected", 4),
			)
			break
		}

		// check if array access is safe
		if offset > i-1 || len(data) <= i-1 {
			sshLog.Debug("Array access unsafe",
				zap.String("ident", h.conversation.Ident),
				zap.String("direction", dirStr),
				zap.Int("offset", offset),
				zap.Int("i-1", i-1),
				zap.Int("dataLen", len(data)),
			)
			break
		}

		length := int(binary.BigEndian.Uint32(data[offset : i-1]))
		padding := int(data[i-1])
		
		sshLog.Debug("Parsing SSH packet",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
			zap.Int("packetLength", length),
			zap.Int("padding", padding),
		)

		if len(data) < i+length-padding-1 {
			sshLog.Debug("Insufficient data for KexInit",
				zap.String("ident", h.conversation.Ident),
				zap.String("direction", dirStr),
				zap.Int("dataLen", len(data)),
				zap.Int("required", i+length-padding-1),
			)
			// fmt.Println("break: len(data) < i+length-padding-1")
			break
		}

		// fmt.Println("padding", padding, "length", length)
		// fmt.Println(hex.Dump(data[i:i+length-padding-1]))

		var init KexInitMsg

		err = Unmarshal(data[i:i+length-padding-1], &init)
		if err != nil {
			sshLog.Warn("Failed to unmarshal KexInit",
				zap.String("ident", h.conversation.Ident),
				zap.String("direction", dirStr),
				zap.Error(err),
			)
			fmt.Println(err)
			break
		}
		
		kexInitFound = true
		sshLog.Info("Successfully parsed KexInit",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
		)

		// spew.Dump("found SSH KexInit", h.parent.ident, init)
		hash, raw := computeHASSH(init)

		// Lookup HASSH fingerprint in database to enrich SSH audit record
		var hasshDescriptions []string
		for _, soft := range software.HashDBMap[hash] {
			hasshDescriptions = append(hasshDescriptions, soft.Version)
		}

		if dir == reassembly.TCPDirClientToServer {
			err = Decoder.Writer.Write(&types.SSH{
				Timestamp:         h.conversation.FirstClientPacket.UnixNano(),
				HASSH:             hash,
				Flow:              h.conversation.Ident,
				Ident:             h.clientIdent,
				Algorithms:        raw,
				IsClient:          true,
				HASSHDescriptions: hasshDescriptions,
			})
			if err != nil {
				sshLog.Error("failed to flush ssh audit record", zap.Error(err))
			} else {
				sshLog.Info("SSH audit record written (client)",
					zap.String("ident", h.conversation.Ident),
					zap.String("hassh", hash),
					zap.String("clientIdent", h.clientIdent),
				)
			}

			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

			h.clientKexInit = &init

			sshLog.Info("found clientKexInit", zap.String("ident", h.conversation.Ident))
		} else {
			err = Decoder.Writer.Write(&types.SSH{
				Timestamp:         h.conversation.FirstServerPacket.UnixNano(),
				HASSH:             hash,
				Flow:              utils.ReverseFlowIdent(h.conversation.Ident),
				Ident:             h.serverIdent,
				Algorithms:        raw,
				IsClient:          false,
				HASSHDescriptions: hasshDescriptions,
			})
			if err != nil {
				sshLog.Error("failed to flush ssh audit record", zap.Error(err))
			} else {
				sshLog.Info("SSH audit record written (server)",
					zap.String("ident", h.conversation.Ident),
					zap.String("hassh", hash),
					zap.String("serverIdent", h.serverIdent),
				)
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
	
	if !kexInitFound {
		sshLog.Warn("No KexInit found in stream",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
			zap.Int("dataLen", len(data)),
		)
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
