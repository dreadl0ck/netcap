/*
* NETCAP - Traffic Analysis Framework
* Copyright (c) 2017-2025 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"encoding/binary"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/software"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	ja4 "github.com/dreadl0ck/netcap/internal/ja4plusadapter"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/types"
)

/*
 * SSH - The Secure Shell Protocol
 */

type sshReader struct {
	conversation *core.ConversationInfo

	clientIdent       string
	serverIdent       string
	clientKexInit     *KexInitMsg
	serverKexInit     *KexInitMsg
	software          []*types.Software
	ja4sshData        *ja4.SSHStreamData
	ja4sshFingerprint string
	ja4sshSessionType string
	observedAt        [2]int64
	qualifications    [2]string
}

const maxSSHPrefix = 64 << 10

// New returns a new SSH reader.
func (h *sshReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	reader := &sshReader{conversation: conversation}
	if ja4.Enabled {
		reader.ja4sshData = ja4.NewSSHStreamData()
	}
	return reader
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
		serverBuf   bytes.Buffer
		clientBuf   bytes.Buffer
		started     [2]bool
		stopped     [2]bool
		observation [2]string
	)

	for _, d := range h.conversation.Data {
		index := 0
		buf := &clientBuf
		if d.Direction() == reassembly.TCPDirServerToClient {
			index, buf = 1, &serverBuf
		}
		if fragment, ok := d.(*core.StreamData); ok {
			if fragment.HasGap(started[index]) {
				stopped[index] = true
				h.qualifications[index] = "capture or retention gap"
			} else if fragment.SkippedBytes == -1 {
				h.qualifications[index] = "capture started midstream"
			}
			if fragment.TCPObservation != "" {
				if started[index] && observation[index] != fragment.TCPObservation {
					stopped[index] = true
				}
				h.qualifications[index] = fragment.TCPObservation + "; endpoint delivery unconfirmed"
			}
			observation[index] = fragment.TCPObservation
		}
		payloadLen := len(d.Raw())
		if payloadLen > 0 && !started[index] {
			h.observedAt[index] = core.FragmentTime(d)
			started[index] = true
		}
		if !stopped[index] && buf.Len() < maxSSHPrefix {
			buf.Write(d.Raw()[:min(payloadLen, maxSSHPrefix-buf.Len())])
		}
		if d.Direction() == reassembly.TCPDirClientToServer {
			// Track for JA4SSH
			if ja4.Enabled && payloadLen > 0 {
				h.ja4sshData.AddClientPacket(payloadLen)
			} else if ja4.Enabled {
				h.ja4sshData.AddClientACK()
			}
		} else {
			// Track for JA4SSH
			if ja4.Enabled && payloadLen > 0 {
				h.ja4sshData.AddServerPacket(payloadLen)
			} else if ja4.Enabled {
				h.ja4sshData.AddServerACK()
			}
		}
	}

	// Compute JA4SSH fingerprint from all collected packet data
	if ja4.Enabled {
		h.ja4sshFingerprint = ja4.ComputeJA4SSH(h.ja4sshData)
		h.ja4sshSessionType = ja4.DetectSessionType(h.ja4sshFingerprint)
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

	// Keep either observed identification when its KEX was not captured.
	if h.clientKexInit == nil || h.serverKexInit == nil {
		// Create audit records for ident-only connections (incomplete handshakes)
		if h.clientIdent != "" && h.clientKexInit == nil {
			err := Decoder.Writer.Write(&types.SSH{
				Timestamp:         h.observedAt[0],
				Ja4Ssh:            h.ja4sshFingerprint,
				Flow:              h.conversation.Ident,
				Ident:             h.clientIdent,
				Algorithms:        "", // No algorithms without KexInit
				IsClient:          true,
				Notes:             h.notes(0, true),
				Ja4SshSessionType: h.ja4sshSessionType,
				CommunityID:       h.conversation.CommunityID,
			})
			if err != nil {
				sshLog.Error("failed to write SSH audit record for client ident", zap.Error(err))
			} else {
				sshLog.Info("SSH audit record written (client ident-only)",
					zap.String("ident", h.conversation.Ident),
					zap.String("clientIdent", h.clientIdent),
					zap.String("ja4ssh", h.ja4sshFingerprint),
				)
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}

		if h.serverIdent != "" && h.serverKexInit == nil {
			err := Decoder.Writer.Write(&types.SSH{
				Timestamp:         h.observedAt[1],
				Ja4Ssh:            h.ja4sshFingerprint,
				Flow:              utils.ReverseFlowIdent(h.conversation.Ident),
				Ident:             h.serverIdent,
				Algorithms:        "", // No algorithms without KexInit
				IsClient:          false,
				Notes:             h.notes(1, true),
				Ja4SshSessionType: h.ja4sshSessionType,
				CommunityID:       h.conversation.CommunityID,
			})
			if err != nil {
				sshLog.Error("failed to write SSH audit record for server ident", zap.Error(err))
			} else {
				sshLog.Info("SSH audit record written (server ident-only)",
					zap.String("ident", h.conversation.Ident),
					zap.String("serverIdent", h.serverIdent),
					zap.String("ja4ssh", h.ja4sshFingerprint),
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

func (h *sshReader) notes(index int, noKex bool) string {
	var notes []string
	if noKex {
		notes = append(notes, "Incomplete handshake - no KexInit")
	}
	peer := h.conversation.ServerData
	if index == 1 {
		peer = h.conversation.ClientData
	}
	if len(peer.FirstNonEmpty()) == 0 {
		notes = append(notes, "peer not observed")
	}
	if !h.conversation.TCPHandshakeComplete {
		notes = append(notes, "TCP establishment incomplete")
	}
	switch h.conversation.TCPRoleSource {
	case "first-observed":
		notes = append(notes, "endpoint role unknown; first-observed direction")
	case "service-port":
		notes = append(notes, "endpoint role inferred from service port")
	}
	if h.qualifications[index] != "" {
		notes = append(notes, h.qualifications[index])
	}
	return strings.Join(notes, "; ")
}

func (h *sshReader) processSSHIdent(ident string, entity string) {
	i := parseSSHIdent(ident)
	if i != nil {
		index, flow := 0, h.conversation.Ident
		if entity == "server" {
			index, flow = 1, utils.ReverseFlowIdent(flow)
		}
		software.WriteSoftware([]*software.AtomicSoftware{
			{
				Software: &types.Software{
					Timestamp:  h.observedAt[index],
					Product:    i.productName,
					Version:    i.productVersion,
					SourceName: "SSH " + entity + " Ident",
					Service:    serviceSSH,
					Flows:      []string{flow},
					Notes:      "SSH version: " + i.sshVersion + " OS: " + i.os,
					SourceData: ident,
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

	data, err := io.ReadAll(io.LimitReader(r, maxSSHPrefix))
	if err != nil && !errors.Is(err, io.EOF) {
		sshLog.Warn("Failed to read data from buffer",
			zap.String("ident", h.conversation.Ident),
			zap.String("direction", dirStr),
			zap.Error(err),
		)
		return
	}

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

	ident, offset := sshIdentification(data)
	if offset == 0 {
		return
	}
	if dir == reassembly.TCPDirClientToServer {
		h.clientIdent = ident
		h.processSSHIdent(ident, "client")
	} else {
		h.serverIdent = ident
		h.processSSHIdent(ident, "server")
	}

	init, ok := initialKex(data[offset:])
	if !ok {
		return
	}

	index, flow := 0, h.conversation.Ident
	ciphers, macs := init.CiphersClientServer, init.MACsClientServer
	if dir == reassembly.TCPDirClientToServer {
		h.clientKexInit = &init
	} else {
		h.serverKexInit = &init
		index, flow = 1, utils.ReverseFlowIdent(flow)
		ciphers, macs = init.CiphersServerClient, init.MACsServerClient
	}
	err = Decoder.Writer.Write(&types.SSH{
		Timestamp:               h.observedAt[index],
		Notes:                   h.notes(index, false),
		Ja4Ssh:                  h.ja4sshFingerprint,
		Flow:                    flow,
		Ident:                   ident,
		Algorithms:              buildAlgorithmsString(init),
		IsClient:                index == 0,
		Ja4SshSessionType:       h.ja4sshSessionType,
		SoftwareVersion:         extractSoftwareVersion(ident),
		OSGuess:                 guessOS(ident),
		HasWeakKex:              hasWeakKex(init.KexAlgos),
		HasWeakCipher:           hasWeakCipher(ciphers),
		HasWeakMAC:              hasWeakMAC(macs),
		ServerHostKeyAlgorithms: strings.Join(init.ServerHostKeyAlgos, ","),
		CommunityID:             h.conversation.CommunityID,
	})
	if err != nil {
		sshLog.Error("failed to flush ssh audit record", zap.Error(err))
	} else {
		atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	}
}

func initialKex(data []byte) (KexInitMsg, bool) {
	var init KexInitMsg
	if len(data) < 6 || data[5] != 20 {
		return init, false
	}
	length, padding := int(binary.BigEndian.Uint32(data)), int(data[4])
	if padding < 4 || length < padding+2 || length > maxSSHPrefix || length+4 > len(data) {
		return init, false
	}
	err := Unmarshal(data[5:4+length-padding], &init)
	return init, err == nil
}

func parseSSHInfoFromHasshDB(soft string) (sshVersion string, product string, version string, os string) {
	var (
		firstSplit    = strings.Split(soft, " ? ")
		sshVersionTmp = firstSplit[0]
		sshVersionArr = strings.Split(sshVersionTmp, " | ")
	)

	// Check if we have at least 2 parts after splitting by " | "
	if len(sshVersionArr) < 2 {
		// Handle malformed entries - return what we can
		if len(sshVersionArr) > 0 {
			sshVersion = sshVersionArr[0]
		}
		if len(firstSplit) > 1 {
			os = firstSplit[len(firstSplit)-1]
		}
		return sshVersion, product, version, os
	}

	// Now safe to access sshVersionArr[1]
	vendorVersion := strings.Split(sshVersionArr[1], " ")

	if len(firstSplit) > 1 {
		os = firstSplit[len(firstSplit)-1]

		// Check bounds before accessing vendorVersion elements
		if len(vendorVersion) > 0 {
			product = vendorVersion[0]
		}
		if len(vendorVersion) > 1 {
			version = vendorVersion[1]
		}

		return sshVersionArr[0], product, version, os
	}

	// Check bounds before accessing vendorVersion elements
	if len(vendorVersion) > 0 {
		product = vendorVersion[0]
	}
	if len(vendorVersion) > 1 {
		version = vendorVersion[1]
	}

	return sshVersionArr[0], product, version, os
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

// buildAlgorithmsString creates a summary of the SSH algorithms from KexInit
func buildAlgorithmsString(init KexInitMsg) string {
	var b strings.Builder

	b.WriteString("kex:")
	b.WriteString(strings.Join(init.KexAlgos, ","))
	b.WriteString(";ciphers:")
	b.WriteString(strings.Join(init.CiphersClientServer, ","))
	b.WriteString(";macs:")
	b.WriteString(strings.Join(init.MACsClientServer, ","))
	b.WriteString(";compression:")
	b.WriteString(strings.Join(init.CompressionClientServer, ","))

	return b.String()
}

// weakKexAlgorithms contains key exchange algorithms considered weak
var weakKexAlgorithms = map[string]bool{
	"diffie-hellman-group1-sha1":         true,
	"diffie-hellman-group14-sha1":        true,
	"diffie-hellman-group-exchange-sha1": true,
}

// weakCiphers contains encryption ciphers considered weak
var weakCiphers = map[string]bool{
	"3des-cbc":     true,
	"arcfour":      true,
	"arcfour128":   true,
	"arcfour256":   true,
	"blowfish-cbc": true,
	"cast128-cbc":  true,
	"aes128-cbc":   true, // CBC mode is weak
	"aes192-cbc":   true,
	"aes256-cbc":   true,
}

// weakMACs contains MAC algorithms considered weak
var weakMACs = map[string]bool{
	"hmac-md5":     true,
	"hmac-md5-96":  true,
	"hmac-sha1":    true,
	"hmac-sha1-96": true,
}

// hasWeakKex checks if any offered key exchange algorithm is weak
func hasWeakKex(kexAlgos []string) bool {
	for _, kex := range kexAlgos {
		if weakKexAlgorithms[kex] {
			return true
		}
	}
	return false
}

// hasWeakCipher checks if any offered cipher is weak
func hasWeakCipher(ciphers []string) bool {
	for _, cipher := range ciphers {
		if weakCiphers[cipher] {
			return true
		}
	}
	return false
}

// hasWeakMAC checks if any offered MAC algorithm is weak
func hasWeakMAC(macs []string) bool {
	for _, mac := range macs {
		if weakMACs[mac] {
			return true
		}
	}
	return false
}

// extractSoftwareVersion extracts the software version from SSH ident string
func extractSoftwareVersion(ident string) string {
	// SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
	// Extract the part after SSH-x.x-
	parts := strings.SplitN(ident, "-", 3)
	if len(parts) >= 3 {
		// Return everything after SSH-2.0-
		return parts[2]
	}
	return ""
}

// guessOS attempts to guess the OS from the SSH ident string
func guessOS(ident string) string {
	identLower := strings.ToLower(ident)

	if strings.Contains(identLower, "ubuntu") {
		return "Ubuntu Linux"
	} else if strings.Contains(identLower, "debian") {
		return "Debian Linux"
	} else if strings.Contains(identLower, "centos") || strings.Contains(identLower, "rhel") || strings.Contains(identLower, "red hat") {
		return "Red Hat/CentOS Linux"
	} else if strings.Contains(identLower, "freebsd") {
		return "FreeBSD"
	} else if strings.Contains(identLower, "windows") {
		return "Windows"
	} else if strings.Contains(identLower, "cisco") {
		return "Cisco IOS"
	} else if strings.Contains(identLower, "dropbear") {
		return "Embedded Linux"
	} else if strings.Contains(identLower, "openssh") {
		// Generic OpenSSH - likely Unix/Linux
		return "Unix/Linux"
	}
	return ""
}
