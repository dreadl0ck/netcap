package tls

import (
	"encoding/binary"
	"io"
	"sort"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	httpdecoder "github.com/dreadl0ck/netcap/internal/decoder/stream/http"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/tlsdecrypt"
)

func captureTLSRecords(fragments core.DataFragments) []tlsdecrypt.Record {
	seen := false
	for _, f := range fragments {
		if d, ok := f.(*core.StreamData); ok && (d.DiscardedBytes > 0 || d.TCPObservation != "" || d.SkippedBytes != 0 && seen) {
			return nil
		}
		seen = seen || len(f.Raw()) > 0
	}
	r, pos := streamutils.FragmentReader(fragments, false)
	var records []tlsdecrypt.Record
	for len(records) < 65536 {
		at := pos.Timestamp()
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			break
		}
		n := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] < 20 || header[0] > 23 || header[1] != 3 || n > 18432 {
			return nil
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil
		}
		records = append(records, tlsdecrypt.Record{Type: header[0], Version: binary.BigEndian.Uint16(header[1:]), Body: body, At: at})
	}
	return records
}

func (h *tlsReader) decryptApplication() {
	if decoderconfig.Instance == nil || decoderconfig.Instance.TLSSecrets.Empty() {
		return
	}
	c := h.conversation
	var directions [2]core.DataFragments
	if c.ClientData != nil || c.ServerData != nil {
		directions[0], directions[1] = c.ClientData, c.ServerData
	} else {
		for _, f := range c.Data {
			side := 0
			if f.Direction() == reassembly.TCPDirServerToClient {
				side = 1
			}
			directions[side] = append(directions[side], f)
		}
	}
	records := [2][]tlsdecrypt.Record{captureTLSRecords(directions[0]), captureTLSRecords(directions[1])}
	session := tlsdecrypt.Handshake(records)
	if session == nil {
		return
	}
	plaintext := session.Decrypt(decoderconfig.Instance.TLSSecrets, records)
	if len(plaintext) == 0 {
		return
	}
	conversation := *c
	conversation.Data, conversation.ClientData, conversation.ServerData = nil, nil, nil
	conversation.TLSDecrypted = true
	if session.ClientSide() == 1 {
		conversation.ClientIP, conversation.ServerIP = c.ServerIP, c.ClientIP
		conversation.ClientPort, conversation.ServerPort = c.ServerPort, c.ClientPort
		conversation.ClientMAC, conversation.ServerMAC = c.ServerMAC, c.ClientMAC
		conversation.FirstClientPacket, conversation.FirstServerPacket = c.FirstServerPacket, c.FirstClientPacket
	}
	sort.SliceStable(plaintext, func(i, j int) bool { return plaintext[i].At < plaintext[j].At })
	var prefix [2][]byte
	for _, p := range plaintext {
		d := &core.StreamData{RawData: p.Data, Dir: reassembly.TCPDirClientToServer}
		d.CaptureInformation.Timestamp = time.Unix(0, p.At)
		side := 0
		if !p.Client {
			side = 1
			d.Dir = reassembly.TCPDirServerToClient
			conversation.ServerData = append(conversation.ServerData, d)
		} else {
			conversation.ClientData = append(conversation.ClientData, d)
		}
		conversation.Data = append(conversation.Data, d)
		n := min(len(p.Data), max(0, 16384-len(prefix[side])))
		prefix[side] = append(prefix[side], p.Data[:n]...)
	}
	if httpdecoder.Decoder.CanDecodeStream(prefix[0], prefix[1]) {
		httpdecoder.Decoder.GetReaderFactory().New(&conversation).Decode()
	}
}
