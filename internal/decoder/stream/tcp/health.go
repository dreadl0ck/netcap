package tcp

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

type ReassemblyHealth struct {
	Version               int      `json:"version"`
	ChecksumPolicy        string   `json:"checksumPolicy"`
	RejectedChecksums     int64    `json:"rejectedChecksums"`
	RejectedIPv4Checksums int64    `json:"rejectedIPv4Checksums"`
	RejectedOptions       int64    `json:"rejectedOptions"`
	RejectedFSM           int64    `json:"rejectedFSM"`
	MissingBytes          int64    `json:"missingBytes"`
	Limitations           []string `json:"limitations"`
}

func WriteReassemblyHealth() error {
	if config.Instance.Out == "" {
		return nil
	}
	h := ReassemblyHealth{Version: 1, ChecksumPolicy: "tolerant", Limitations: []string{"invalid checksum may reflect capture offload; the policy does not identify its cause", "rejected TCP packets remain available in retained packet evidence; no parsed transaction is not proof of no traffic"}}
	h.Limitations = append(h.Limitations, "strict reassembly validates IPv4 header and TCP checksums; packet audit records remain available and UDP checksums are not validated")
	if config.Instance.Checksum {
		h.ChecksumPolicy = "strict"
	}
	streamutils.Stats.Lock()
	h.RejectedChecksums = streamutils.Stats.RejectChecksum
	h.RejectedIPv4Checksums = streamutils.Stats.RejectIPv4Checksum
	h.RejectedOptions = streamutils.Stats.RejectOpt
	h.RejectedFSM = streamutils.Stats.RejectFsm
	h.MissingBytes = streamutils.Stats.MissedBytes
	streamutils.Stats.Unlock()
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(config.Instance.Out, "TCPReassemblyHealth.json"), b, 0600)
}

func validIPv4Checksum(header []byte) bool {
	if len(header) < 20 || len(header)%2 != 0 {
		return false
	}
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}
