package evidence

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/gopacket/gopacket/pcapgo"
)

type CaptureInspection struct {
	Version          int         `json:"version"`
	SourceSHA256     string      `json:"sourceSHA256"`
	SourceBytes      string      `json:"sourceBytes"`
	Format           string      `json:"format"`
	Compression      string      `json:"compression"`
	Packets          uint64      `json:"packets,string"`
	CapturedBytes    uint64      `json:"capturedBytes,string"`
	WireBytes        uint64      `json:"wireBytes,string"`
	TruncatedPackets uint64      `json:"truncatedPackets,string"`
	FirstNs          string      `json:"firstNs,omitempty"`
	LastNs           string      `json:"lastNs,omitempty"`
	OutOfOrder       bool        `json:"outOfOrder"`
	Interfaces       []Interface `json:"interfaces"`
	Limitations      []string    `json:"limitations"`
}

func InspectCapture(ctx context.Context, path string, maxPackets int, maxBytes int64) (CaptureInspection, error) {
	result := CaptureInspection{Version: 1, Compression: "none", Interfaces: []Interface{}, Limitations: []string{"Capture clock is uncorrected; interface metadata is source-provided", "Counts cover the original stored capture, not inferred application transactions"}}
	if maxPackets < 1 || maxPackets > 1000000 || maxBytes < 1 || maxBytes > 1<<30 {
		return result, fmt.Errorf("invalid inspection bounds")
	}
	f, before, err := artifactio.Open(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return result, err
	}
	defer f.Close()
	if before.Size() > maxBytes {
		return result, fmt.Errorf("stored capture byte limit exceeded")
	}
	result.SourceBytes = strconv.FormatInt(before.Size(), 10)
	hash := sha256.New()
	raw := bufio.NewReader(io.TeeReader(&inspectionReader{ctx: ctx, input: f, remaining: maxBytes}, hash))
	magic, err := raw.Peek(4)
	if err != nil {
		return result, err
	}
	var input io.Reader = raw
	if magic[0] == 0x1f && magic[1] == 0x8b {
		z, e := gzip.NewReader(raw)
		if e != nil {
			return result, e
		}
		defer z.Close()
		input = z
		result.Compression = "gzip"
	}
	decoded := bufio.NewReader(&inspectionReader{ctx: ctx, input: input, remaining: maxBytes})
	magic, err = decoded.Peek(4)
	if err != nil {
		return result, err
	}
	var reader packetReader
	var ng *pcapgo.NgReader
	var legacy *pcapgo.Reader
	section := 0
	if binary.BigEndian.Uint32(magic) == 0x0a0d0d0a {
		result.Format = "pcapng"
		ng, err = pcapgo.NewNgReader(&guardedNGReader{input: decoded}, pcapgo.NgReaderOptions{WantMixedLinkType: true, SectionEndCallback: func(_ []pcapgo.NgInterface, _ pcapgo.NgSectionInfo) { section++ }})
		reader = ng
	} else {
		result.Format = "pcap"
		legacy, err = pcapgo.NewReader(decoded)
		if err == nil && legacy.Snaplen() > maxCapturedPacket {
			legacy.SetSnaplen(maxCapturedPacket)
		}
		reader = legacy
	}
	if err != nil {
		return result, err
	}
	interfaces := map[[2]int]bool{}
	var previous, minTime, maxTime int64
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		_, ci, e := reader.ReadPacketData()
		if e == io.EOF {
			break
		}
		if e != nil {
			return result, e
		}
		if result.Packets >= uint64(maxPackets) {
			return result, fmt.Errorf("inspection packet limit exceeded")
		}
		at := ci.Timestamp.UnixNano()
		if !time.Unix(0, at).Equal(ci.Timestamp) {
			return result, fmt.Errorf("capture timestamp is outside signed Unix nanoseconds")
		}
		if result.Packets == 0 {
			minTime, maxTime = at, at
		} else {
			if at < previous {
				result.OutOfOrder = true
			}
			if at < minTime {
				minTime = at
			}
			if at > maxTime {
				maxTime = at
			}
		}
		previous = at
		if ci.CaptureLength < 0 || ci.Length < ci.CaptureLength {
			return result, fmt.Errorf("invalid packet lengths")
		}
		result.Packets++
		result.CapturedBytes += uint64(ci.CaptureLength)
		result.WireBytes += uint64(ci.Length)
		if ci.Length > ci.CaptureLength {
			result.TruncatedPackets++
		}
		key := [2]int{section, ci.InterfaceIndex}
		if !interfaces[key] {
			var intf pcapgo.NgInterface
			if ng != nil {
				intf, e = ng.Interface(ci.InterfaceIndex)
				if e != nil {
					return result, e
				}
			} else {
				intf = pcapgo.DefaultNgInterface
				intf.LinkType = legacy.LinkType()
				intf.SnapLength = legacy.Snaplen()
			}
			result.Interfaces = append(result.Interfaces, Interface{Section: section, SourceIndex: ci.InterfaceIndex, OutputIndex: len(result.Interfaces), Metadata: intf})
			interfaces[key] = true
			if len(interfaces) > 256 {
				return result, fmt.Errorf("inspection interface limit exceeded")
			}
		}
	}
	if result.Packets > 0 {
		result.FirstNs = strconv.FormatInt(minTime, 10)
		result.LastNs = strconv.FormatInt(maxTime, 10)
	}
	// Read compressed trailers and remaining raw bytes into the source identity.
	if _, err = io.Copy(io.Discard, decoded); err != nil {
		return result, err
	}
	if _, err = io.Copy(io.Discard, raw); err != nil {
		return result, err
	}
	after, err := f.Stat()
	if err != nil {
		return result, err
	}
	current, _, err := artifactio.Open(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return result, err
	}
	defer current.Close()
	info, err := current.Stat()
	if err != nil {
		return result, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, info) {
		return result, fmt.Errorf("inspection source changed")
	}
	result.SourceSHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

type inspectionReader struct {
	ctx       context.Context
	input     io.Reader
	remaining int64
}

func (r *inspectionReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if r.remaining <= 0 {
		var b [1]byte
		n, e := r.input.Read(b[:])
		if n > 0 {
			return 0, fmt.Errorf("inspection byte limit exceeded")
		}
		return 0, e
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, e := r.input.Read(p)
	r.remaining -= int64(n)
	return n, e
}
