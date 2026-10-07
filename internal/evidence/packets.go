package evidence

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

// Selection uses an inclusive capture-time window. It does not identify a TCP incarnation.
type Selection struct {
	BPF        string `json:"bpf"`
	StartNs    *int64 `json:"startNs,omitempty,string"`
	EndNs      *int64 `json:"endNs,omitempty,string"`
	MaxPackets int    `json:"maxPackets"`
}

type PacketSpan struct {
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}

type Interface struct {
	Section     int                `json:"section"`
	SourceIndex int                `json:"sourceIndex"`
	OutputIndex int                `json:"outputIndex"`
	Metadata    pcapgo.NgInterface `json:"metadata"`
}

type PacketManifest struct {
	Version                  int          `json:"version"`
	SourceSHA256             string       `json:"sourceSHA256"`
	OutputSHA256             string       `json:"outputSHA256"`
	OutputFormat             string       `json:"outputFormat"`
	Selection                Selection    `json:"selection"`
	SourcePackets            uint64       `json:"sourcePackets"`
	Selected                 uint64       `json:"selectedPackets"`
	PacketSpans              []PacketSpan `json:"sourcePacketSpans"`
	Interfaces               []Interface  `json:"interfaces"`
	Limitations              []string     `json:"limitations"`
	SourceTruncatedPackets   uint64       `json:"sourceTruncatedPackets"`
	SelectedTruncatedPackets uint64       `json:"selectedTruncatedPackets"`
	MaxCapturedPacketBytes   int          `json:"maxCapturedPacketBytes"`
	MaxCaptureBlockBytes     int          `json:"maxCaptureBlockBytes"`
}

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// ExportPackets writes a PCAPNG derivative and hashes the actual input/output bytes.
// Callers must discard output on any error; no partial export is evidence-qualified.
func ExportPackets(ctx context.Context, input string, output io.Writer, selection Selection) (PacketManifest, error) {
	manifest := PacketManifest{Version: 1, OutputFormat: "pcapng", Selection: selection, MaxCapturedPacketBytes: maxCapturedPacket, MaxCaptureBlockBytes: maxCaptureBlock,
		PacketSpans: []PacketSpan{}, Interfaces: []Interface{},
		Limitations: []string{"selection is tuple/time context, not a unique session incarnation", "packet options, source statistics, secrets and name-resolution blocks are not copied; retain the original capture"}}
	if selection.MaxPackets <= 0 || (selection.StartNs == nil) != (selection.EndNs == nil) ||
		(selection.StartNs != nil && *selection.EndNs < *selection.StartNs) {
		return manifest, fmt.Errorf("invalid packet export limits or time range")
	}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	in, err := os.Open(input)
	if err != nil {
		return manifest, err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return manifest, err
	}
	if !before.Mode().IsRegular() {
		return manifest, fmt.Errorf("packet source must be a regular file")
	}
	inputHash, outputHash := sha256.New(), sha256.New()
	buffer := bufio.NewReader(io.TeeReader(in, inputHash))
	magic, err := buffer.Peek(4)
	if err != nil {
		return manifest, fmt.Errorf("capture magic: %w", err)
	}
	var reader packetReader
	var ng *pcapgo.NgReader
	var legacy *pcapgo.Reader
	var legacySnaplen uint32
	section := 0
	if binary.BigEndian.Uint32(magic) == 0x0a0d0d0a {
		ng, err = pcapgo.NewNgReader(&guardedNGReader{input: buffer}, pcapgo.NgReaderOptions{WantMixedLinkType: true,
			SectionEndCallback: func(_ []pcapgo.NgInterface, _ pcapgo.NgSectionInfo) { section++ }})
		reader = ng
	} else {
		legacy, err = pcapgo.NewReader(buffer)
		if err == nil {
			legacySnaplen = legacy.Snaplen()
			if legacySnaplen > maxCapturedPacket {
				legacy.SetSnaplen(maxCapturedPacket)
			}
		}
		reader = legacy
	}
	if err != nil {
		return manifest, fmt.Errorf("capture header: %w", err)
	}
	bpfs := make(map[layers.LinkType]*pcap.BPF)
	interfaceIDs := make(map[[2]int]int)
	var writer *pcapgo.NgWriter
	for {
		if err := ctx.Err(); err != nil {
			return manifest, err
		}
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest, fmt.Errorf("capture packet: %w", err)
		}
		manifest.SourcePackets++
		if ci.Length < ci.CaptureLength {
			return manifest, fmt.Errorf("captured packet is longer than declared wire length")
		}
		if ci.Length > ci.CaptureLength {
			manifest.SourceTruncatedPackets++
		}
		intf := pcapgo.DefaultNgInterface
		if ng != nil {
			intf, err = ng.Interface(ci.InterfaceIndex)
			if err != nil {
				return manifest, err
			}
		} else {
			intf.LinkType, intf.SnapLength = legacy.LinkType(), legacySnaplen
			intf.TimestampResolution = 6
			if legacy.Resolution() == gopacket.TimestampResolutionNanosecond {
				intf.TimestampResolution = 9
			}
		}
		bpf := bpfs[intf.LinkType]
		if bpf == nil {
			compileType := intf.LinkType
			// Capture LINKTYPE_RAW (101) differs from platform-specific DLT_RAW.
			if compileType == layers.LinkTypeRaw {
				dlt := pcap.DatalinkNameToVal("RAW")
				if dlt < 0 || dlt > 255 {
					return manifest, fmt.Errorf("unsupported RAW datalink: %d", dlt)
				}
				compileType = layers.LinkType(dlt)
			}
			bpf, err = pcap.NewBPF(compileType, 262144, selection.BPF)
			if err != nil {
				return manifest, fmt.Errorf("compile packet selection: %w", err)
			}
			bpfs[intf.LinkType] = bpf
		}
		if selection.StartNs != nil && (ci.Timestamp.UnixNano() < *selection.StartNs || ci.Timestamp.UnixNano() > *selection.EndNs) {
			continue
		}
		if !bpf.Matches(ci, data) {
			continue
		}
		if manifest.Selected >= uint64(selection.MaxPackets) {
			return manifest, fmt.Errorf("packet export limit exceeded: %d", selection.MaxPackets)
		}
		key := [2]int{section, ci.InterfaceIndex}
		outputIndex, exists := interfaceIDs[key]
		if !exists {
			outInterface := intf
			// NgWriter emits absolute nanosecond timestamps.
			outInterface.TimestampOffset, outInterface.TimestampResolution = 0, 9
			if writer == nil {
				options := pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "netcap evidence export"}}
				writer, err = pcapgo.NewNgWriterInterface(io.MultiWriter(output, outputHash), outInterface, options)
				outputIndex = 0
			} else {
				outputIndex, err = writer.AddInterface(outInterface)
			}
			if err != nil {
				return manifest, err
			}
			interfaceIDs[key] = outputIndex
			manifest.Interfaces = append(manifest.Interfaces, Interface{Section: section, SourceIndex: ci.InterfaceIndex, OutputIndex: outputIndex, Metadata: intf})
		}
		ci.InterfaceIndex = outputIndex
		if err := writer.WritePacket(ci, data); err != nil {
			return manifest, err
		}
		manifest.Selected++
		if ci.Length > ci.CaptureLength {
			manifest.SelectedTruncatedPackets++
		}
		if n := len(manifest.PacketSpans); n > 0 && manifest.PacketSpans[n-1].Last+1 == manifest.SourcePackets {
			manifest.PacketSpans[n-1].Last = manifest.SourcePackets
		} else {
			manifest.PacketSpans = append(manifest.PacketSpans, PacketSpan{First: manifest.SourcePackets, Last: manifest.SourcePackets})
		}
	}
	if writer != nil {
		if err := writer.Flush(); err != nil {
			return manifest, err
		}
	}
	after, err := in.Stat()
	if err != nil {
		return manifest, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return manifest, fmt.Errorf("packet source changed during export")
	}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	manifest.SourceSHA256 = hex.EncodeToString(inputHash.Sum(nil))
	manifest.OutputSHA256 = hex.EncodeToString(outputHash.Sum(nil))
	return manifest, nil
}
