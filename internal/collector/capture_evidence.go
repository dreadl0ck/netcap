package collector

import (
	"encoding/binary"
	"errors"
	"fmt"

	decoderpacket "github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func (c *Collector) initCaptureEvidence() error {
	if !c.config.CaptureEvidence {
		if c.config.RetainPackets {
			return fmt.Errorf("packet retention requires capture evidence")
		}
		return nil
	}
	kind, source := c.captureKind, c.captureSource
	if kind == "" {
		kind = "live"
		source = "unspecified-library-source"
	}
	directory := c.config.DecoderConfig.Out
	if directory == "" {
		directory = "."
	}
	segment, retention := c.config.PacketSegmentBytes, c.config.PacketRetentionBytes
	if segment == 0 {
		segment = 32 << 20
	}
	if retention == 0 {
		retention = 512 << 20
	}
	manifest, err := evidence.NewCapture(c.runCtx, directory, evidence.CaptureConfig{Kind: kind, Source: source, BPF: c.Bpf, SnapLen: c.config.SnapLen, Workers: c.config.Workers,
		MaxRetainedTCPBytes: c.config.DecoderConfig.MaxRetainedTCPBytes,
		IncludeDecoders:     c.config.DecoderConfig.IncludeDecoders, ExcludeDecoders: c.config.DecoderConfig.ExcludeDecoders, Reassembly: c.config.ReassembleConnections, RetainPackets: c.config.RetainPackets, SegmentBytes: segment, RetentionBytes: retention})
	if err != nil {
		return err
	}
	c.captureEvidence = manifest
	return nil
}

func (c *Collector) observeCaptureEvidence(packet gopacket.Packet) {
	if c.captureEvidence == nil {
		return
	}
	ci := packet.Metadata().CaptureInfo
	if c.config.RetainPackets && ((c.captureLinkType == 239 && inputPacketInfo(ci).Order == binary.BigEndian) || !supportedRetentionTimestamp(ci.Timestamp)) {
		// The evidence segment writer always emits little-endian, timestamped EPBs.
		// Refuse rather than mislabel native-order NFLOG or invent a timestamp.
		c.captureEvidenceError = fmt.Errorf("packet retention does not support big-endian NFLOG or absent/out-of-range timestamps; retain the original capture")
		return
	}
	var vlans []uint16
	for _, layer := range packet.Layers() {
		if vlan, ok := layer.(*layers.Dot1Q); ok {
			vlans = append(vlans, vlan.VLANIdentifier)
		}
	}
	c.captureEvidence.ObserveScope(decoderpacket.CalcCommunityID(packet), packet.Metadata().CaptureInfo.InterfaceIndex, vlans)
	if err := c.captureEvidence.Observe(packet.Data(), packet.Metadata().CaptureInfo, c.captureLinkType); err != nil {
		c.captureEvidenceError = err
	}
}

func (c *Collector) finalizeCaptureEvidence() {
	if c.captureEvidence == nil {
		return
	}
	c.behaviorHealthMu.Lock()
	stats := c.behaviorCaptureHealth
	c.behaviorHealthMu.Unlock()
	c.captureEvidence.Kernel(stats.KernelReceived, stats.KernelDrops, stats.StatsError)
	status := "stopped"
	if c.captureComplete {
		status = "done"
	}
	if err := c.captureEvidence.Close(status, c.admittedPackets, c.behaviorQueueDrops, errors.Join(c.captureRunError, c.flowExportError, c.captureEvidenceError)); err != nil {
		c.captureEvidenceError = err
	}
}
