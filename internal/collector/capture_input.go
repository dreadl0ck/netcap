package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder/packet"
)

// CaptureInputReport describes input coverage independently of audit counts.
// Issues is bounded; counters include every occurrence, even after it fills.
type CaptureInputReport struct {
	Format            string              `json:"format"`
	Status            string              `json:"status"`
	ReachedEOF        bool                `json:"reachedEOF"`
	CountedPackets    int64               `json:"countedPackets"`
	ProcessedPackets  int64               `json:"processedPackets"`
	SkippedRecords    int64               `json:"skippedRecords"`
	ReadErrors        int64               `json:"readErrors"`
	LinkErrors        int64               `json:"linkErrors"`
	DecodeErrors      int64               `json:"decodeErrors"`
	LinkErrors        int64               `json:"linkErrors"`
	Unsupported       int64               `json:"unsupportedPackets"`
	SnaplenOverrides  int64               `json:"snaplenOverrides"`
	SnapshotTruncated int64               `json:"snapshotTruncatedPackets"`
	Issues            []CaptureInputIssue `json:"issues,omitempty"`
}

type CaptureInputIssue struct {
	Offset      int64  `json:"offset"`
	Kind        string `json:"kind"`
	Reason      string `json:"reason"`
	Recoverable bool   `json:"recoverable"`
}

type CaptureInputError struct{ Report CaptureInputReport }

func (e *CaptureInputError) Error() string {
	message := fmt.Sprintf("capture input %s: processed=%d skipped=%d read-errors=%d link-errors=%d decode-errors=%d unsupported=%d", e.Report.Status, e.Report.ProcessedPackets, e.Report.SkippedRecords, e.Report.ReadErrors, e.Report.LinkErrors, e.Report.DecodeErrors, e.Report.Unsupported)
	if len(e.Report.Issues) > 0 {
		message += fmt.Sprintf("; offset %d: %s", e.Report.Issues[0].Offset, e.Report.Issues[0].Reason)
	}
	return message
}

func (r *CaptureInputReport) issue(offset int64, kind, reason string, recoverable bool) {
	if len(r.Issues) < 16 {
		r.Issues = append(r.Issues, CaptureInputIssue{Offset: offset, Kind: kind, Reason: reason, Recoverable: recoverable})
	}
}

func (r *CaptureInputReport) result() error {
	r.Status = "complete"
	if !r.ReachedEOF {
		r.Status = "stopped"
	}
	if r.SnapshotTruncated > 0 {
		r.Status = "partial"
	}
	if r.Unsupported > 0 {
		r.Status = "unsupported"
	}
	if r.ReadErrors > 0 || r.LinkErrors > 0 {
		r.Status = "partial"
		if r.ProcessedPackets == 0 {
			r.Status = "error"
		}
	}
	if r.ReadErrors+r.LinkErrors+r.Unsupported > 0 {
		return &CaptureInputError{Report: *r}
	}
	return nil
}

func openCaptureInput(path string, ng bool) (captureReader, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	var r captureReader
	if ng {
		r, err = newBoundedNGReader(f)
	} else {
		r, err = newBoundedPCAPReader(f)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, enhancePcapError(path, err)
	}
	return r, f, nil
}

// Both passes use this loop. Only a fully consumed, length-delimited bad record
// is skipped. A short header/payload, oversize PCAP record or conflicting block
// trailer stops at the valid prefix, without searching bytes for another header.
func walkCaptureInput(ctx context.Context, r captureReader, report *CaptureInputReport, visit func([]byte, gopacket.CaptureInfo) bool) {
	for ctx.Err() == nil {
		var data []byte
		var ci gopacket.CaptureInfo
		var err error
		if visit == nil {
			data, ci, err = r.ZeroCopyReadPacketData()
		} else {
			data, ci, err = r.ReadPacketData()
		}
		if err == io.EOF {
			report.ReachedEOF = true
			return
		}
		if err != nil {
			var readErr *captureReadError
			errors.As(err, &readErr)
			offset, recoverable := int64(0), false
			if readErr != nil {
				offset, recoverable = readErr.Offset, readErr.Recoverable
			}
			report.ReadErrors++
			report.issue(offset, "read", err.Error(), recoverable)
			if !recoverable {
				return
			}
			report.SkippedRecords++
			continue
		}
		if visit != nil && !visit(data, ci) {
			return
		}
		report.ProcessedPackets++
		info := inputPacketInfo(ci)
		if info.SnaplenOverride {
			report.SnaplenOverrides++
		}
		if ci.CaptureLength < ci.Length {
			report.SnapshotTruncated++
		}
		if info.NoTimestamp {
			report.Unsupported++
			report.issue(info.Offset, "unsupported", "PCAPNG simple packet has no timestamp; no timestamp inferred", true)
		}
	}
}

func countCaptureInput(ctx context.Context, path string, ng bool) (int64, error) {
	r, f, err := openCaptureInput(path, ng)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	report := CaptureInputReport{}
	walkCaptureInput(ctx, r, &report, nil)
	return report.ProcessedPackets, errors.Join(report.result(), ctx.Err())
}

func (c *Collector) collectCaptureInput(path string, ng bool) (resultErr error) {
	c.captureKind, c.captureSource = "file", path
	defer c.recoverFromPanic()
	ctx, finish, err := c.beginCapture()
	if err != nil {
		return err
	}
	defer func() {
		c.captureRunError = resultErr
		finish()
		c.cleanup(false)
		resultErr = errors.Join(resultErr, c.flowExportError, c.captureEvidenceError, c.artifactAnalysisError)
	}()
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() {
		return fmt.Errorf("capture input must be a regular file")
	}
	c.inputSize = stat.Size()
	count, countErr := countCaptureInput(ctx, path, ng)
	atomic.StoreInt64(&c.numPackets, count)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r, f, err := openCaptureInput(path, ng)
	if err != nil {
		return err
	}
	defer f.Close()
	defer interruptCapture(ctx, ctx, func() { _ = f.Close() })()
	c.captureLinkType = r.LinkType()
	c.config.BaseLayer = linkTypeToLayerType(r.LinkType())
	if c.config.BaseLayer == 0 {
		c.config.BaseLayer = gopacket.LayerTypePayload // Per-packet dispatch reports unsupported links.
	}
	packet.SetBaseLayerType(c.config.BaseLayer)
	if err := c.Init(); err != nil {
		return err
	}
	c.printlnStdOut("counted", count, "readable packets in", path)
	if countErr != nil {
		c.printlnStdOut("counting found incomplete input; processing readable records:", countErr)
	}
	report := CaptureInputReport{Format: "pcap", CountedPackets: count}
	if ng {
		report.Format = "pcapng"
	}
	stopProgress := c.printProgressInterval()
	defer close(stopProgress)
	walkCaptureInput(ctx, r, &report, func(data []byte, ci gopacket.CaptureInfo) bool {
		c.captureLinkType = ci.AncillaryData[0].(layers.LinkType)
		p := c.decodeRawPacketData(data, &ci)
		if failure := p.ErrorLayer(); failure != nil {
			kind := "decode"
			var linkErr *captureLinkError
			if errors.As(failure.Error(), &linkErr) {
				if linkErr.Unsupported {
					report.Unsupported++
					kind = "unsupported"
				} else {
					report.LinkErrors++
					kind = "link"
				}
			} else if p.Layers()[0] == failure || c.captureLinkType == layers.LinkTypeEthernet && p.LinkLayer() == nil {
				report.LinkErrors++
				kind = "link"
			} else {
				// A fully read malformed protocol packet is captured evidence,
				// not a corrupt PCAP record. Retain its parser qualification.
				report.DecodeErrors++
			}
			report.issue(inputPacketInfo(ci).Offset, kind, failure.Error().Error(), true)
		}
		return c.handlePacket(p)
	})
	if report.ReachedEOF && report.ProcessedPackets != count {
		report.ReadErrors++
		report.issue(0, "read", "packet count changed between count and processing passes", false)
	}
	resultErr = errors.Join(report.result(), ctx.Err())
	c.captureInputStatus = report.Status
	c.captureComplete = report.ReachedEOF && resultErr == nil
	data, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(c.config.DecoderConfig.Out, "capture-input.json"), append(data, '\n'), 0600)
	}
	c.printlnStdOut("capture input status:", report.Status, "processed:", report.ProcessedPackets, "skipped:", report.SkippedRecords)
	return errors.Join(resultErr, err)
}
