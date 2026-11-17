package collector

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
)

type auditClosedWriter struct {
	name string
	size int64
}

func (c *Collector) collectAuditStages(decoders []core.DecoderAPI, closed []auditClosedWriter, finalizers map[string]error) {
	byType := map[string]*evidence.AuditStage{}
	for index, d := range decoders {
		name := strings.TrimPrefix(d.GetType().String(), "NC_")
		stage := byType[name]
		if stage == nil {
			stage = &evidence.AuditStage{Type: name, Stage: "application", State: "sealed", Coverage: "complete", Files: []evidence.SealedAuditFile{}}
			switch d.(type) {
			case *packet.GoPacketDecoder, *packet.Decoder:
				stage.Stage = "packet"
			case *decoder.AbstractDecoder:
				stage.Stage = "aggregate"
			}
			byType[name] = stage
		}
		stage.Records += d.NumRecords()
		if closed[index].size > 0 {
			file := evidence.SealedAuditFile{Name: closed[index].name}
			if !slices.Contains(stage.Files, file) {
				stage.Files = append(stage.Files, file)
			}
		}
		if err := finalizers[d.GetName()]; err != nil {
			stage.State = "failed"
			stage.Reason = boundedStageReason(err)
		}
		if err := netio.WriterError(d.GetWriter()); err != nil {
			stage.State = "failed"
			stage.Reason = boundedStageReason(err)
		}
	}
	c.auditStages = nil
	for _, stage := range byType {
		if stage.Records > 0 && len(stage.Files) == 0 && stage.State == "sealed" {
			stage.State = "unavailable"
			stage.Reason = "writer did not produce a local audit file"
		}
		if c.config.DecoderConfig.Null || c.config.DecoderConfig.CSV || c.config.DecoderConfig.JSON {
			stage.State = "unavailable"
			stage.Reason = "record query sealing requires local protobuf output"
			stage.Files = []evidence.SealedAuditFile{}
		}
		c.auditStages = append(c.auditStages, *stage)
	}
}

func boundedStageReason(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 4096 {
		message = message[:4096]
	}
	return message
}

func (c *Collector) sealAuditStages() error {
	if c.captureEvidence == nil || len(c.auditStages) == 0 {
		return nil
	}
	for index := range c.auditStages {
		stage := &c.auditStages[index]
		if !c.captureComplete || c.captureCoverageError != nil || c.captureRunError != nil {
			stage.Coverage = "partial"
			if stage.Reason == "" {
				stage.Reason = "input coverage is incomplete; consult capture-input.json and capture-manifest.json"
			}
		}
		if stage.Stage != "packet" && c.captureEvidenceError != nil {
			stage.Coverage = "partial"
			if stage.Reason == "" {
				stage.Reason = boundedStageReason(c.captureEvidenceError)
			}
			if stage.Records == 0 && stage.State == "sealed" {
				stage.State = "failed"
			}
		}
		if stage.Stage == "aggregate" && c.config.DecoderConfig.AggregateStore != nil {
			if err := c.config.DecoderConfig.AggregateStore.Error(); err != nil {
				stage.State = "failed"
				stage.Reason = boundedStageReason(err)
			}
		}
	}
	if err := c.captureEvidence.SealAuditStages(c.auditStages); err != nil {
		return fmt.Errorf("seal audit stages: %w", err)
	}
	return nil
}
