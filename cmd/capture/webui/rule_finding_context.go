package webui

import (
	"log"
	"strings"

	"github.com/dreadl0ck/netcap/internal/evidencelink"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

type findingContextWriter struct {
	rules.AlertWriter
	index *evidencelink.FindingContext
}

func (w findingContextWriter) WriteAlert(alert *types.Alert) error {
	return w.AlertWriter.WriteAlert(w.index.Enrich(alert))
}

func (s *Server) findingAlertWriter(dir string, stop <-chan struct{}, selected []*rules.Rule, writer rules.AlertWriter) rules.AlertWriter {
	if !s.featureEnabled(featureEvidenceLinks) {
		return writer
	}
	for _, rule := range selected {
		if !rule.Enabled || rule.EffectiveKind() == rules.KindInventory {
			continue
		}
		switch strings.TrimPrefix(rule.Type, "NC_") {
		case "File", "HTTP", "TLSCertificate", "TLSClientHello", "Connection":
			index, err := evidencelink.BuildFindingContext(func(typ string, visit func(types.AuditRecord) error) error {
				_, err := scanRuleAudit(dir, typ, stop, s.shutdownChan, visit)
				return err
			})
			if err != nil {
				log.Printf("[WebUI] Finding context unavailable: %v", err)
				return writer
			}
			return findingContextWriter{writer, index}
		}
	}
	return writer
}
