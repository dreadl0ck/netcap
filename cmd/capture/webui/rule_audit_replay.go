package webui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func scanRuleAudit(dir, auditType string, stop, shutdown <-chan struct{}, visit func(types.AuditRecord) error) (int, error) {
	auditType = strings.TrimPrefix(auditType, "NC_")
	want, ok := types.Type_value["NC_"+auditType]
	if !ok {
		return 0, fmt.Errorf("unknown audit type: %s", auditType)
	}
	compressed := true
	f, _, err := artifactio.Open(dir, auditType+".ncap.gz")
	if errors.Is(err, os.ErrNotExist) {
		compressed = false
		f, _, err = artifactio.Open(dir, auditType+".ncap")
	}
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open %s audit: %w", auditType, err)
	}
	reader, err := auditRecordReaderFromFile(f, compressed)
	if err != nil {
		return 0, fmt.Errorf("open %s audit: %w", auditType, err)
	}
	defer reader.Close()
	header, err := reader.ReadHeader()
	if err != nil {
		return 0, fmt.Errorf("read %s audit header: %w", auditType, err)
	}
	if header.Type != types.Type(want) {
		return 0, fmt.Errorf("unexpected audit header type %s for %s", header.Type, auditType)
	}
	var count int
	for {
		select {
		case <-stop:
			return count, errAnalysisStopping
		case <-shutdown:
			return count, errAnalysisStopping
		default:
		}
		record, err := reader.NextRecord()
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, fmt.Errorf("read %s audit record %d: %w", auditType, count+1, err)
		}
		count++
		audit, ok := record.(types.AuditRecord)
		if !ok {
			return count, fmt.Errorf("%s record %d is not an audit record", auditType, count)
		}
		if err := visit(audit); err != nil {
			return count, err
		}
	}
}

func replayRuleAudit(dir, auditType string, stop <-chan struct{}, replay *rules.AuditReplay) (alerts, count int, err error) {
	count, err = scanRuleAudit(dir, auditType, stop, nil, func(record types.AuditRecord) error {
		n, err := replay.Evaluate(record)
		alerts += n
		return err
	})
	if err == nil {
		var final int
		final, err = replay.Finalize()
		alerts += final
	}
	return alerts, count, err
}

var manualRuleSlots = make(chan struct{}, 2)
var errManualRuleCapacity = errors.New("manual rule replay is busy")

func (s *Server) replayManualRules(dir string, selected []*rules.Rule, stop <-chan struct{}) (results []RuleExecResult, err error) {
	select {
	case <-stop:
		return nil, errAnalysisStopping
	case <-s.shutdownChan:
		return nil, errAnalysisStopping
	default:
	}
	select {
	case manualRuleSlots <- struct{}{}:
		defer func() { <-manualRuleSlots }()
	default:
		return nil, errManualRuleCapacity
	}
	release, available := leaseOfflineMutation(dir)
	if !available {
		return nil, fmt.Errorf("capture output is busy")
	}
	defer release()
	writer, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, writer.Close()) }()
	results = make([]RuleExecResult, len(selected))
	engines := make([]*rules.AuditReplay, len(selected))
	groups := make(map[string][]int)
	var order []string
	for i, rule := range selected {
		results[i].RuleName = rule.Name
		typ := strings.TrimPrefix(rule.Type, "NC_")
		if len(groups[typ]) == 0 {
			order = append(order, typ)
		}
		groups[typ] = append(groups[typ], i)
	}
	for _, typ := range order {
		select {
		case <-stop:
			return results, errAnalysisStopping
		case <-s.shutdownChan:
			return results, errAnalysisStopping
		default:
		}
		group := groups[typ]
		start := time.Now()
		var active bool
		for _, i := range group {
			engine, err := rules.NewAuditReplay(&rules.Config{Rules: []*rules.Rule{selected[i]}}, writer)
			if err != nil {
				results[i].Error = err.Error()
				continue
			}
			engines[i], active = engine, true
		}
		if !active {
			continue
		}
		_, scanErr := scanRuleAudit(dir, typ, stop, s.shutdownChan, func(record types.AuditRecord) error {
			for _, i := range group {
				if results[i].Error != "" {
					continue
				}
				results[i].RecordsRead++
				count, err := engines[i].Evaluate(record)
				results[i].AlertsCount += count
				if err != nil {
					results[i].Error = err.Error()
				}
			}
			return nil
		})
		for _, i := range group {
			result := &results[i]
			if result.Error == "" {
				finalErr := scanErr
				if finalErr == nil {
					var count int
					count, finalErr = engines[i].Finalize()
					result.AlertsCount += count
				}
				result.Success = finalErr == nil
				if finalErr != nil {
					result.Error = finalErr.Error()
				}
			}
			result.ExecutionTime = time.Since(start).Milliseconds()
			engines[i] = nil
		}
		if errors.Is(scanErr, errAnalysisStopping) {
			return results, scanErr
		}
	}
	return results, nil
}
