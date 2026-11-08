package webui

import (
	"encoding/json"
	"fmt"
)

type RenderedChartCoverage struct {
	Basis            string `json:"basis"`
	Selection        string `json:"selection"`
	PointLimit       int    `json:"pointLimit"`
	RenderedValues   int    `json:"renderedValues"`
	ValuesKnown      bool   `json:"valuesKnown"`
	SourcesRequested int    `json:"sourcesRequested"`
	SourcesRead      int    `json:"sourcesRead"`
	AbsentSources    int    `json:"absentSources"`
	LimitReached     bool   `json:"limitReached"`
	TruncatedLabels  int    `json:"truncatedLabels"`
}

func (c RenderedChartCoverage) Header() string { data, _ := json.Marshal(c); return string(data) }
func (c RenderedChartCoverage) Text() string {
	if !c.ValuesKnown {
		return fmt.Sprintf("Retained audit records · %s\nRendered counts and truncation not reported; configured cap %d\nSources read %d/%d; no wire-volume inference", c.Selection, c.PointLimit, c.SourcesRead, c.SourcesRequested)
	}
	return fmt.Sprintf("Retained audit records · %s\nValues %d; cap %d; cap reached %t\nSources read %d/%d; absent %d; truncated labels %d\nCap reached does not measure omitted traffic; rates are derived\nTruncated category labels can merge distinct values", c.Selection, c.RenderedValues, c.PointLimit, c.LimitReached, c.SourcesRead, c.SourcesRequested, c.AbsentSources, c.TruncatedLabels)
}
