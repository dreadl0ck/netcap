package webui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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

func (c RenderedChartCoverage) textFor(p Presentation) string {
	lines := []string{p.text("Retained audit records") + " · " + p.text(c.Selection)}
	if !c.ValuesKnown {
		lines = append(lines,
			fmt.Sprintf(p.text("Rendered counts and truncation not reported; configured cap %d"), c.PointLimit),
			fmt.Sprintf(p.text("Sources read %d/%d; no wire-volume inference"), c.SourcesRead, c.SourcesRequested))
	} else {
		lines = append(lines,
			fmt.Sprintf(strings.Replace(p.text("Values %d; cap %d; cap reached %t"), "%t", "%s", 1), c.RenderedValues, c.PointLimit, p.text(strconv.FormatBool(c.LimitReached))),
			fmt.Sprintf(p.text("Sources read %d/%d; absent %d; truncated labels %d"), c.SourcesRead, c.SourcesRequested, c.AbsentSources, c.TruncatedLabels),
			p.text("Cap reached does not measure omitted traffic; rates are derived"), p.text("Truncated category labels can merge distinct values"))
	}
	return strings.Join(lines, "\n")
}

const retainedChartQualification = "Retained audit summaries · sampling/completeness unreported · derived rates, not wire-volume measurements"
const schematicChartQualification = "Schematic protocol relationships · synthesized links, not observed packet parentage · audit counts, not wire volume"

func chartCoverageTexts(coverage *RenderedChartCoverage, schematic bool) map[string]string {
	texts := make(map[string]string, len(presentationLocales))
	for _, locale := range presentationLocales {
		p := Presentation{Locale: locale}
		text := p.text(retainedChartQualification)
		if schematic {
			text = p.text(schematicChartQualification)
		}
		if coverage != nil {
			text = coverage.textFor(p)
			if schematic {
				text += "\n" + p.text(schematicChartQualification)
			}
		}
		texts[locale] = text
	}
	return texts
}
