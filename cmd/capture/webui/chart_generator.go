/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"

	"github.com/dreadl0ck/netcap/defaults"
	netcaptypes "github.com/dreadl0ck/netcap/types"
)

// dataPoint represents a time-series data point
type dataPoint struct {
	time  time.Time
	value float64
}

// kvPair represents a key-value pair for categorical data
type kvPair struct {
	key   string
	value int
}

// ChartGenerator handles chart generation from audit records
type ChartGenerator struct {
	auditType     string
	field         string
	chartType     string
	interval      string
	showLegend    bool
	maxDataPoints int
}

// NewChartGenerator creates a new chart generator
func NewChartGenerator(auditType, field, chartType, interval string, showLegend bool, maxDataPoints int) *ChartGenerator {
	// Default to 1000 if not specified or invalid
	if maxDataPoints <= 0 {
		maxDataPoints = 1000
	}
	return &ChartGenerator{
		auditType:     auditType,
		field:         field,
		chartType:     chartType,
		interval:      interval,
		showLegend:    showLegend,
		maxDataPoints: maxDataPoints,
	}
}

// GenerateChart generates a chart and returns it as HTML
func (cg *ChartGenerator) GenerateChart(outDir string) (io.Reader, error) {
	filePath := filepath.Join(outDir, cg.auditType+defaults.FileExtension+".gz")

	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Determine if field is numeric or string
	isNumeric, err := cg.isFieldNumeric(reader)
	if err != nil {
		return nil, err
	}

	// Reset reader
	reader.Close()
	reader, err = NewAuditRecordReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to reopen audit file: %w", err)
	}
	defer reader.Close()
	_, _ = reader.ReadHeader()

	// Generate appropriate chart based on field type and chart type
	if isNumeric {
		return cg.generateNumericChart(reader)
	}
	return cg.generateCategoricalChart(reader, outDir)
}

// isFieldNumeric checks if the specified field is numeric
// Supports nested field access using dot notation
func (cg *ChartGenerator) isFieldNumeric(reader *AuditRecordReader) (bool, error) {
	msg, err := reader.NextRecord()
	if err != nil {
		return false, fmt.Errorf("failed to read record: %w", err)
	}

	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	// Navigate to the field using dot notation
	field, err := navigateToField(v, cg.field)
	if err != nil {
		return false, err
	}

	switch field.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true, nil
	default:
		return false, nil
	}
}

// generateNumericChart generates charts for numeric fields
func (cg *ChartGenerator) generateNumericChart(reader *AuditRecordReader) (io.Reader, error) {
	var dataPoints []dataPoint

	// If interval is empty or not specified, use all records with actual timestamps
	if cg.interval == "" {
		// Read records up to maxDataPoints and extract field values with actual timestamps
		recordCount := 0
		for recordCount < cg.maxDataPoints {
			msg, err := reader.NextRecord()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read record: %w", err)
			}

			// Get timestamp
			var timestamp int64
			if ar, ok := msg.(netcaptypes.AuditRecord); ok {
				timestamp = ar.Time()
			} else {
				continue
			}

			// Extract field value
			value, err := extractNumericField(msg, cg.field)
			if err != nil {
				continue
			}

			dataPoints = append(dataPoints, dataPoint{
				time:  time.Unix(0, timestamp),
				value: value,
			})
			recordCount++
		}

		if len(dataPoints) == 0 {
			return nil, fmt.Errorf("no records found with valid numeric field %s", cg.field)
		}

		// Sort by timestamp
		sort.Slice(dataPoints, func(i, j int) bool {
			return dataPoints[i].time.Before(dataPoints[j].time)
		})
	} else {
		// Use time bucketing with the specified interval
		duration, err := time.ParseDuration(cg.interval)
		if err != nil {
			return nil, fmt.Errorf("invalid interval: %w", err)
		}

		// Map to aggregate values by time bucket
		timeBuckets := make(map[int64][]float64)

		// Read records up to maxDataPoints and extract field values
		recordCount := 0
		for recordCount < cg.maxDataPoints {
			msg, err := reader.NextRecord()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read record: %w", err)
			}

			// Get timestamp
			var timestamp int64
			if ar, ok := msg.(netcaptypes.AuditRecord); ok {
				timestamp = ar.Time()
			} else {
				continue
			}

			// Extract field value
			value, err := extractNumericField(msg, cg.field)
			if err != nil {
				continue
			}

			// Calculate time bucket
			bucket := (timestamp / int64(duration)) * int64(duration)
			timeBuckets[bucket] = append(timeBuckets[bucket], value)
			recordCount++
		}

		if len(timeBuckets) == 0 {
			return nil, fmt.Errorf("no records found with valid numeric field %s", cg.field)
		}

		// Aggregate buckets and sort by timestamp
		for bucket, values := range timeBuckets {
			var sum float64
			for _, v := range values {
				sum += v
			}
			avg := sum / float64(len(values))
			dataPoints = append(dataPoints, dataPoint{
				time:  time.Unix(0, bucket),
				value: avg,
			})
		}

		sort.Slice(dataPoints, func(i, j int) bool {
			return dataPoints[i].time.Before(dataPoints[j].time)
		})
	}

	// Generate chart based on type
	switch cg.chartType {
	case "line":
		return cg.generateLineChart(dataPoints), nil
	case "bar":
		return cg.generateBarChart(dataPoints), nil
	case "area":
		return cg.generateAreaChart(dataPoints), nil
	case "scatter":
		return cg.generateScatterChart(dataPoints), nil
	case "funnel":
		return cg.generateFunnelChart(dataPoints), nil
	case "radar":
		return cg.generateRadarChart(dataPoints), nil
	default:
		return cg.generateLineChart(dataPoints), nil
	}
}

// generateCategoricalChart generates charts for string/categorical fields
func (cg *ChartGenerator) generateCategoricalChart(reader *AuditRecordReader, outDir string) (io.Reader, error) {
	// Count occurrences of each value
	valueCounts := make(map[string]int)

	recordCount := 0
	for recordCount < cg.maxDataPoints {
		msg, err := reader.NextRecord()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read record: %w", err)
		}

		value, err := extractStringField(msg, cg.field)
		if err != nil {
			continue
		}

		// Limit string length and skip empty values
		if value == "" {
			continue
		}
		if len(value) > 100 {
			value = value[:100] + "..."
		}

		valueCounts[value]++
		recordCount++
	}

	if len(valueCounts) == 0 {
		return nil, fmt.Errorf("no records found with valid field %s", cg.field)
	}

	// Sort by count
	var sorted []kvPair
	for k, v := range valueCounts {
		sorted = append(sorted, kvPair{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].value > sorted[j].value
	})

	// Limit to top 20 categories
	if len(sorted) > 20 {
		sorted = sorted[:20]
	}

	// Generate chart based on type
	switch cg.chartType {
	case "pie":
		return cg.generatePieChart(sorted), nil
	case "bar":
		return cg.generateCategoryBarChart(sorted), nil
	case "wordcloud":
		return cg.generateWordCloudChart(sorted), nil
	case "funnel":
		return cg.generateCategoryFunnelChart(sorted), nil
	case "sankey":
		// Sankey needs to read audit records, so reopen the file
		filePath := filepath.Join(outDir, cg.auditType+defaults.FileExtension+".gz")
		sankeyReader, err := NewAuditRecordReader(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to reopen audit file for sankey: %w", err)
		}
		defer sankeyReader.Close()
		_, _ = sankeyReader.ReadHeader()
		return cg.generateSankeyChart(sankeyReader)
	case "graph":
		return cg.generateGraphChart(sorted), nil
	default:
		return cg.generatePieChart(sorted), nil
	}
}

// generateLineChart generates a line chart
func (cg *ChartGenerator) generateLineChart(dataPoints []dataPoint) io.Reader {
	line := charts.NewLine()

	line.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithDataZoomOpts(opts.DataZoom{
			Type:  "slider",
			Start: 0,
			End:   100,
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{
					Show:  opts.Bool(true),
					Title: "Save as Image",
				},
				DataZoom: &opts.ToolBoxFeatureDataZoom{
					Show:  opts.Bool(true),
					Title: map[string]string{"zoom": "Zoom", "back": "Reset"},
				},
				Restore: &opts.ToolBoxFeatureRestore{
					Show:  opts.Bool(true),
					Title: "Restore",
				},
			},
		}),
	)

	xAxis := make([]string, len(dataPoints))
	yAxis := make([]opts.LineData, len(dataPoints))
	for i, dp := range dataPoints {
		xAxis[i] = dp.time.Format("15:04:05")
		yAxis[i] = opts.LineData{Value: dp.value}
	}

	// Only show labels for small datasets (< 50 points) to avoid clutter
	showLabels := len(dataPoints) < 50

	line.SetXAxis(xAxis).AddSeries(cg.field, yAxis).
		SetSeriesOptions(
			charts.WithLineChartOpts(opts.LineChart{Smooth: opts.Bool(true)}),
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(showLabels),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	// Remove grid lines for cleaner appearance
	line.SetGlobalOptions(
		charts.WithXAxisOpts(opts.XAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
	)

	return renderChartWithFullHeight(line.Render)
}

// generateBarChart generates a bar chart
func (cg *ChartGenerator) generateBarChart(dataPoints []dataPoint) io.Reader {
	bar := charts.NewBar()

	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithDataZoomOpts(opts.DataZoom{
			Type:  "slider",
			Start: 0,
			End:   100,
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	xAxis := make([]string, len(dataPoints))
	yAxis := make([]opts.BarData, len(dataPoints))
	for i, dp := range dataPoints {
		xAxis[i] = dp.time.Format("15:04:05")
		yAxis[i] = opts.BarData{Value: dp.value}
	}

	// Only show labels for small datasets (< 50 points) to avoid clutter
	showLabels := len(dataPoints) < 50

	bar.SetXAxis(xAxis).AddSeries(cg.field, yAxis).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(showLabels),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	// Remove grid lines for cleaner appearance
	bar.SetGlobalOptions(
		charts.WithXAxisOpts(opts.XAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
	)

	return renderChartWithFullHeight(bar.Render)
}

// generateAreaChart generates an area chart
func (cg *ChartGenerator) generateAreaChart(dataPoints []dataPoint) io.Reader {
	line := charts.NewLine()

	line.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "slider", Start: 0, End: 100}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	xAxis := make([]string, len(dataPoints))
	yAxis := make([]opts.LineData, len(dataPoints))
	for i, dp := range dataPoints {
		xAxis[i] = dp.time.Format("15:04:05")
		yAxis[i] = opts.LineData{Value: dp.value}
	}

	// Only show labels for small datasets (< 50 points) to avoid clutter
	showLabels := len(dataPoints) < 50

	line.SetXAxis(xAxis).AddSeries(cg.field, yAxis).
		SetSeriesOptions(
			charts.WithLineChartOpts(opts.LineChart{Smooth: opts.Bool(true)}),
			charts.WithAreaStyleOpts(opts.AreaStyle{Opacity: opts.Float(0.5)}),
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(showLabels),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	// Remove grid lines for cleaner appearance
	line.SetGlobalOptions(
		charts.WithXAxisOpts(opts.XAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
	)

	return renderChartWithFullHeight(line.Render)
}

// generateScatterChart generates a scatter chart
func (cg *ChartGenerator) generateScatterChart(dataPoints []dataPoint) io.Reader {
	scatter := charts.NewScatter()

	scatter.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "slider", Start: 0, End: 100}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	xAxis := make([]string, len(dataPoints))
	yAxis := make([]opts.ScatterData, len(dataPoints))
	for i, dp := range dataPoints {
		xAxis[i] = dp.time.Format("15:04:05")
		yAxis[i] = opts.ScatterData{Value: dp.value}
	}

	// Only show labels for small datasets (< 50 points) to avoid clutter
	showLabels := len(dataPoints) < 50

	scatter.SetXAxis(xAxis).AddSeries(cg.field, yAxis).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(showLabels),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	// Remove grid lines for cleaner appearance
	scatter.SetGlobalOptions(
		charts.WithXAxisOpts(opts.XAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
	)

	return renderChartWithFullHeight(scatter.Render)
}

// generatePieChart generates a pie chart for categorical data
func (cg *ChartGenerator) generatePieChart(data []kvPair) io.Reader {
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s Distribution", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Orient: "vertical",
			Right:  "5%",
			Top:    "15%",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	items := make([]opts.PieData, len(data))
	for i, kv := range data {
		items[i] = opts.PieData{Name: kv.key, Value: kv.value}
	}

	pie.AddSeries("distribution", items).
		SetSeriesOptions(charts.WithLabelOpts(opts.Label{
			Show:       opts.Bool(true),
			Formatter:  "{b}: {c} ({d}%)",
			Color:      "white",
			FontSize:   12,
			FontWeight: "normal",
		}))

	return renderChartWithFullHeight(pie.Render)
}

// generateCategoryBarChart generates a bar chart for categorical data
func (cg *ChartGenerator) generateCategoryBarChart(data []kvPair) io.Reader {
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s Distribution", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	xAxis := make([]string, len(data))
	yAxis := make([]opts.BarData, len(data))
	for i, kv := range data {
		xAxis[i] = kv.key
		yAxis[i] = opts.BarData{Value: kv.value}
	}

	// Only show labels for small datasets (< 20 categories) to avoid clutter
	showLabels := len(data) < 20

	bar.SetXAxis(xAxis).AddSeries(cg.field, yAxis).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(showLabels),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	// Remove grid lines for cleaner appearance
	bar.SetGlobalOptions(
		charts.WithXAxisOpts(opts.XAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			SplitLine: &opts.SplitLine{Show: opts.Bool(false)},
		}),
	)

	return renderChartWithFullHeight(bar.Render)
}

// generateFunnelChart generates a funnel chart for numeric time-series data
func (cg *ChartGenerator) generateFunnelChart(dataPoints []dataPoint) io.Reader {
	funnel := charts.NewFunnel()
	funnel.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s Funnel", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	// Sample data points for funnel (show progression)
	step := 1
	if len(dataPoints) > 10 {
		step = len(dataPoints) / 10
	}

	items := make([]opts.FunnelData, 0)
	for i := 0; i < len(dataPoints); i += step {
		items = append(items, opts.FunnelData{
			Name:  dataPoints[i].time.Format("15:04:05"),
			Value: dataPoints[i].value,
		})
	}

	// Always show labels for funnel charts (they're designed for few items)
	funnel.AddSeries(cg.field, items).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(true),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	return renderChartWithFullHeight(funnel.Render)
}

// generateRadarChart generates a radar chart for multi-dimensional comparison
func (cg *ChartGenerator) generateRadarChart(dataPoints []dataPoint) io.Reader {
	radar := charts.NewRadar()
	radar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s Radar", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	// Create radar indicators (up to 10 time slices)
	indicators := make([]*opts.Indicator, 0)
	step := 1
	if len(dataPoints) > 10 {
		step = len(dataPoints) / 10
	}

	var maxVal float64
	for _, dp := range dataPoints {
		if dp.value > maxVal {
			maxVal = dp.value
		}
	}

	radarData := make([]float64, 0)
	for i := 0; i < len(dataPoints); i += step {
		indicators = append(indicators, &opts.Indicator{
			Name: dataPoints[i].time.Format("15:04"),
			Max:  float32(maxVal * 1.1),
		})
		radarData = append(radarData, dataPoints[i].value)
	}

	radar.AddSeries(cg.field, []opts.RadarData{
		{Value: radarData, Name: cg.field},
	}).
		SetGlobalOptions(
			charts.WithRadarComponentOpts(opts.RadarComponent{
				Indicator: indicators,
				SplitLine: &opts.SplitLine{Show: opts.Bool(true)},
			}),
		)

	return renderChartWithFullHeight(radar.Render)
}

// generateWordCloudChart generates a word cloud for categorical data
func (cg *ChartGenerator) generateWordCloudChart(data []kvPair) io.Reader {
	wc := charts.NewWordCloud()
	wc.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s Word Cloud", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	items := make([]opts.WordCloudData, len(data))
	for i, kv := range data {
		items[i] = opts.WordCloudData{
			Name:  kv.key,
			Value: kv.value,
		}
	}

	wc.AddSeries("wordcloud", items).
		SetSeriesOptions(
			charts.WithWorldCloudChartOpts(opts.WordCloudChart{
				SizeRange: []float32{14, 80},
				Shape:     "circle",
			}),
		)

	return renderChartWithFullHeight(wc.Render)
}

// generateCategoryFunnelChart generates a funnel chart for categorical data
func (cg *ChartGenerator) generateCategoryFunnelChart(data []kvPair) io.Reader {
	funnel := charts.NewFunnel()
	funnel.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s Distribution Funnel", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(cg.showLegend),
			Right:  "10%",
			Top:    "5%",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
				Color:           "white",
				TextBorderWidth: 0,
			},
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	items := make([]opts.FunnelData, len(data))
	for i, kv := range data {
		items[i] = opts.FunnelData{
			Name:  kv.key,
			Value: kv.value,
		}
	}

	// Always show labels for funnel charts (they're designed for few items)
	funnel.AddSeries(cg.field, items).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(true),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	return renderChartWithFullHeight(funnel.Render)
}

// generateSankeyChart generates a sankey diagram for flow visualization
func (cg *ChartGenerator) generateSankeyChart(reader *AuditRecordReader) (io.Reader, error) {
	sankey := charts.NewSankey()
	sankey.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - Flow Diagram", cg.auditType),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	// Extract source/destination relationships from audit records
	type flow struct {
		source string
		target string
		value  int
	}
	flows := make(map[string]*flow)
	nodes := make(map[string]bool)

	// Read records and build flow map
	count := 0
	for count < 1000 { // Limit to 1000 records for performance
		msg, err := reader.NextRecord()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Try to get source and destination from AuditRecord interface
		if ar, ok := msg.(netcaptypes.AuditRecord); ok {
			src := ar.Src()
			dst := ar.Dst()

			if src == "" || dst == "" {
				continue
			}

			// Truncate long addresses
			if len(src) > 40 {
				src = src[:40] + "..."
			}
			if len(dst) > 40 {
				dst = dst[:40] + "..."
			}

			key := src + "->" + dst
			if f, exists := flows[key]; exists {
				f.value++
			} else {
				flows[key] = &flow{source: src, target: dst, value: 1}
			}

			nodes[src] = true
			nodes[dst] = true
			count++
		}
	}

	// Convert to nodes and links
	nodeList := make([]opts.SankeyNode, 0, len(nodes))
	for node := range nodes {
		nodeList = append(nodeList, opts.SankeyNode{Name: node})
	}

	linkList := make([]opts.SankeyLink, 0, len(flows))
	for _, f := range flows {
		linkList = append(linkList, opts.SankeyLink{
			Source: f.source,
			Target: f.target,
			Value:  float32(f.value),
		})
	}

	// Limit to top 50 flows
	if len(linkList) > 50 {
		sort.Slice(linkList, func(i, j int) bool {
			return linkList[i].Value > linkList[j].Value
		})
		linkList = linkList[:50]
	}

	// Always show labels for sankey diagrams (they're designed to show relationships)
	sankey.AddSeries("flows", nodeList, linkList).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(true),
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
			charts.WithLineStyleOpts(opts.LineStyle{Opacity: opts.Float(0.5)}),
		)

	return renderChartWithFullHeight(sankey.Render), nil
}

// generateGraphChart generates a graph/network chart for relationships
func (cg *ChartGenerator) generateGraphChart(data []kvPair) io.Reader {
	graph := charts.NewGraph()
	graph.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInitWithTheme(types.ThemeWesteros)),
		charts.WithTitleOpts(opts.Title{
			Title:    fmt.Sprintf("%s - %s Network Graph", cg.auditType, cg.field),
			Subtitle: "",
			TitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        18,
				FontWeight:      "bold",
				TextBorderWidth: 0,
			},
			SubtitleStyle: &opts.TextStyle{
				Color:           "white",
				FontSize:        12,
				TextBorderWidth: 0,
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(true)}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: opts.Bool(true),
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: opts.Bool(true), Title: "Save"},
			},
		}),
	)

	// Create nodes
	nodes := make([]opts.GraphNode, len(data))
	for i, kv := range data {
		// Node size based on value
		symbolSize := 10 + (float32(kv.value) / float32(data[0].value) * 50)
		if symbolSize > 100 {
			symbolSize = 100
		}

		nodes[i] = opts.GraphNode{
			Name:       kv.key,
			Value:      float32(kv.value),
			SymbolSize: symbolSize,
			Category:   i % 5, // Distribute across 5 categories for coloring
		}
	}

	// Create links between adjacent nodes (for visualization)
	links := make([]opts.GraphLink, 0)
	for i := 0; i < len(nodes)-1; i++ {
		links = append(links, opts.GraphLink{
			Source: nodes[i].Name,
			Target: nodes[i+1].Name,
		})
	}

	// Create categories
	categories := make([]*opts.GraphCategory, 5)
	for i := range 5 {
		categories[i] = &opts.GraphCategory{Name: fmt.Sprintf("Group %d", i+1)}
	}

	// Always show labels for graph charts (they're designed to show relationships)
	graph.AddSeries("graph", nodes, links).
		SetSeriesOptions(
			charts.WithGraphChartOpts(opts.GraphChart{
				Layout:             "circular",
				Roam:               opts.Bool(true),
				FocusNodeAdjacency: opts.Bool(true),
				Categories:         categories,
			}),
			charts.WithLabelOpts(opts.Label{
				Show:       opts.Bool(true),
				Position:   "right",
				Color:      "white",
				FontSize:   12,
				FontWeight: "normal",
			}),
		)

	return renderChartWithFullHeight(graph.Render)
}

// renderChartWithFullHeight renders a go-echarts chart and injects CSS so it fills the iframe
func renderChartWithFullHeight(render func(io.Writer) error) io.Reader {
	html, err := injectFullHeightCSS(render)
	if err == nil {
		return bytes.NewReader(html)
	}

	var buf bytes.Buffer
	if err := render(&buf); err == nil {
		return bytes.NewReader(buf.Bytes())
	}

	fallback := fmt.Sprintf("<html><body><pre>Failed to render chart: %v</pre></body></html>", err)
	return bytes.NewReader([]byte(fallback))
}

// extractStringField extracts a string field value from a message
func extractStringField(msg any, fieldPath string) (string, error) {
	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return "", fmt.Errorf("message is not a struct")
	}

	// Navigate to the field using dot notation
	field, err := navigateToField(v, fieldPath)
	if err != nil {
		return "", err
	}

	switch field.Kind() {
	case reflect.String:
		return field.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", field.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", field.Uint()), nil
	case reflect.Bool:
		return fmt.Sprintf("%t", field.Bool()), nil
	case reflect.Slice:
		if field.Type().Elem().Kind() == reflect.String {
			var strs []string
			for i := 0; i < field.Len(); i++ {
				strs = append(strs, field.Index(i).String())
			}
			return strings.Join(strs, ", "), nil
		}
		return fmt.Sprintf("[%d items]", field.Len()), nil
	default:
		return fmt.Sprintf("%v", field.Interface()), nil
	}
}
