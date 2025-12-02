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
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// readCredentials reads all credentials from the Credentials audit file
func readCredentials(outDir string) ([]CredentialSummary, error) {
	filePath := filepath.Join(outDir, "Credentials"+defaults.FileExtension+".gz")
	log.Printf("[Credentials Chart] Looking for credentials file: %s", filePath)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[Credentials Chart] Credentials file does not exist: %s", filePath)
		return []CredentialSummary{}, nil
	}

	fileInfo, _ := os.Stat(filePath)
	log.Printf("[Credentials Chart] Found credentials file (size: %d bytes)", fileInfo.Size())

	// Open the audit file
	reader, err := netio.Open(filePath, defaults.BufferSize)
	if err != nil {
		log.Printf("[Credentials Chart] ERROR: Failed to open credentials file: %v", err)
		return nil, err
	}
	defer reader.Close()

	// IMPORTANT: Read the netcap file header first!
	_, err = reader.ReadHeader()
	if err != nil {
		log.Printf("[Credentials Chart] ERROR: Failed to read file header: %v", err)
		return nil, err
	}
	log.Printf("[Credentials Chart] File header read successfully, reading records...")

	// Read all credentials
	var credentials []CredentialSummary
	var cred types.Credentials
	recordCount := 0

	for {
		err := reader.Next(&cred)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Credentials Chart] ERROR: Error reading credential record (after %d records): %v", recordCount, err)
				// Check if this is a protobuf schema mismatch error
				if strings.Contains(err.Error(), "wrong wireType") || strings.Contains(err.Error(), "proto:") {
					log.Printf("[Credentials Chart] Protobuf schema mismatch detected - audit file needs to be regenerated")
				}
			}
			break
		}

		recordCount++

		// Skip credentials with empty username AND password - they provide no useful information
		if cred.User == "" && cred.Password == "" {
			continue
		}

		credentials = append(credentials, CredentialSummary{
			Timestamp: cred.Timestamp,
			Service:   cred.Service,
			Flow:      cred.Flow,
			User:      cred.User,
			Password:  cred.Password,
			Notes:     cred.Notes,
		})
	}

	log.Printf("[Credentials Chart] Read %d credential records (filtered from %d total)", len(credentials), recordCount)
	return credentials, nil
}

// generateCredentialsByServiceChart generates a bar chart showing credentials by service
func generateCredentialsByServiceChart(outDir string, showLegend bool) *charts.Bar {
	credentials, err := readCredentials(outDir)
	if err != nil {
		credentials = []CredentialSummary{}
	}

	// Count credentials by service
	serviceCount := make(map[string]int)
	for _, cred := range credentials {
		service := cred.Service
		if service == "" {
			service = "Unknown"
		}
		serviceCount[service]++
	}

	// Sort by count
	type servicePair struct {
		Service string
		Count   int
	}
	var services []servicePair
	for service, count := range serviceCount {
		services = append(services, servicePair{service, count})
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Count > services[j].Count
	})

	// Take top 10
	if len(services) > 10 {
		services = services[:10]
	}

	// Create chart
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Credentials by Service",
			Subtitle: "",
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Count",
			Type: "value",
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name: "Service",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show: opts.Bool(showLegend),
		}),
	)

	// Prepare data
	xLabels := make([]string, len(services))
	values := make([]opts.BarData, len(services))
	for i, s := range services {
		xLabels[i] = s.Service
		values[i] = opts.BarData{Value: s.Count}
	}

	bar.SetXAxis(xLabels).AddSeries("Credentials", values)

	return bar
}

// generateCredentialsTimelineChart generates a line chart showing credentials over time
func generateCredentialsTimelineChart(outDir string, showLegend bool) *charts.Line {
	credentials, err := readCredentials(outDir)
	if err != nil || len(credentials) == 0 {
		credentials = []CredentialSummary{}
	}

	// Sort by timestamp
	sort.Slice(credentials, func(i, j int) bool {
		return credentials[i].Timestamp < credentials[j].Timestamp
	})

	// Create time buckets if we have data
	var xLabels []string
	var values []opts.LineData

	if len(credentials) > 0 {
		minTs := credentials[0].Timestamp
		maxTs := credentials[len(credentials)-1].Timestamp
		duration := maxTs - minTs

		// Choose bucket size based on duration
		var bucketSize int64
		var timeFormat string
		if duration > 3600*1e9 { // > 1 hour
			bucketSize = 60 * 1e9 // 1 minute buckets
			timeFormat = "15:04"
		} else if duration > 60*1e9 { // > 1 minute
			bucketSize = 10 * 1e9 // 10 second buckets
			timeFormat = "15:04:05"
		} else {
			bucketSize = 1e9 // 1 second buckets
			timeFormat = "15:04:05"
		}

		// Create buckets
		bucketCount := make(map[int64]int)
		for _, cred := range credentials {
			bucket := (cred.Timestamp / bucketSize) * bucketSize
			bucketCount[bucket]++
		}

		// Sort buckets
		var buckets []int64
		for bucket := range bucketCount {
			buckets = append(buckets, bucket)
		}
		sort.Slice(buckets, func(i, j int) bool {
			return buckets[i] < buckets[j]
		})

		// Prepare data
		xLabels = make([]string, len(buckets))
		values = make([]opts.LineData, len(buckets))
		for i, bucket := range buckets {
			t := time.Unix(0, bucket)
			xLabels[i] = t.Format(timeFormat)
			values[i] = opts.LineData{Value: bucketCount[bucket]}
		}
	}

	// Create chart
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Credentials Timeline",
			Subtitle: "",
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Count",
			Type: "value",
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name: "Time",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show: opts.Bool(showLegend),
		}),
	)

	line.SetXAxis(xLabels).AddSeries("Credentials", values).SetSeriesOptions(
		charts.WithLineChartOpts(opts.LineChart{Smooth: opts.Bool(true)}),
	)

	return line
}

// generateCredentialsUsernamesChart generates a bar chart showing top usernames
func generateCredentialsUsernamesChart(outDir string, showLegend bool) *charts.Bar {
	credentials, err := readCredentials(outDir)
	if err != nil {
		credentials = []CredentialSummary{}
	}

	// Count usernames
	usernameCount := make(map[string]int)
	for _, cred := range credentials {
		username := cred.User
		if username == "" {
			username = "(empty)"
		}
		usernameCount[username]++
	}

	// Sort by count
	type userPair struct {
		Username string
		Count    int
	}
	var usernames []userPair
	for username, count := range usernameCount {
		usernames = append(usernames, userPair{username, count})
	}
	sort.Slice(usernames, func(i, j int) bool {
		return usernames[i].Count > usernames[j].Count
	})

	// Take top 15
	if len(usernames) > 15 {
		usernames = usernames[:15]
	}

	// Create chart
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Usernames",
			Subtitle: "",
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Count",
			Type: "value",
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name: "Username",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show: opts.Bool(showLegend),
		}),
	)

	// Prepare data
	xLabels := make([]string, len(usernames))
	values := make([]opts.BarData, len(usernames))
	for i, u := range usernames {
		// Truncate long usernames for display
		displayName := u.Username
		if len(displayName) > 30 {
			displayName = displayName[:27] + "..."
		}
		xLabels[i] = displayName
		values[i] = opts.BarData{Value: u.Count}
	}

	bar.SetXAxis(xLabels).AddSeries("Count", values)

	return bar
}

// generateCredentialsFlowsChart generates a pie chart showing credentials by flow
func generateCredentialsFlowsChart(outDir string, showLegend bool) *charts.Pie {
	credentials, err := readCredentials(outDir)
	if err != nil {
		credentials = []CredentialSummary{}
	}

	// Count credentials by flow
	flowCount := make(map[string]int)
	for _, cred := range credentials {
		flow := cred.Flow
		if flow == "" {
			flow = "Unknown"
		}
		// Simplify flow for display (extract just IPs if possible)
		parts := strings.Split(flow, " ")
		if len(parts) > 0 {
			flow = parts[0] // Just use first part (usually the connection tuple)
		}
		flowCount[flow]++
	}

	// Sort by count
	type flowPair struct {
		Flow  string
		Count int
	}
	var flows []flowPair
	for flow, count := range flowCount {
		flows = append(flows, flowPair{flow, count})
	}
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].Count > flows[j].Count
	})

	// Take top 10
	if len(flows) > 10 {
		flows = flows[:10]
	}

	// Create chart
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Credentials by Flow",
			Subtitle: "",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "item",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Orient: "vertical",
			Right:  "0%",
			Top:    "15%",
		}),
	)

	// Prepare data
	items := make([]opts.PieData, len(flows))
	for i, f := range flows {
		// Truncate long flow names
		displayName := f.Flow
		if len(displayName) > 40 {
			displayName = displayName[:37] + "..."
		}
		items[i] = opts.PieData{Name: displayName, Value: f.Count}
	}

	pie.AddSeries("Flow", items).SetSeriesOptions(
		charts.WithLabelOpts(opts.Label{
			Show:      opts.Bool(true),
			Formatter: "{b}: {c}",
		}),
	)

	return pie
}
