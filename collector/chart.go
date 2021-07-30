/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package collector

import (
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RenderPacketsPerSecond will render a html chart for the packet ingestion rate of the collector over time.
// Do not call while the collector is running, the access to the pps map is not synchronized.
// If you need runtime metrics, use prometheus.
func (c *Collector) RenderPacketsPerSecond(inputFile string, out string) {

	// discard all file extensions if there are any
	parts := strings.Split(out, ".")
	if len(parts) > 1 {
		out = parts[0]
	}

	log.Println("filename", out)

	page := components.NewPage()
	page.PageTitle = "NETCAP packets per second"
	page.AddCharts(
		renderPPSChart(c.statsInterval, inputFile, c.pps),
	)

	outPath := filepath.Join(out, "pps-line.html")

	// TODO: log might be closed at this point already
	//c.log.Info("rendering throughput chart",
	//	zap.String("inputfile", inputfile),
	//	zap.Int("datapoints", len(c.pps)),
	//	zap.Int("datapoints", len(c.pps)),
	//	zap.String("out", outPath),
	//)
	log.Println("creating pps chart at", outPath)

	// create file
	f, err := os.Create(outPath)
	if err != nil {
		log.Fatal("failed to create output file for line chart: ", err)
	}

	// render data
	err = page.Render(io.MultiWriter(f))
	if err != nil {
		log.Fatal("failed to render label scatter plot", err)
	}

	// close file handle
	_ = f.Close()
}

func renderPPSChart(interval time.Duration, filename string, pps map[time.Time]float64) *charts.Line {
	chart := charts.NewLine()
	chart.SetGlobalOptions(charts.WithTitleOpts(
		opts.Title{
			Title:    "Throughput in packets per second",
			Subtitle: "File " + filename + " in " + interval.String() + " intervals",
		}),
		charts.WithLegendOpts(
			opts.Legend{
				Show: true,
			},
		),
	)

	var data ppsDataSlice
	for t, v := range pps {
		data = append(data, ppsData{
			time:  t,
			value: v,
		})
	}
	sort.Sort(data)

	var times []time.Time
	for _, s := range data {
		times = append(times, s.time)
	}

	chart.SetXAxis(times).
		AddSeries("pps", generateLineItems(data)).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:     true,
				Position: "right",
			}),
			charts.WithLineChartOpts(opts.LineChart{Smooth: true}),
		)

	return chart
}

// generate data for line chart
func generateLineItems(data ppsDataSlice) []opts.LineData {
	items := make([]opts.LineData, 0)
	for _, v := range data {
		items = append(items, opts.LineData{
			Value: v.value,
		})
	}
	return items
}

type ppsData struct {
	time  time.Time
	value float64
}

// ppsDataSlice implements sort.Interface to sort throughput data points based on their timestamp.
type ppsDataSlice []ppsData

// Len will return the length.
func (d ppsDataSlice) Len() int {
	return len(d)
}

// Less will return true if the value at index i is smaller than the other one.
func (d ppsDataSlice) Less(i, j int) bool {
	return d[i].time.Before(d[j].time)
}

// Swap will switch the values.
func (d ppsDataSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
