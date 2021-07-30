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

package manager

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
)

var instance *LabelManager

type scatterData struct {
	time  time.Time
	value int
}

// scatterDataSlice implements sort.Interface to sort scatter data points based on their timestamp.
type scatterDataSlice []scatterData

// Len will return the length.
func (d scatterDataSlice) Len() int {
	return len(d)
}

// Less will return true if the value at index i is smaller than the other one.
func (d scatterDataSlice) Less(i, j int) bool {
	return d[i].time.Before(d[j].time)
}

// Swap will switch the values.
func (d scatterDataSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func generateScatterItems(values []scatterData) []opts.ScatterData {
	items := make([]opts.ScatterData, len(values))
	for i := 0; i < len(values); i++ {
		items[i] = opts.ScatterData{
			Value:        values[i].value,
			Symbol:       "circle",
			SymbolSize:   7,
			SymbolRotate: 0,
		}
	}
	return items
}

func scatterShowLabel(filename string, attacks map[time.Time]int, normal map[time.Time]int) *charts.Scatter {
	scatter := charts.NewScatter()
	scatter.SetGlobalOptions(charts.WithTitleOpts(
		opts.Title{
			Title:    "Labels for " + filename,
			Subtitle: "Displayed is the label count in " + instance.scatterDuration.String() + " intervals",
		}),
		charts.WithLegendOpts(
			opts.Legend{
				Show: true,
			},
		),
	)

	var attackData scatterDataSlice
	for t, v := range attacks {
		attackData = append(attackData, scatterData{
			time:  t,
			value: v,
		})
	}
	sort.Sort(attackData)

	var normalData scatterDataSlice
	for t, v := range normal {
		normalData = append(normalData, scatterData{
			time:  t,
			value: v,
		})
	}
	sort.Sort(normalData)

	var times []time.Time
	for _, s := range normalData {
		times = append(times, s.time)
	}

	scatter.SetXAxis(times).
		AddSeries("Attack", generateScatterItems(attackData)).
		AddSeries("Normal", generateScatterItems(normalData)).
		SetSeriesOptions(charts.WithLabelOpts(
			opts.Label{
				Show:     true,
				Position: "right",
			}),
		)
	return scatter
}

// Render will render the current label manager
func Render(out string) {
	if instance != nil {

		// TODO make configurable
		filename := filepath.Base(out)
		if filename == "" {
			filename = "label"
		}

		// discard all file extensions if there are any
		parts := strings.Split(filename, ".")
		if len(parts) > 1 {
			filename = parts[0]
		}

		page := components.NewPage()
		page.PageTitle = "NETCAP label scatterplot"
		page.AddCharts(
			scatterShowLabel(filename, instance.scatterAttackMap, instance.scatterNormalMap),
		)

		f, err := os.Create(filepath.Join(out, filename+"-scatter.html"))
		if err != nil {
			panic(err)
		}
		err = page.Render(io.MultiWriter(f))
		if err != nil {
			log.Println("failed to render label scatter plot", err)
		}
	}
}
