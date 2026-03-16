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
	for i := range values {
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
				Show: opts.Bool(true),
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
				Show:     opts.Bool(true),
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
