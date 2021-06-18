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
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"io"
	"os"
	"sort"
	"time"
)

var instance *LabelManager

type scatterData struct {
	time  time.Time
	value int
}

// decodingErrorSlice implements sort.Interface to sort decodingErrors based on their number of occurrence.
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
			SymbolSize:   10,
			SymbolRotate: 0,
		}
	}
	return items
}

func scatterShowLabel(scatterMap map[time.Time]int) *charts.Scatter {
	scatter := charts.NewScatter()
	scatter.SetGlobalOptions(charts.WithTitleOpts(
		opts.Title{
			Title: "Labels",
		}),
		charts.WithLegendOpts(
			opts.Legend{
				Show: true,
			}),
	)

	var sd scatterDataSlice
	for t, v := range scatterMap {
		sd = append(sd, scatterData{
			time:  t,
			value: v,
		})
	}
	sort.Sort(sd)
	var times []time.Time
	for _, s := range sd {
		times = append(times, s.time)
	}

	//fmt.Println(sd)

	scatter.SetXAxis(times).
		AddSeries("Attack", generateScatterItems(sd)).
		//AddSeries("Normal", generateScatterItems(normal)).
		SetSeriesOptions(charts.WithLabelOpts(
			opts.Label{
				Show:     true,
				Position: "right",
			}),
		)
	return scatter
}

// Render will render the current label manager
func Render() {
	page := components.NewPage()
	page.AddCharts(
		scatterShowLabel(instance.scatterMap),
	)
	f, err := os.Create("scatter.html")
	if err != nil {
		panic(err)
	}
	page.Render(io.MultiWriter(f))
}
