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
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/table"
)

// Location is the location to use for timestamp parsing and comparison.
var Location = time.Local

// LabelManager keeps track of attack information that shall be mapped onto the audit records.
type LabelManager struct {
	labels   []*attackInfo
	progress bool

	// classificationMap map of classifications.
	classificationMap map[string]int
	excluded          map[string]bool

	// debug mode
	Debug bool

	removeFilesWithoutMatches bool

	// scatter plot
	scatterPlot      bool
	scatterAttackMap map[time.Time]int
	scatterNormalMap map[time.Time]int
	scatterMapMu     sync.Mutex
	scatterDuration  time.Duration

	labelHits map[string]int64
	sync.Mutex
}

// NewLabelManager returns a new label manager instance.
func NewLabelManager(progress bool, debug bool, removeFilesWithoutMatches bool, scatterplot bool, scatterDuration time.Duration) *LabelManager {
	m := &LabelManager{
		progress:                  progress,
		classificationMap:         make(map[string]int),
		excluded:                  make(map[string]bool),
		Debug:                     debug,
		removeFilesWithoutMatches: removeFilesWithoutMatches,
		scatterPlot:               scatterplot,
		scatterAttackMap:          map[time.Time]int{},
		scatterNormalMap:          map[time.Time]int{},
		scatterDuration:           scatterDuration,
		labelHits:                 map[string]int64{},
	}
	instance = m
	return m
}

// Init will load the attack information from disk.
func (m *LabelManager) Init(pathMappingInfo string) {

	_, m.labels = m.parseAttackInfosYAML(pathMappingInfo)
	if len(m.labels) == 0 {
		fmt.Println("no labels found.")
		os.Exit(1)
	}

	var rows [][]string
	for i, c := range m.labels {
		y, m, d := c.Date.Date()
		rows = append(rows, []string{strconv.Itoa(i + 1), c.Name, fmt.Sprintf("%d-%d-%d", y, m, d), strconv.Itoa(len(c.Victims)), strconv.Itoa(len(c.Attackers)), c.MITRE, c.Category})
	}

	// print alert summary
	table.Render(os.Stdout, []string{"Num", "AttackName", "Date", "Victims", "NumAttackers", "MITRE", "category"}, rows)
	fmt.Println()
}

func Stats(target io.Writer) {
	if instance != nil {
		var (
			total int64
			rows  [][]string
		)
		for _, num := range instance.labelHits {
			total += num
		}
		for c, num := range instance.labelHits {
			rows = append(rows, []string{c, strconv.FormatInt(num, 10), progress(num, total)})
		}

		// print summary and newline
		table.Render(target, []string{"Category", "Count", "Share"}, rows)
		fmt.Fprintln(target)
	}
}

func ResetStats() {
	if instance != nil {
		instance.labelHits = map[string]int64{}
	}
}

func progress(current, total int64) string {
	percent := (float64(current) / float64(total)) * float64(100)
	return strconv.FormatFloat(percent, 'f', 2, 64) + "%"
}
