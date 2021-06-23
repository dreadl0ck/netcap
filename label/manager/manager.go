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
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/evilsocket/islazy/tui"
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
	tui.Table(os.Stdout, []string{"Num", "AttackName", "Date", "Victims", "NumAttackers", "MITRE", "category"}, rows)
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
		tui.Table(target, []string{"Category", "Count", "Share"}, rows)
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
