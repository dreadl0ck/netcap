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
	"os"
	"strconv"
	"time"

	"github.com/evilsocket/islazy/tui"
)

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
}

// NewLabelManager returns a new label manager instance.
func NewLabelManager(progress bool, debug bool, removeFilesWithoutMatches bool) *LabelManager {
	return &LabelManager{
		progress:          progress,
		classificationMap: make(map[string]int),
		excluded:          make(map[string]bool),
		Debug:             debug,
	}
}

// Init will load the attack information from disk.
func (m *LabelManager) Init(pathMappingInfo string) {

	_, m.labels = m.parseAttackInfosYAML(pathMappingInfo)
	if len(m.labels) == 0 {
		fmt.Println("no labels found.")
		os.Exit(1)
	}

	fmt.Println("got", len(m.labels), "labels")

	var rows [][]string
	for i, c := range m.labels {
		y, m, d := c.Date.Date()
		rows = append(rows, []string{strconv.Itoa(i + 1), c.Name, fmt.Sprintf("%d-%d-%d", y, m, d), strconv.Itoa(len(c.Victims)), strconv.Itoa(len(c.Attackers)), c.MITRE, c.Category})
	}

	// print alert summary
	tui.Table(os.Stdout, []string{"Num", "AttackName", "Date", "Victims", "NumAttackers", "MITRE", "category"}, rows)
	fmt.Println()
}
