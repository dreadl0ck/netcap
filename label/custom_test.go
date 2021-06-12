/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2019 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package label

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"testing"
)

func TestReadIDS2018Labels(t *testing.T) {
	labelMap, labels := parseAttackInfosYAML("configs/cic-ids2018-attacks.yml")

	fmt.Println("=== labelMap")
	spew.Dump(labelMap)

	fmt.Println("=== labels")
	spew.Dump(labels)
}

func TestReadSWAT2019Labels(t *testing.T) {
	labelMap, labels := parseAttackInfosCSV("configs/swat-2019-attacks.csv")

	fmt.Println("=== labelMap")
	spew.Dump(labelMap)

	fmt.Println("=== labels")
	spew.Dump(labels)
}
