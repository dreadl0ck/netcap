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

package label

import (
	"os"

	"github.com/namsral/flag"
)

// Flags returns all flags.
func Flags() (flags []string) {
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, f.Name)
	})

	return
}

var (
	fs                 = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenerateConfig = fs.Bool("gen-config", false, "generate config")
	_                  = fs.String("config", "", "read configuration from file at path")
	flagDebug          = fs.Bool("debug", false, "toggle debug mode")
	flagInput          = fs.String("read", "", "use specified pcap file to scan with suricata")
	flagSeparator      = fs.String("sep", ",", "set separator string for csv output")
	flagOutDir         = fs.String("out", "", "specify output directory, will be created if it does not exist")

	flagDescription           = fs.Bool("description", false, "use attack description instead of classification for labels")
	flagProgressBars          = fs.Bool("progress", false, "use progress bars")
	flagStopOnDuplicateLabels = fs.Bool("strict", false, "fail when there is more than one alert for the same timestamp")
	flagExcludeLabels         = fs.String("exclude", "", "specify a comma separated list of suricata classifications that shall be excluded from the generated labeled csv")
	flagCollectLabels         = fs.Bool("collect", false, "append classifications from alert with duplicate timestamps to the generated label")
	flagDisableLayerMapping   = fs.Bool("disable-layers", false, "do not map layer types by timestamp")
	flagSuricataConfigPath    = fs.String("suricata-config", "/usr/local/etc/suricata/suricata.yaml", "set the path to the suricata config file")
	flagCustom                = fs.String("custom", "", "use custom mappings at path")

	// this wont work currently, because the Select() func will stop if there are fields that are not present on an audit record
	// as labeling iterates over all available records, there will always be a record that does not have all selected fields
	// TODO: create a func that ignores fields that do not exist on the target audit record, maybe Select() and SelectStrict()
	// flagSelect    = flag.String("select", "", "select specific fields of an audit records when generating csv or tables").
)
