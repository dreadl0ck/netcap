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

package maltego_test

import (
	"github.com/dreadl0ck/maltego"
	"testing"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream"

	icongen "github.com/dreadl0ck/material-icon-gen"
)

const (
	svgIconPath = "/tmp/icons/material-icons"
)

// image name to type
var subset = map[string]string{
	"cloud_upload":   "outline",
	"cloud_download": "outline",
	"contact_page":   "outline",
}

// image name to colors
var coloredIcons = map[string][]string{
	"insert_drive_file": colors,
}

var colors = []string{
	"indianred",
	"aquamarine",
	"orangered",
	"crimson",
	"red",
	"coral",
	"slateblue",
	"rebeccapurple",
	"orange",
	"gold",
	"green",
	"thistle",
	"magenta",
	"blueviolet",
	"navy",
	"tomato",
	"indigo",
	"lawngreen",
	"salmon",
	"seagreen",
	"olivedrab",
	"powderblue",
	"olive",
	"dodgerblue",
	"firebrick",
	"steelblue",
	"aqua",
	"skyblue",
	"teal",
	"blue",
	"burlywood",
	"tan",
	"turquoise",
	"rosybrown",
	"sandybrown",
	"goldenrod",
	"peru",
	"royalblue",
	"deepskyblue",
	"chocolate",
	"saddlebrown",
	"sienna",
	"cadetblue",
	"brown",
	"maroon",
	"midnightblue",
}

func TestGenerateAuditRecordIconsSVG(t *testing.T) {

	maltegoSizes := []int{16, 24, 32, 48, 96}

	// generate all icons
	icongen.GenerateIconsSVG(
		svgIconPath,
		icongen.DefaultSvgURL,
		maltegoSizes,
		coloredIcons,
		func(newBase string, color string) {
			maltego.CreateXMLIconFile(newBase + "_" + color)
		},
	)

	// generate a subset of the icons in a different variation
	icongen.GenerateAdditionalIconsSVG(
		svgIconPath,
		maltegoSizes,
		subset,
		func(newBase string, color string) {
			maltego.CreateXMLIconFile(newBase + "_" + color)
		},
	)

	// generate icons for packet decoders
	packet.ApplyActionToPacketDecoders(func(d packet.DecoderAPI) {
		imgBase := icongen.GenerateIconSVG(svgIconPath, d.GetName(), maltegoSizes)
		maltego.CreateXMLIconFile(imgBase + "_black")
	})

	// generate icons for go packet decoders
	packet.ApplyActionToGoPacketDecoders(func(d *packet.GoPacketDecoder) {
		imgBase := icongen.GenerateIconSVG(svgIconPath, d.Layer.String(), maltegoSizes)
		maltego.CreateXMLIconFile(imgBase + "_black")
	})

	// generate icons for stream decoders
	stream.ApplyActionToStreamDecoders(func(d core.StreamDecoderAPI) {
		imgBase := icongen.GenerateIconSVG(svgIconPath, d.GetName(), maltegoSizes)
		maltego.CreateXMLIconFile(imgBase + "_black")
	})

	// generate icons for abstract decoders
	stream.ApplyActionToAbstractDecoders(func(d core.DecoderAPI) {
		imgBase := icongen.GenerateIconSVG(svgIconPath, d.GetName(), maltegoSizes)
		maltego.CreateXMLIconFile(imgBase + "_black")
	})
}
