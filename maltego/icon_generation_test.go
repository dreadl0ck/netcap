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

//go:build assets

package maltego_test

import (
	"testing"

	"github.com/dreadl0ck/maltego"

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
