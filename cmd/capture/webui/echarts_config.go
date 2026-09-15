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

package webui

import (
	"github.com/go-echarts/go-echarts/v2/opts"
	echartstypes "github.com/go-echarts/go-echarts/v2/types"
)

var netcapChartColors = []string{
	"#3b82f6",
	"#8b5cf6",
	"#38bdf8",
	"#a78bfa",
	"#34d399",
	"#fbbf24",
}

const netcapWordCloudColor = `function () {
	var colors = ['#3b82f6', '#8b5cf6', '#38bdf8', '#a78bfa', '#34d399', '#fbbf24'];
	return colors[Math.floor(Math.random() * colors.length)];
}`

// getDefaultChartInit returns default initialization options for all charts
// with local assets host configuration to avoid loading from external CDN
func getDefaultChartInit() opts.Initialization {
	return opts.Initialization{
		Width:           "100%",
		Height:          "100%",
		Theme:           echartstypes.ThemeWesteros,
		BackgroundColor: "#050508",
		AssetsHost:      "/static/echarts/", // Serve from local backend
	}
}

// getDefaultChartInitWithTheme returns initialization options with custom theme
func getDefaultChartInitWithTheme(theme string) opts.Initialization {
	return opts.Initialization{
		Width:           "100%",
		Height:          "100%",
		Theme:           theme,
		BackgroundColor: "#050508",
		AssetsHost:      "/static/echarts/", // Serve from local backend
	}
}
