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

package webui

import (
	"github.com/go-echarts/go-echarts/v2/opts"
	echartstypes "github.com/go-echarts/go-echarts/v2/types"
)

// getDefaultChartInit returns default initialization options for all charts
// with local assets host configuration to avoid loading from external CDN
func getDefaultChartInit() opts.Initialization {
	return opts.Initialization{
		Width:           "100%",
		Height:          "100%",
		Theme:           echartstypes.ThemeMacarons,
		BackgroundColor: "#1e1e1e",
		AssetsHost:      "/static/echarts/", // Serve from local backend
	}
}

// getDefaultChartInitWithTheme returns initialization options with custom theme
func getDefaultChartInitWithTheme(theme string) opts.Initialization {
	return opts.Initialization{
		Width:           "100%",
		Height:          "100%",
		Theme:           theme,
		BackgroundColor: "#1e1e1e",
		AssetsHost:      "/static/echarts/", // Serve from local backend
	}
}

