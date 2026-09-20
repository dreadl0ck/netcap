//go:build !appstore

package webui

import "embed"

// The "all:" prefix includes dotfiles. Build the frontend before compiling.
//
//go:embed all:frontend/dist
var EmbeddedAssets embed.FS

const embeddedFrontendRoot = "frontend/dist"
