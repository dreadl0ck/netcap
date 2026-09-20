//go:build appstore

package webui

import "embed"

// Netcap Pro uses this package's API server but serves its own Wails frontend.
// Excluding Netcap's standalone UI also excludes direct-edition functionality.
//
//go:embed frontend_appstore/index.html
var EmbeddedAssets embed.FS

const embeddedFrontendRoot = "frontend_appstore"
