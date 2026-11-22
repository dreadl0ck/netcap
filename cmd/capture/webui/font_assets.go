package webui

import (
	"net/http"
	"regexp"
)

const chartFontStylesheet = "/static/fonts/noto-sans-sc/index.css"
const chartFontFamily = `Arial, "Noto Sans SC Variable", "PingFang SC", "Microsoft YaHei", "Noto Sans CJK SC", "Noto Sans SC", sans-serif`

var publicFontPath = regexp.MustCompile(`^/static/fonts/noto-sans-sc/(index\.css|LICENSE|noto-sans-sc-[a-z0-9-]+-wght-normal\.woff2)$`)

// Opaque-origin chart frames load fonts without cookies and send Origin: null.
func isPublicFontRequest(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && publicFontPath.MatchString(r.URL.Path)
}
