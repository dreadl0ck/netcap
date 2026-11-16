package webui

import "os"

type localUpload struct {
	AnalysisID string
	Filename   string
	RootInfo   os.FileInfo
	InputInfo  os.FileInfo
	OutputInfo os.FileInfo
}
