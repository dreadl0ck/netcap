package webtech

import "os"

func openCatalogue(root *os.Root) (*os.File, error) { return root.Open(FileName) }
