//go:build !ja4plus

package http

import "bufio"

func extractHeaderOrderFromReader(*bufio.Reader) ([]string, []string, string) {
	return nil, nil, ""
}
