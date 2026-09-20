//go:build ja4plus

package http

import (
	"bufio"
	"bytes"
	"strings"
)

func extractHeaderOrderFromReader(reader *bufio.Reader) (headerOrder []string, cookieFields []string, acceptLanguage string) {
	peekSizes := []int{1024, 4096, 8192, 16384, 32768}
	var peeked []byte
	for _, size := range peekSizes {
		data, err := reader.Peek(size)
		if err != nil && len(data) == 0 {
			return nil, nil, ""
		}
		peeked = data
		if bytes.Contains(peeked, []byte("\r\n\r\n")) || bytes.Contains(peeked, []byte("\n\n")) || len(data) < size {
			break
		}
	}
	if len(peeked) == 0 {
		return nil, nil, ""
	}

	headerEnd := bytes.Index(peeked, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(peeked, []byte("\n\n"))
		if headerEnd == -1 {
			headerEnd = len(peeked)
		}
	}

	lines := bytes.Split(peeked[:headerEnd], []byte("\n"))
	for _, rawLine := range lines[1:] {
		line := bytes.TrimRight(rawLine, "\r")
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		headerName := string(bytes.TrimSpace(line[:colon]))
		headerValue := string(bytes.TrimSpace(line[colon+1:]))
		headerOrder = append(headerOrder, headerName)
		if strings.EqualFold(headerName, "Cookie") {
			cookieFields = parseCookieFieldNamesFromValue(headerValue)
		}
		if strings.EqualFold(headerName, "Accept-Language") {
			acceptLanguage = headerValue
		}
	}
	return headerOrder, cookieFields, acceptLanguage
}

func parseCookieFieldNamesFromValue(cookieValue string) []string {
	var fields []string
	for pair := range strings.SplitSeq(cookieValue, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if equals := strings.IndexByte(pair, '='); equals > 0 {
			fields = append(fields, strings.TrimSpace(pair[:equals]))
		} else if equals == -1 {
			fields = append(fields, pair)
		}
	}
	return fields
}
