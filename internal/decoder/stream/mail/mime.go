package mail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	stdmail "net/mail"
	"net/textproto"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/types"
)

type mimeAttachment struct {
	part  *types.MailPart
	data  []byte
	depth int
	err   error
}

func parseMIMEMessage(buf []byte) (map[string]string, []*types.MailPart, []mimeAttachment, func(), error) {
	releases := []func(){}
	cleanup := func() {
		for _, r := range releases {
			r()
		}
	}
	message, err := stdmail.ReadMessage(bytes.NewReader(buf))
	if err != nil {
		return nil, nil, nil, cleanup, err
	}
	headers := map[string]string{}
	for k, v := range message.Header {
		headers[k] = strings.Join(v, ", ")
	}
	headers["CC"] = message.Header.Get("Cc")
	headers["x-originating-ip"] = message.Header.Get("X-Originating-IP")
	var parts []*types.MailPart
	var attachments []mimeAttachment
	var used int64
	count := 0
	var visit func(textproto.MIMEHeader, io.Reader, int) error
	visit = func(header textproto.MIMEHeader, r io.Reader, depth int) error {
		count++
		if depth > 8 || count > 128 {
			return fmt.Errorf("MIME nesting/part budget exceeded")
		}
		typ, params, err := mime.ParseMediaType(header.Get("Content-Type"))
		if err != nil && header.Get("Content-Type") != "" {
			return err
		}
		if typ == "" {
			typ = "text/plain"
		}
		if strings.HasPrefix(typ, "multipart/") {
			if params["boundary"] == "" {
				return fmt.Errorf("missing MIME boundary")
			}
			reader := multipart.NewReader(r, params["boundary"])
			for {
				part, e := reader.NextRawPart()
				if e == io.EOF {
					return nil
				}
				if e != nil {
					return e
				}
				if e = visit(part.Header, part, depth+1); e != nil {
					return e
				}
			}
		}
		if used >= file.GetMaxFileSize() {
			return fmt.Errorf("MIME aggregate byte budget exceeded")
		}
		wire, release, e := file.ReadBodyLimit(r, file.GetMaxFileSize()-used)
		releases = append(releases, release)
		used += int64(len(wire))
		if used > file.GetMaxFileSize() {
			return fmt.Errorf("MIME aggregate byte budget exceeded")
		}
		content := wire
		encoding := strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding")))
		var decoded io.Reader
		switch encoding {
		case "", "7bit", "8bit", "binary":
		case "base64":
			decoded = base64.NewDecoder(base64.StdEncoding, bytes.NewReader(wire))
		case "quoted-printable":
			decoded = quotedprintable.NewReader(bytes.NewReader(wire))
		default:
			return fmt.Errorf("unsupported MIME transfer encoding %q", encoding)
		}
		if decoded != nil {
			if used >= file.GetMaxFileSize() {
				return fmt.Errorf("MIME aggregate byte budget exceeded")
			}
			var rr func()
			var decodeErr error
			content, rr, decodeErr = file.ReadBodyLimit(decoded, file.GetMaxFileSize()-used)
			releases = append(releases, rr)
			used += int64(len(content))
			if e == nil {
				e = decodeErr
			}
		}
		disposition, dparams, de := mime.ParseMediaType(header.Get("Content-Disposition"))
		if de != nil && header.Get("Content-Disposition") != "" {
			return de
		}
		name := dparams["filename"]
		if name == "" {
			name = params["name"]
		}
		fields := map[string]string{}
		for k, v := range header {
			fields[k] = strings.Join(v, ", ")
		}
		part := &types.MailPart{ID: fmt.Sprintf("mime-%d", count), Filename: name, Header: fields, Content: strings.ToValidUTF8(string(wire), "�")}
		parts = append(parts, part)
		if disposition == "attachment" || name != "" {
			attachments = append(attachments, mimeAttachment{part, content, depth, e})
		}
		return e
	}
	err = visit(textproto.MIMEHeader(message.Header), message.Body, 0)
	return headers, parts, attachments, cleanup, err
}
