package mail

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"io"
)

// ReadWireLine preserves line endings and refuses oversized protocol lines.
func ReadWireLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > 64<<10 {
			return "", fmt.Errorf("mail protocol line exceeds 64 KiB")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return string(line), err
		}
		return string(line), nil
	}
}

type dotWireReader struct {
	r       *bufio.Reader
	pending []byte
	done    bool
	failure error
}

func (r *dotWireReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if r.failure != nil {
			return 0, r.failure
		}
		line, err := ReadWireLine(r.r)
		if line == ".\r\n" || line == ".\n" {
			r.done = true
			return 0, io.EOF
		}
		if err != nil {
			r.failure = err
			if err == io.EOF {
				r.failure = io.ErrUnexpectedEOF
			}
		}
		b := []byte(line)
		if bytes.HasPrefix(b, []byte("..")) {
			b = b[1:]
		}
		r.pending = b
		if len(r.pending) == 0 {
			return 0, r.failure
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func ReadDotMessage(r *bufio.Reader) ([]byte, func(), error) {
	return file.ReadBody(&dotWireReader{r: r})
}
