package webui

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const localUploadLimit = int64(10 << 30)
const uploadFormOverhead = int64(64 << 10)

type uploadContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r uploadContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// receiveCaptureUpload spools one bounded file without ParseMultipartForm's RAM budget.
// The caller owns closing and removing the returned private temporary file.
func receiveCaptureUpload(w http.ResponseWriter, r *http.Request, limit int64) (file *os.File, header *multipart.FileHeader, err error) {
	if limit <= 0 || limit > localUploadLimit {
		limit = localUploadLimit
	}
	if r.ContentLength > limit+uploadFormOverhead {
		return nil, nil, fmt.Errorf("upload request exceeds %d bytes", limit+uploadFormOverhead)
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit+uploadFormOverhead)
	defer r.Body.Close()
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil && file != nil {
			file.Close()
			os.Remove(file.Name())
			file = nil
		}
	}()
	for {
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return file, nil, nextErr
		}
		if part.FormName() != "file" || file != nil {
			return file, nil, fmt.Errorf("expected exactly one file part")
		}
		filename := sanitizePcapFilename(part.FileName())
		ext := strings.ToLower(filepath.Ext(filename))
		if ext != ".pcap" && ext != ".pcapng" {
			return file, nil, fmt.Errorf("only .pcap and .pcapng files are allowed")
		}
		file, err = os.CreateTemp("", "netcap-upload-*")
		if err != nil {
			return file, nil, err
		}
		written, copyErr := io.Copy(file, uploadContextReader{r.Context(), io.LimitReader(part, limit+1)})
		if copyErr != nil {
			return file, nil, copyErr
		}
		if written == 0 || written > limit {
			return file, nil, fmt.Errorf("capture must contain 1 to %d bytes", limit)
		}
		header = &multipart.FileHeader{Filename: filename, Size: written}
	}
	if file == nil {
		return nil, nil, fmt.Errorf("no file provided")
	}
	if _, err = io.Copy(io.Discard, r.Body); err != nil {
		return file, nil, err
	}
	if err = r.Context().Err(); err != nil {
		return file, nil, err
	}
	_, err = file.Seek(0, io.SeekStart)
	return file, header, err
}
