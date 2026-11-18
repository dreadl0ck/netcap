package http

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"golang.org/x/net/http2"
)

var errHTTPSourceCompatibility = errors.New("HTTP mode requires checked compatibility decoding")

func sourceResponseContentType(c *core.ConversationInfo, body *file.BodySpool, encoding string) string {
	if encoding != "gzip" {
		return http.DetectContentType(body.Prefix())
	}
	detected, err := backedGzipContentType(c, body, "")
	if err != nil {
		c.FragmentError = err
	}
	return detected
}

func opaqueSourceRequest(request *http.Request) bool {
	encoding := strings.ToLower(strings.TrimSpace(request.Header.Get(headerContentEncoding)))
	if encoding != "" && encoding != "identity" && request.Header.Get(headerContentEncoding) != "gzip" {
		return false
	}
	typ, _, _ := mime.ParseMediaType(request.Header.Get(headerContentType))
	return typ != "application/json" && !strings.HasSuffix(typ, "+json") && typ != "application/x-www-form-urlencoded" && typ != "multipart/form-data"
}

func backedGzipRequestType(c *core.ConversationInfo, spool *file.BodySpool) (string, error) {
	return backedGzipContentType(c, spool, http.DetectContentType(spool.Prefix()))
}

func backedGzipContentType(c *core.ConversationInfo, spool *file.BodySpool, fallback string) (string, error) {
	const gzipCredits = 65536
	if err := c.StateBudget.Reserve(gzipCredits); err != nil {
		return "", err
	}
	defer c.StateBudget.Release(gzipCredits)
	r, err := gzip.NewReader(spool.Reader())
	if err != nil {
		return fallback, nil
	}
	defer r.Close()
	limit := file.GetMaxFileSize()
	if limit <= 0 || limit > 100<<20 {
		limit = 100 << 20
	}
	bounded := &io.LimitedReader{R: r, N: limit + 1}
	prefix, release, err := readSourceRequestBody(c, bounded)
	defer release()
	if c.FragmentError != nil {
		return "", c.FragmentError
	}
	if err != nil || bounded.N == 0 {
		return fallback, nil
	}
	return http.DetectContentType(prefix), nil
}

func sourceBackedForm(request *http.Request) (media, boundary string) {
	if request.Method != "POST" && request.Method != "PUT" && request.Method != "PATCH" {
		return "", ""
	}
	encoding := strings.ToLower(strings.TrimSpace(request.Header.Get(headerContentEncoding)))
	if encoding != "" && encoding != "identity" {
		return "", ""
	}
	media, params, _ := mime.ParseMediaType(request.Header.Get(headerContentType))
	switch {
	case media == "multipart/form-data":
		return media, params["boundary"]
	case media == "application/json", strings.HasSuffix(media, "+json"):
		return "application/json", ""
	case media == "application/x-www-form-urlencoded":
		return media, ""
	}
	return "", ""
}

func (h *httpReader) parseBackedSmallForm(req *http.Request, spool *file.BodySpool, media string) error {
	size := spool.Size()
	if size > maxJSONFormBytes {
		req.Form, _ = evidenceQuery(req.URL.RawQuery)
		return fmt.Errorf("backed form exceeds 1 MiB")
	}
	// Charge temporary decoding separately from the fields retained for pairing.
	credit := 4096 + 64*size
	urlEncoded := media == "application/x-www-form-urlencoded"
	if urlEncoded {
		credit = 4096 + 2*size // Input plus the string passed to the form parser.
	}
	if err := h.conversation.StateBudget.Reserve(credit); err != nil {
		h.conversation.FragmentError = err
		return err
	}
	defer func() { h.conversation.StateBudget.Release(credit) }()
	body := make([]byte, int(size))
	if _, err := io.ReadFull(spool.Reader(), body); err != nil {
		file.RecordArtifactWriteError(err)
		return err
	}
	if urlEncoded {
		extra := size // Unescaped key and value storage.
		for pair := range bytes.SplitSeq(body, []byte("&")) {
			if len(pair) != 0 {
				extra += 256
			}
		}
		if err := h.conversation.StateBudget.Reserve(extra); err != nil {
			h.conversation.FragmentError = err
			return err
		}
		credit += extra
	}
	parseErr := parseEvidenceForm(req, body)
	var retained int64
	for name, values := range req.PostForm {
		retained += 256 + int64(len(name))
		if urlEncoded {
			retained += 64 * int64(len(values)) // Value slices in both Form and PostForm.
		}
		for _, value := range values {
			retained += int64(len(value))
		}
	}
	if err := h.conversation.StateBudget.Reserve(retained); err != nil {
		h.conversation.FragmentError = err
		return err
	}
	h.sourceHeaderCredits += retained
	return parseErr
}

func sourceRequestBodyLimit() int64 {
	limit := file.GetMaxFileSize()
	if limit <= 0 || limit > 100<<20 {
		return 100 << 20
	}
	return limit
}

type sourceRequestBodyMode uint8

const (
	requestBuffered sourceRequestBodyMode = iota
	requestSpooled
	requestCappedSample
	requestSample
)

func sourceRequestMode(cfg *decoderconfig.Config, req *http.Request, form string) sourceRequestBodyMode {
	if cfg == nil || cfg.IncludePayloads || req.Body == http.NoBody {
		return requestBuffered
	}
	storage := cfg.FileStorage != ""
	if (storage && req.Method == methodPOST) || form != "" || req.Header.Get(headerContentEncoding) == "gzip" {
		return requestSpooled
	}
	if req.ContentLength == 0 && len(req.TransferEncoding) == 0 {
		return requestBuffered
	}
	if storage {
		return requestCappedSample
	}
	return requestSample
}

func readCappedSourceRequestBody(c *core.ConversationInfo, body io.Reader) ([]byte, func(), error) {
	limit := sourceRequestBodyLimit()
	bounded := &io.LimitedReader{R: body, N: limit + 1}
	sample, release, err := readSourceRequestBody(c, bounded)
	if bounded.N == 0 {
		return sample[:min(int64(len(sample)), limit)], release, fmt.Errorf("%w: per-file %d", file.ErrArtifactLimit, limit)
	}
	return sample, release, err
}

func readSourceRequestBody(c *core.ConversationInfo, body io.Reader) (sample []byte, release func(), resultErr error) {
	const scratchSize = 32768
	const sampleSize = 512
	release = func() {}
	if err := c.StateBudget.Reserve(scratchSize + sampleSize); err != nil {
		c.FragmentError = err
		return nil, release, err
	}
	defer c.StateBudget.Release(scratchSize)
	sample = make([]byte, 0, sampleSize)
	var once sync.Once
	release = func() { once.Do(func() { c.StateBudget.Release(sampleSize) }) }
	returned := false
	defer func() {
		if !returned {
			release()
		}
	}()
	sample, resultErr = scanSourceBody(body, make([]byte, scratchSize), sample)
	returned = true
	return sample, release, resultErr
}

func scanSourceBody(body io.Reader, buffer, sample []byte) ([]byte, error) {
	empty := 0
	for {
		n, err := body.Read(buffer)
		if n > 0 {
			sample = append(sample, buffer[:min(n, cap(sample)-len(sample))]...)
			empty = 0
		} else if err == nil {
			empty++
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return sample, err
		}
		if empty >= 100 {
			return sample, io.ErrNoProgress
		}
	}
}

func (h *httpReader) SupportsFragmentSource() bool {
	c := decoderconfig.Instance
	if c == nil || h.conversation.ClientSource == nil || h.conversation.ServerSource == nil {
		return false
	}
	if c.FileStorage != "" {
		extractor, ok := file.GetExtractor("HTTP")
		if !ok {
			return false
		}
		if _, ok := extractor.(*HTTPFileExtractor); !ok {
			return false
		}
	}
	return true
}

func sourceHTTPOrientation(c *core.ConversationInfo) (*core.ConversationInfo, error) {
	const prefixSize = 16384
	var credit int64
	for _, source := range []core.RangedFragmentSource{c.ClientSource, c.ServerSource} {
		if source.Count() > 0 {
			credit += prefixSize
		}
	}
	if err := c.StateBudget.Reserve(credit); err != nil {
		return nil, err
	}
	defer c.StateBudget.Release(credit)
	client, err := core.ReadSourcePrefix(c.ClientSource, prefixSize)
	if err != nil {
		return nil, err
	}
	server, err := core.ReadSourcePrefix(c.ServerSource, prefixSize)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(client, []byte(http2.ClientPreface)) || bytes.HasPrefix(server, []byte(http2.ClientPreface)) {
		return nil, errHTTPSourceCompatibility
	}
	for _, reverse := range []bool{false, true} {
		data := [2][]byte{client, server}
		request, response := 0, 1
		if reverse {
			request, response = 1, 0
		}
		a, b := httpStart(data[request], false), httpStart(data[response], true)
		if a >= 0 && b >= 0 && (a > 0 || b > 0) {
			return nil, errHTTPSourceCompatibility
		}
	}
	copy := *c
	if containsHTTPMethod(server) || containsHTTPProtocolName(client) && !containsHTTPMethod(client) {
		copy.ClientIP, copy.ServerIP = c.ServerIP, c.ClientIP
		copy.ClientPort, copy.ServerPort = c.ServerPort, c.ClientPort
		copy.ClientMAC, copy.ServerMAC = c.ServerMAC, c.ClientMAC
		copy.FirstClientPacket, copy.FirstServerPacket = c.FirstServerPacket, c.FirstClientPacket
		copy.ClientSource, copy.ServerSource = c.ServerSource, c.ClientSource
	}
	return &copy, nil
}

func preflightSourceHTTP(c *core.ConversationInfo) error {
	return streamutils.WalkSourceGapRuns(c.ClientSource, func(source core.RangedFragmentSource, _, _ bool) error {
		return streamutils.WithSourceReader(c, source, false, 16384, func(reader *bufio.Reader, _ *streamutils.ReadPosition) error {
			const scratchSize = 4096
			var scratch []byte
			defer func() { c.StateBudget.Release(int64(len(scratch))) }()
			for {
				_, found := seekHTTPLine(reader, false)
				if !found {
					return nil
				}
				request, evidence, err := readEvidenceRequest(reader)
				if err != nil || evidence.unsafe {
					return nil
				}
				form, _ := sourceBackedForm(request)
				if validH2Upgrade(request) || (request.ContentLength != 0 || len(request.TransferEncoding) > 0) && !opaqueSourceRequest(request) && form == "" {
					return errHTTPSourceCompatibility
				}
				if request.ContentLength != 0 || len(request.TransferEncoding) > 0 {
					if scratch == nil {
						if err := c.StateBudget.Reserve(scratchSize); err != nil {
							return err
						}
						scratch = make([]byte, scratchSize)
					}
					var body io.Reader = request.Body
					var bound *io.LimitedReader
					mode := sourceRequestMode(decoderconfig.Instance, request, form)
					limit := sourceRequestBodyLimit()
					formFallback := mode == requestSpooled && form == "application/x-www-form-urlencoded" && limit > maxJSONFormBytes
					if formFallback {
						bound = &io.LimitedReader{R: body, N: maxJSONFormBytes + 1}
					} else if mode != requestSample {
						bound = &io.LimitedReader{R: body, N: limit + 1}
					}
					if bound != nil {
						body = bound
					}
					_, err := scanSourceBody(body, scratch, nil)
					if bound != nil && bound.N == 0 {
						if formFallback {
							return errHTTPSourceCompatibility
						}
						return nil // The decoder stops this run at the same body limit.
					}
					if err != nil {
						if c.FragmentError != nil {
							return c.FragmentError
						}
						return nil
					}
				}
				_ = request.Body.Close()
			}
		})
	})
}

func (h *httpReader) decodeSource() bool {
	c := h.conversation
	compatible := h.SupportsFragmentSource()
	if compatible {
		err := streamutils.WalkSourceTransportRuns(c, func(run *core.ConversationInfo, _ string) error {
			oriented, err := sourceHTTPOrientation(run)
			if err != nil {
				return err
			}
			return preflightSourceHTTP(oriented)
		})
		if err != nil && !errors.Is(err, errHTTPSourceCompatibility) {
			c.FragmentError = err
			return true
		}
		compatible = err == nil
	}
	if !compatible {
		if c.LoadData == nil {
			c.FragmentError = errHTTPSourceCompatibility
			return true
		}
		if err := c.LoadData(); err != nil {
			c.FragmentError = err
			return true
		}
		return false
	}
	err := streamutils.WalkSourceTransportRuns(c, func(run *core.ConversationInfo, note string) error {
		oriented, err := sourceHTTPOrientation(run)
		if err != nil {
			return err
		}
		reader := &httpReader{conversation: oriented, transportObservation: note, sourceMode: true, unobservedResponseEnd: h.unobservedResponseEnd}
		if decoderconfig.Instance.FileStorage != "" {
			if err := file.PrepareSourceEvidence(oriented); err != nil {
				return err
			}
		}
		reader.decodeTransportRun()
		if h.writeError == nil {
			h.writeError = reader.writeError
		}
		if reader.writeError != nil {
			return reader.writeError
		}
		return oriented.FragmentError
	})
	if err != nil {
		c.FragmentError = err
	}
	return true
}

func (h *httpReader) decodeSourceDirections() {
	for side, source := range []core.RangedFragmentSource{h.conversation.ClientSource, h.conversation.ServerSource} {
		stopDirection := false
		err := streamutils.WalkSourceGapRuns(source, func(chunk core.RangedFragmentSource, lost, unknown bool) error {
			h.initialUnknown = h.initialUnknown || unknown
			h.captureLoss = h.captureLoss || lost
			h.directionBroken[side] = h.directionBroken[side] || lost
			if stopDirection {
				return nil
			}
			parseErr := streamutils.WithSourceReader(h.conversation, chunk, side == 1, 16384, func(reader *bufio.Reader, position *streamutils.ReadPosition) error {
				for {
					skipped, found := seekHTTPLine(reader, side == 1)
					if skipped {
						h.directionBroken[side] = true
						h.pairingQualification = "unpaired_after_unrecognized_bytes"
					}
					if !found {
						return nil
					}
					before := position.Offset()
					var err error
					if side == 0 {
						err = h.readRequest(reader, position)
					} else {
						err = h.readResponse(reader, position)
					}
					if err != nil {
						h.directionBroken[side] = true
						h.pairingQualification = "unpaired_after_parse_error"
						if errors.Is(err, errUnsafeHTTPFraming) {
							h.pairingQualification = "unpaired_after_ambiguous_framing"
						}
						return err
					}
					if position.Offset() == before {
						return nil
					}
					if side == 1 && len(h.responses) > 0 {
						response := h.responses[len(h.responses)-1].response
						if response.StatusCode == 101 || response.Request != nil && response.Request.Method == methodCONNECT && response.StatusCode >= 200 && response.StatusCode < 300 {
							stopDirection = true
							return io.EOF
						}
					}
				}
			})
			if h.conversation.FragmentError != nil {
				return h.conversation.FragmentError
			}
			if errors.Is(parseErr, errUnsafeHTTPFraming) {
				stopDirection = true
			}
			return nil
		})
		if h.conversation.FragmentError != nil {
			return
		}
		if err != nil {
			h.conversation.FragmentError = err
			return
		}
	}
}

func (h *httpReader) retainSourceHeaders(evidence messageEvidence, bytes int) error {
	if !h.sourceMode {
		return nil
	}
	amount := int64(1024 + 8*bytes + 256*len(evidence.headers))
	if bytes < 0 {
		return fmt.Errorf("invalid HTTP header position")
	}
	if err := h.conversation.StateBudget.Reserve(amount); err != nil {
		h.conversation.FragmentError = err
		return err
	}
	h.sourceHeaderCredits += amount
	return nil
}
