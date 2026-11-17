package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"golang.org/x/net/http2"
)

var errHTTPSourceCompatibility = errors.New("HTTP mode requires checked compatibility decoding")

func opaqueSourceRequest(request *http.Request) bool {
	encoding := strings.ToLower(strings.TrimSpace(request.Header.Get(headerContentEncoding)))
	if encoding != "" && encoding != "identity" {
		return false
	}
	typ, _, _ := mime.ParseMediaType(request.Header.Get(headerContentType))
	return typ != "application/json" && !strings.HasSuffix(typ, "+json") && typ != "application/x-www-form-urlencoded" && typ != "multipart/form-data"
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
	buffer := make([]byte, scratchSize)
	empty := 0
	for {
		n, err := body.Read(buffer)
		if n > 0 {
			sample = append(sample, buffer[:min(n, sampleSize-len(sample))]...)
			empty = 0
		} else if err == nil {
			empty++
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			returned = true
			return sample, release, err
		}
		if empty >= 100 {
			returned = true
			return sample, release, io.ErrNoProgress
		}
	}
}

func (h *httpReader) SupportsFragmentSource() bool {
	c := decoderconfig.Instance
	return c != nil && c.FileStorage == "" && !c.IncludePayloads && h.conversation.ClientSource != nil && h.conversation.ServerSource != nil
}

func sourceHTTPOrientation(c *core.ConversationInfo) (*core.ConversationInfo, error) {
	if err := c.StateBudget.Reserve(32768); err != nil {
		return nil, err
	}
	defer c.StateBudget.Release(32768)
	client, err := core.ReadSourcePrefix(c.ClientSource, 16384)
	if err != nil {
		return nil, err
	}
	server, err := core.ReadSourcePrefix(c.ServerSource, 16384)
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
			for {
				_, found := seekHTTPLine(reader, false)
				if !found {
					return nil
				}
				request, evidence, err := readEvidenceRequest(reader)
				if err != nil || evidence.unsafe {
					return nil
				}
				if validH2Upgrade(request) || (request.ContentLength != 0 || len(request.TransferEncoding) > 0) && !opaqueSourceRequest(request) {
					return errHTTPSourceCompatibility
				}
				if request.ContentLength != 0 || len(request.TransferEncoding) > 0 {
					_, release, err := readSourceRequestBody(c, request.Body)
					release()
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
