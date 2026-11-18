package webtech

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

type failedWireBody struct{}

func TestCaptureRawDeflate(t *testing.T) {
	const plain = "<html>fixture</html>"
	encode := func(newWriter func(io.Writer) io.WriteCloser) []byte {
		t.Helper()
		var wire bytes.Buffer
		w := newWriter(&wire)
		if _, err := io.WriteString(w, plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return wire.Bytes()
	}
	raw := encode(func(out io.Writer) io.WriteCloser {
		w, err := flate.NewWriter(out, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		return w
	})
	if body, state := capture(bytes.NewReader(raw), "deflate"); string(body) != plain || state != "complete" {
		t.Fatalf("raw deflate: body=%q state=%s", body, state)
	}
	wrapped := encode(func(out io.Writer) io.WriteCloser { return zlib.NewWriter(out) })
	wrapped[len(wrapped)-1] ^= 1
	if body, state := capture(bytes.NewReader(wrapped), "deflate"); body != nil || state != "decode-failed" {
		t.Fatalf("bad zlib checksum: body=%q state=%s", body, state)
	}
}

func TestCaptureRetainsDecodedPrefixAtWireBudget(t *testing.T) {
	plain := bytes.Repeat([]byte("fixture text\n"), MaxPrefix/13+100)
	for _, kind := range []string{"gzip", "deflate"} {
		t.Run(kind, func(t *testing.T) {
			var wire bytes.Buffer
			var w io.WriteCloser
			var err error
			if kind == "gzip" {
				w, err = gzip.NewWriterLevel(&wire, gzip.NoCompression)
			} else {
				w, err = zlib.NewWriterLevel(&wire, zlib.NoCompression)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(plain); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			body, state := capture(bytes.NewReader(wire.Bytes()), kind)
			if state != "truncated" || len(body) < MaxPrefix/2 || len(body) >= MaxPrefix || !bytes.HasPrefix(plain, body) {
				t.Fatalf("wire budget: decoded %d bytes, state=%s", len(body), state)
			}
			body, state = capture(bytes.NewReader(wire.Bytes()[:MaxPrefix]), kind)
			if state != "decode-failed" || body != nil {
				t.Fatalf("genuinely incomplete encoding: decoded %d bytes, state=%s", len(body), state)
			}
		})
	}
}

func TestCaptureConcatenatedGzipMembers(t *testing.T) {
	encode := func(parts ...string) []byte {
		t.Helper()
		var wire bytes.Buffer
		for _, part := range parts {
			w := gzip.NewWriter(&wire)
			if _, err := io.WriteString(w, part); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		}
		return wire.Bytes()
	}
	wire := encode("<html>", "fixture</html>")
	if body, state := capture(bytes.NewReader(wire), "gzip"); string(body) != "<html>fixture</html>" || state != "complete" {
		t.Fatalf("concatenated body %q, state %s", body, state)
	}
	if body, state := capture(bytes.NewReader(wire[:len(wire)-1]), "gzip"); body != nil || state != "decode-failed" {
		t.Fatalf("truncated second member: body %q, state %s", body, state)
	}
	wire = encode(strings.Repeat("x", MaxPrefix-1), "yz")
	if body, state := capture(bytes.NewReader(wire), "gzip"); len(body) != MaxPrefix || body[MaxPrefix-1] != 'y' || state != "truncated" {
		t.Fatalf("prefix across members: %d bytes, state %s", len(body), state)
	}
}

func TestCaptureBoundedContentEncodingStack(t *testing.T) {
	encode := func(data []byte) []byte {
		t.Helper()
		var inner, outer bytes.Buffer
		gz := gzip.NewWriter(&inner)
		if _, err := gz.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		z := zlib.NewWriter(&outer)
		if _, err := z.Write(inner.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return outer.Bytes()
	}
	plain := []byte("<html>fixture</html>")
	wire := encode(plain)
	body, state := capture(bytes.NewReader(wire), "GZip, Deflate")
	if !bytes.Equal(body, plain) || state != "complete" {
		t.Fatalf("decoded %q, state %s", body, state)
	}
	if body, state := capture(bytes.NewReader(wire), "gzip, deflate, identity"); body != nil || state != "unsupported-encoding" {
		t.Fatalf("over-depth body: %d bytes, state %s", len(body), state)
	}
	if body, state := capture(bytes.NewReader(encode(bytes.Repeat([]byte("x"), MaxPrefix+1))), "gzip, deflate"); len(body) != MaxPrefix || state != "truncated" {
		t.Fatalf("oversized decoded body: %d bytes, state %s", len(body), state)
	}
}

func (failedWireBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type interruptedWireBody struct{ reads int }

func (r *interruptedWireBody) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 1 {
		return copy(p, "partial"), io.ErrUnexpectedEOF
	}
	return copy(p, "unread"), io.EOF
}

func TestPassiveObservationStopsAtWireFailure(t *testing.T) {
	body := &interruptedWireBody{}
	report := Builtin().ObserveReader(Observation{Method: "GET", Status: 200, ContentType: "text/html"}, body, "")
	if body.reads != 1 || report.WireBytes != 7 || !errors.Is(report.WireError, io.ErrUnexpectedEOF) || report.BodyState != "incomplete" {
		t.Fatalf("reads=%d bytes=%d err=%v state=%q", body.reads, report.WireBytes, report.WireError, report.BodyState)
	}
}

func TestPassiveObservationRetainsWireErrorOutsideDetectionScope(t *testing.T) {
	for _, observation := range []Observation{{Method: "GET", Status: 200, ContentType: "application/octet-stream"}, {Method: "HEAD", Status: 201}} {
		report := Builtin().ObserveReader(observation, io.MultiReader(strings.NewReader("short"), failedWireBody{}), "")
		if !errors.Is(report.WireError, io.ErrUnexpectedEOF) || report.WireBytes != 5 {
			t.Fatal("wire failure was replaced by a detection classification", report)
		}
	}
}

type heldReader struct {
	ready   chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (r *heldReader) Read([]byte) (int, error) {
	r.once.Do(func() { r.ready <- struct{}{}; <-r.release })
	return 0, io.EOF
}

func TestAggregateConcurrentCaptureAdmission(t *testing.T) {
	ready := make(chan struct{}, 16)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			Builtin().ObserveReader(Observation{Method: "GET", Status: 200, ContentType: "text/html"}, &heldReader{ready: ready, release: release}, "")
		})
	}
	for range 16 {
		<-ready
	}
	n := reserved.Load()
	report := Builtin().ObserveReader(Observation{Method: "GET", Status: 200, ContentType: "text/html"}, strings.NewReader("private"), "")
	close(release)
	wg.Wait()
	if n != MaxAggregate || report.BodyState != "budget-exhausted" || reserved.Load() != 0 {
		t.Fatal(n, report, reserved.Load())
	}
}

func TestSharedVectors(t *testing.T) {
	b, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Body, Method, State string
		Status                    int
		Generator                 []string
		Want                      [][3]string
		ContentType               string `json:"content_type"`
		BodyState                 string `json:"body_state"`
	}
	if err = json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	e, err := Parse(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Method == "" {
				c.Method = "GET"
			}
			if c.Status == 0 {
				c.Status = 200
			}
			if c.ContentType == "" {
				c.ContentType = "text/html"
			}
			if c.State == "" {
				c.State = "complete"
			}
			if c.BodyState == "" {
				c.BodyState = "complete"
			}
			r := e.Observe(Observation{Method: c.Method, Status: c.Status, ContentType: c.ContentType, Generator: c.Generator, Body: []byte(c.Body), BodyState: c.State})
			if r.BodyState != c.BodyState || len(r.Matches) != len(c.Want) {
				t.Fatalf("%+v want %s %v", r, c.BodyState, c.Want)
			}
			for i, m := range r.Matches {
				if [3]string{m.Product, m.Version, m.Precision} != c.Want[i] || !strings.HasPrefix(m.ID, "netcap.webtech.") {
					t.Fatalf("%+v", r)
				}
			}
		})
	}
}
func TestBoundsDecodingAndBudget(t *testing.T) {
	e := Builtin()
	o := Observation{Method: "GET", Status: 200, ContentType: "text/html"}
	for _, encoding := range []string{"identity", "gzip", "deflate", "br"} {
		var b bytes.Buffer
		if encoding == "gzip" {
			w := gzip.NewWriter(&b)
			_, _ = w.Write(bytes.Repeat([]byte("x"), 16<<20))
			_ = w.Close()
		} else {
			b.WriteString("<meta name=generator content='WordPress 6.8'>")
		}
		r := e.ObserveReader(o, &b, encoding)
		want := map[string]string{"identity": "complete", "gzip": "truncated", "deflate": "decode-failed", "br": "unsupported-encoding"}[encoding]
		if r.BodyState != want {
			t.Fatalf("%s: %+v", encoding, r)
		}
	}
	r := e.ObserveReader(o, strings.NewReader(strings.Repeat("x", MaxPrefix)+"<meta name=generator content='WordPress 6.8'>"), "")
	if r.BodyState != "truncated" || len(r.Matches) != 0 {
		t.Fatal(r)
	}
	r = e.ObserveReader(o, strings.NewReader("<meta "+strings.Repeat("x", MaxTag)+">"), "")
	if r.BodyState != "tag-limited" {
		t.Fatal(r)
	}
	reserved.Store(MaxAggregate)
	t.Cleanup(func() { reserved.Store(0) })
	b := strings.NewReader("private")
	r = e.ObserveReader(o, b, "")
	if r.BodyState != "budget-exhausted" || b.Len() != 0 {
		t.Fatal(r, b.Len())
	}
}
func TestStrictCatalogue(t *testing.T) {
	for _, b := range [][]byte{bytes.Replace(descriptors, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "schema_version": 1`), 1), bytes.Replace(descriptors, []byte(`"precision":"major"`), []byte(`"precision":"numeric"`), 1), append(append([]byte{}, descriptors...), []byte(`{}`)...), bytes.Replace(descriptors, []byte(`"GET"`), []byte(`"POST"`), 1), bytes.Repeat([]byte(" "), MaxCatalogue+1)} {
		if _, err := Parse(b); err == nil {
			t.Fatalf("accepted invalid descriptor")
		}
	}
	_, s := Load(t.TempDir())
	if s.State != "missing-builtins" || s.Rules != 2 {
		t.Fatal(s)
	}
}
func BenchmarkObserve(b *testing.B) {
	e := Builtin()
	o := Observation{Method: "GET", Status: 200, ContentType: "text/html", Body: []byte(strings.Repeat("x", MaxPrefix-64) + "<meta name=generator content='WordPress 6.8'>"), BodyState: "truncated"}
	b.ReportAllocs()
	b.SetBytes(int64(len(o.Body)))
	for b.Loop() {
		e.Observe(o)
	}
}
