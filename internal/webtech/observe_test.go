package webtech

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

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
