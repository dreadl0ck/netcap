package waf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/apipolicy"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestAPIResponseMethodAndBodylessStatusMatrix(t *testing.T) {
	response := `{"description":"representation","headers":{"X-Result":{"required":true,"schema":{"type":"integer","minimum":1}}},"content":{"application/json":{"schema":{"type":"object","required":["ok"],"properties":{"ok":{"const":true}}}}}}`
	responses := fmt.Sprintf(`{"200":%s,"201":%s,"204":%s,"304":%s}`, response, response, response, response)
	operation := `{"responses":` + responses + `}`
	doc := `{"openapi":"3.1.0","info":{"title":"methods","version":"1"},"paths":{"/items":{"get":` + operation + `,"head":` + operation + `}}}`
	for _, routed := range []bool{false, true} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, status := range []int{200, 201, 204, 304} {
				for _, variant := range []string{"valid", "missing-body", "invalid-body", "missing-header", "invalid-header", "wrong-type", "duplicate-type", "missing-type"} {
					t.Run(fmt.Sprintf("routed=%t/%s/%d/%s", routed, method, status, variant), func(t *testing.T) {
						bodyless := method == http.MethodHead || status == 204 || status == 304
						want := status
						if variant == "missing-header" || variant == "invalid-header" || variant == "wrong-type" || variant == "duplicate-type" || !bodyless && variant != "valid" {
							want = 502
						}
						// net/http removes Content-Type from 304 responses at the origin.
						if status == 304 && (variant == "wrong-type" || variant == "duplicate-type") {
							want = status
						}
						origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							w.Header().Set("Content-Type", "application/json")
							w.Header().Set("X-Result", "1")
							switch variant {
							case "missing-header":
								w.Header().Del("X-Result")
							case "invalid-header":
								w.Header().Set("X-Result", "0")
							case "wrong-type":
								w.Header().Set("Content-Type", "text/plain")
							case "duplicate-type":
								w.Header().Add("Content-Type", "application/json")
							case "missing-type":
								w.Header()["Content-Type"] = nil
							}
							payload := `{"ok":true}`
							if variant == "invalid-body" {
								payload = `{"ok":false}`
							}
							if variant == "missing-body" {
								payload = ""
							}
							if status == 200 || status == 201 {
								w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
							}
							w.WriteHeader(status)
							_, _ = io.WriteString(w, payload)
						}))
						defer origin.Close()
						c := apiConfig(t, config(origin.URL), map[string][]byte{"openapi.json": []byte(doc)}, apipolicy.Declaration{OpenAPI: "openapi.json"})
						c.APIValidateResponse = true
						if routed {
							r := routeFixture(t, origin.URL, "methods", "api.example", "/", 1)
							r.Methods = []string{http.MethodGet, http.MethodHead}
							r.DescriptorPath, r.DescriptorSHA256, r.APIValidateResponse = c.DescriptorPath, c.DescriptorSHA256, true
							c.DescriptorPath, c.DescriptorSHA256, c.APIValidateResponse = "", "", false
							c.Routes = []RouteConfig{r}
						}
						h := firewall(t, c, compiled(t, "enforce", "request", ""))
						proxy := httptest.NewServer(h)
						defer proxy.Close()
						req, _ := http.NewRequest(method, proxy.URL+"/items", nil)
						req.Host = "api.example"
						resp, err := proxy.Client().Do(req)
						if err != nil {
							t.Fatal(err)
						}
						data, err := io.ReadAll(resp.Body)
						resp.Body.Close()
						if err != nil || resp.StatusCode != want {
							t.Fatalf("status=%d want=%d body=%s err=%v", resp.StatusCode, want, data, err)
						}
						if method == http.MethodHead || want == 204 || want == 304 {
							if len(data) != 0 || len(resp.TransferEncoding) != 0 {
								t.Fatalf("bodyless payload=%q transfer=%v", data, resp.TransferEncoding)
							}
						}
						if method == http.MethodHead && (want == 200 || want == 201) && variant == "valid" && resp.ContentLength != 11 {
							t.Fatalf("representation length lost: %d", resp.ContentLength)
						}
						if want == 502 && bytes.Contains(data, []byte(`"ok"`)) {
							t.Fatalf("origin payload leaked: %s", data)
						}
					})
				}
			}
		}
	}
}

func apiConfig(t *testing.T, c Config, artifacts map[string][]byte, d apipolicy.Declaration) Config {
	t.Helper()
	dir := t.TempDir()
	d.Version = "netcap-api/v1"
	d.Artifacts = map[string]apipolicy.Artifact{}
	write := func(name string, data []byte) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	}
	for name, data := range artifacts {
		if name != d.Descriptors && !json.Valid(data) {
			t.Fatalf("invalid fixture JSON %s", name)
		}
		d.Artifacts[name] = apipolicy.Artifact{Path: name, SHA256: write(name, data)}
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	c.BootstrapDir = dir
	c.DescriptorPath = "bundle.json"
	c.DescriptorSHA256 = write(c.DescriptorPath, data)
	return c
}

const apiContract = `{"openapi":"3.1.0","info":{"title":"test","version":"1"},"paths":{"/items":{"post":{"parameters":[{"in":"header","name":"X-Required","required":true,"schema":{"type":"string","minLength":1}},{"in":"query","name":"limit","required":true,"schema":{"type":"integer","minimum":1,"maximum":10}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["text","n"],"additionalProperties":false,"properties":{"text":{"type":"string"},"n":{"type":"integer","minimum":1,"maximum":10}}}}}},"responses":{"200":{"description":"OK","content":{"application/json":{"schema":{"type":"object","required":["ok"],"properties":{"ok":{"const":true}}}}}}}}}}}`

func TestAPIOriginBoundaryAndResponseOptIn(t *testing.T) {
	apiOriginBoundary(t, false)
}

func TestRoutedAPIOriginBoundaryAndResponseOptIn(t *testing.T) {
	apiOriginBoundary(t, true)
}

func apiOriginBoundary(t *testing.T, routed bool) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":false,"private":"must not leak"}`)
	}))
	defer origin.Close()
	c := apiConfig(t, config(origin.URL), map[string][]byte{"openapi.json": []byte(apiContract)}, apipolicy.Declaration{OpenAPI: "openapi.json", Passthrough: []apipolicy.Binding{{Method: "GET", Path: "/health"}}})
	_, _, handler := composedFirewall(t, c, compiled(t, "enforce", "request", ""), routed)
	proxy := httptest.NewServer(handler)
	defer proxy.Close()
	request := func(path, body string, required bool) int {
		t.Helper()
		req, _ := http.NewRequest("POST", proxy.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if required {
			req.Header.Set("X-Required", "yes")
		}
		resp, err := proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if status := request("/items?limit=2", `{"text":"SELECT password FROM users; ' OR 1=1 -- harmless prose","n":2}`, true); status != 200 {
		t.Fatalf("benign SQL-ish string denied: %d", status)
	}
	for _, tc := range []struct {
		path, body string
		header     bool
	}{
		{"/items?limit=2", `{"text":"x","n":11}`, true}, {"/items?limit=2", `{"text":"x","n":null}`, true}, {"/items?limit=2", `{"text":"x"}`, true},
		{"/items?limit=2", `{"text":"x","n":2,"n":3}`, true}, {"/items?limit=2", `{"text":"x","n":2}`, false}, {"/items?limit=2&limit=2", `{"text":"x","n":2}`, true},
		{"/items", `{"text":"x","n":2}`, true}, {"/unknown?limit=2", `{"text":"x","n":2}`, true},
		{"/items?limit=2&unknown=x", `{"text":"x","n":2}`, true},
	} {
		if status := request(tc.path, tc.body, tc.header); status < 400 {
			t.Fatalf("invalid reached origin: %+v", tc)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("invalid request contacted origin: %d", got)
	}
	for _, method := range []string{"GET", "DELETE", "HEAD"} {
		req, _ := http.NewRequest(method, proxy.URL+"/items?limit=2", nil)
		resp, err := proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 || calls.Load() != 1 {
			t.Fatalf("undeclared method %s reached origin", method)
		}
	}
	// A late invalid member on a chunked request must not even contact origin.
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", proxy.URL+"/items?limit=2", pr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Required", "yes")
	done := make(chan error, 1)
	go func() {
		resp, err := proxy.Client().Do(req)
		if err == nil {
			if resp.StatusCode < 400 {
				err = apipolicy.ErrInvalid
			}
			resp.Body.Close()
		}
		done <- err
	}()
	if _, err := io.WriteString(pw, `{"text":"long safe prefix",`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("origin contacted before request completed")
	}
	_, _ = io.WriteString(pw, `"n":999}`)
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("late invalid field contacted origin")
	}
	c.APIValidateResponse = true
	_, _, responseHandler := composedFirewall(t, c, compiled(t, "enforce", "request", ""), routed)
	server := httptest.NewServer(responseHandler)
	defer server.Close()
	req, _ = http.NewRequest("POST", server.URL+"/items?limit=2", strings.NewReader(`{"text":"x","n":2}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Required", "yes")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 502 || bytes.Contains(data, []byte("must not leak")) || calls.Load() != 2 {
		t.Fatalf("delivery gate status=%d body=%s calls=%d", resp.StatusCode, data, calls.Load())
	}
	// Response rejection prevented delivery; the second origin call still executed.
}

func grpcArtifact(t *testing.T) ([]byte, protoreflect.MessageDescriptor) {
	t.Helper()
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("api.proto"), Package: proto.String("api"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{
		{Name: proto.String("Nested"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("amount"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum()}}},
		{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("nested"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: proto.String(".api.Nested")}}},
	}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Exchange"), InputType: proto.String(".api.Request"), OutputType: proto.String(".api.Request"), ClientStreaming: proto.Bool(true), ServerStreaming: proto.Bool(true)}}}}}}}
	data, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatal(err)
	}
	d, err := files.FindDescriptorByName("api.Request")
	if err != nil {
		t.Fatal(err)
	}
	return data, d.(protoreflect.MessageDescriptor)
}

func TestAPIGRPCRealH2ProtobufLateFragmentAndIsolation(t *testing.T) {
	apiGRPCBoundary(t, false)
}

func TestRoutedAPIGRPCRealH2ProtobufLateFragmentAndIsolation(t *testing.T) {
	apiGRPCBoundary(t, true)
}

func apiGRPCBoundary(t *testing.T, routed bool) {
	artifact, md := grpcArtifact(t)
	message := func(amount int64) []byte {
		t.Helper()
		m := dynamicpb.NewMessage(md)
		f := md.Fields().ByName("nested")
		nested := dynamicpb.NewMessage(f.Message())
		nested.Set(f.Message().Fields().ByName("amount"), protoreflect.ValueOfInt64(amount))
		m.Set(f, protoreflect.ValueOfMessage(nested))
		wire, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return protowire.AppendVarint(protowire.AppendTag(wire, 99, protowire.VarintType), 123)
	}
	valid, bad := message(3), message(999)
	seen := make(chan []byte, 8)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("origin did not receive HTTP/2")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		for {
			var head [5]byte
			if _, err := io.ReadFull(r.Body, head[:]); err != nil {
				break
			}
			n := binary.BigEndian.Uint32(head[1:])
			if n > 1<<20 {
				t.Error("bad frame length")
				return
			}
			data := make([]byte, n)
			if _, err := io.ReadFull(r.Body, data); err != nil {
				break
			}
			m := dynamicpb.NewMessage(md)
			if err := proto.Unmarshal(data, m); err != nil {
				t.Error(err)
				return
			}
			seen <- data
			_, _ = w.Write(append(head[:], data...))
			if r.Header.Get("X-Bad-Response") == "true" {
				badFrame := make([]byte, 5)
				binary.BigEndian.PutUint32(badFrame[1:], uint32(len(bad)))
				_, _ = w.Write(append(badFrame, bad...))
			}
			_ = http.NewResponseController(w).Flush()
		}
		w.Header().Set("Grpc-Status", "0")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	schema := map[string]any{"type": "integer", "minimum": 1, "maximum": 10}
	fields := map[string]apipolicy.FieldPolicy{"nested.amount": {Required: true, Schema: schema}}
	c := apiConfig(t, config(origin.URL), map[string][]byte{"api.pb": artifact}, apipolicy.Declaration{Descriptors: "api.pb", GRPC: map[string]apipolicy.MethodPolicy{"/api.Service/Exchange": {Request: fields, Response: fields}}})
	c.APIValidateResponse = true
	// The same descriptor binds both directions, with separate field policies.
	f, bound, routedHandler := composedFirewall(t, c, compiled(t, "enforce", "request", ""), routed)
	bound.transport.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	h, err := f.MessageHandler(false, true)
	if err != nil {
		t.Fatal(err)
	}
	var peersMu sync.Mutex
	peers := map[string]bool{}
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peersMu.Lock()
		peers[r.RemoteAddr] = true
		peersMu.Unlock()
		if routed {
			routedHandler.ServeHTTP(w, r)
		} else {
			h.ServeHTTP(w, r)
		}
	}))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	client := proxy.Client()
	client.Timeout = 4 * time.Second
	frame := func(data []byte) []byte {
		h := make([]byte, 5)
		binary.BigEndian.PutUint32(h[1:], uint32(len(data)))
		return append(h, data...)
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", proxy.URL+"/api.Service/Exchange", pr)
	req.Header.Set("Content-Type", "application/grpc")
	done := make(chan struct{})
	go func() {
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		close(done)
	}()
	wire := frame(bad)
	if _, err := pw.Write(wire[:len(wire)-1]); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-seen:
		t.Fatalf("partial frame leaked: %x", got)
	case <-time.After(30 * time.Millisecond):
	}
	// A valid RPC on the same pooled H2 connection completes while the denied
	// stream is still waiting for its final fragment.
	goodReq, _ := http.NewRequest("POST", proxy.URL+"/api.Service/Exchange", bytes.NewReader(frame(valid)))
	goodReq.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(goodReq)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.ProtoMajor != 2 || !bytes.Equal(data, frame(valid)) {
		t.Fatalf("valid stream failed: %x %v", data, err)
	}
	select {
	case got := <-seen:
		if !bytes.Equal(got, valid) {
			t.Fatal("unknown protobuf fields changed")
		}
	case <-ctx.Done():
		t.Fatal("valid stream never reached origin")
	}
	_, _ = pw.Write(wire[len(wire)-1:])
	pw.Close()
	<-done
	select {
	case got := <-seen:
		t.Fatalf("denied nested protobuf field reached origin: %x", got)
	case <-time.After(30 * time.Millisecond):
	}
	// A completed denied stream must not poison another RPC on the connection.
	goodReq, _ = http.NewRequest("POST", proxy.URL+"/api.Service/Exchange", bytes.NewReader(frame(valid)))
	goodReq.Header.Set("Content-Type", "application/grpc")
	resp, err = client.Do(goodReq)
	if err != nil {
		t.Fatal(err)
	}
	data, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(data, frame(valid)) {
		t.Fatal("cross-stream state leaked", err)
	}
	goodReq, _ = http.NewRequest("POST", proxy.URL+"/api.Service/Exchange", bytes.NewReader(frame(valid)))
	goodReq.Header.Set("Content-Type", "application/grpc")
	goodReq.Header.Set("X-Bad-Response", "true")
	resp, err = client.Do(goodReq)
	if err != nil {
		t.Fatal(err)
	}
	data, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(data, frame(valid)) || resp.Trailer.Get("Grpc-Status") != "7" {
		t.Fatalf("late invalid response frame leaked: %x trailer=%v err=%v", data, resp.Trailer, err)
	}
	for len(seen) > 0 {
		<-seen
	}
	pr, pw = io.Pipe()
	req, _ = http.NewRequestWithContext(ctx, "POST", proxy.URL+"/api.Service/Exchange", pr)
	req.Header.Set("Content-Type", "application/grpc")
	done = make(chan struct{})
	go func() {
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		close(done)
	}()
	if _, err := pw.Write(frame(valid)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-seen:
		if !bytes.Equal(got, valid) {
			t.Fatal("first message changed")
		}
	case <-ctx.Done():
		t.Fatal("first message was not streamed")
	}
	if _, err := pw.Write(wire[:len(wire)-1]); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-seen:
		t.Fatalf("partial later message leaked: %x", got)
	case <-time.After(30 * time.Millisecond):
	}
	_, _ = pw.Write(wire[len(wire)-1:])
	pw.Close()
	<-done
	select {
	case got := <-seen:
		t.Fatalf("invalid later message leaked: %x", got)
	case <-time.After(30 * time.Millisecond):
	}
	peersMu.Lock()
	defer peersMu.Unlock()
	if len(peers) != 1 {
		t.Fatalf("isolation test used %d client connections rather than multiplexed streams", len(peers))
	}
}
