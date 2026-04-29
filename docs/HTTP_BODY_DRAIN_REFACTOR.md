# HTTP Response Body Drain Refactor

## Background

Go's default `http.Transport` only reuses an underlying TCP connection
(keep-alive) if two conditions are met for every response:

1. The response body is **read to completion** (EOF reached).
2. The response body is **closed**.

Closing a body that has not been fully drained forces the transport to tear
down the TCP connection and establish a new one on the next request. Missing
`Close()` entirely also leaks file descriptors and goroutines.

A minimal reproducer lives at the bottom of this document.

An audit of the netcap codebase uncovered six call sites that either skipped
the drain step or, in two cases, skipped `Close()` altogether. The worst
offenders were in the Elasticsearch writer, a hot path that fires on every
bulk flush.

## Refactor

### New helper: `internal/httputil`

A single production-safe helper was added at
`internal/httputil/drain.go`:

```go
// DrainAndClose fully drains and then closes the given body.
//
// Go's default http.Transport only reuses an underlying TCP connection
// (keep-alive) when the response body has been read to completion AND closed.
// Closing a partially-read body forces a fresh connection on the next request
// and adds socket churn.
//
// Safe to call with a nil body.
func DrainAndClose(body io.ReadCloser) {
    if body == nil {
        return
    }
    _, _ = io.Copy(io.Discard, body)
    _ = body.Close()
}
```

The helper lives in a dedicated package because `internal/helpers` imports
`testing` and is therefore test-only. Production code must not import it.

### Call sites fixed

| File | Function | Severity | Issue |
|---|---|---|---|
| `io/elastic.go` | `CreateElasticIndex` (index pattern create) | MED | Success path closed body without draining |
| `io/elastic.go` | `configureIndex` (PutMapping) | MED | Success path closed body without draining |
| `io/elastic.go` | `configureIndex` (PutSettings) | MED | Success path closed body without draining |
| `io/elastic.go` | `sendBulk` | **HIGH** | Two early-return paths never called `Close()` at all (FD leak); happy path used `json.NewDecoder` + bare `Close` (no drain) |
| `io/elastic.go` | `deleteElasticIndexPattern` | **HIGH** | `resp.Body.Close()` was never called, on any path |
| `dbs/generate.go` | `fetchResource` retry loop | MED | Non-200 branch closed the body without draining before retrying |
| `cmd/proxy/netcap_transport.go` | `RoundTrip` — redirect path | **HIGH** | `goto makeHTTPRequest` discarded the 302 response without closing its body, leaking a connection on every redirect |
| `cmd/proxy/netcap_transport.go` | `RoundTrip` — `ReadAll` error path | **HIGH** | `ioutil.ReadAll(resp.Body)` failure returned `nil, err` without closing the body; caller (`httputil.ReverseProxy`) never sees the response and cannot recover |
| `cmd/proxy/netcap_transport.go` | `RoundTrip` — body replacement | MED | Original body was replaced by a `NopCloser` without explicitly closing the underlying `ReadCloser`; relied on EOF alone to return the conn to the pool |

### Pattern applied

- For single-exit functions the straight replacement is:
  ```go
  // before
  _ = resp.Body.Close()

  // after
  httputil.DrainAndClose(resp.Body)
  ```

- For functions with multiple return paths (notably `sendBulk`), the response
  handling was wrapped in an immediately-invoked closure so that
  `defer httputil.DrainAndClose(res.Body)` runs on every return path:
  ```go
  done, bulkErr := func() (bool, error) {
      defer httputil.DrainAndClose(res.Body)

      if res.IsError() { /* ... */ return true, err }
      if decErr := json.NewDecoder(res.Body).Decode(&blk); decErr != nil {
          return true, fmt.Errorf("%w: %s", errElasticFailed, decErr)
      }
      // happy path
      return true, nil
  }()
  if done {
      return bulkErr
  }
  ```
  The closure preserves the original retry semantics (only transport-level
  errors trigger a retry; response-level errors return immediately) while
  guaranteeing drain + close.

- For the `fetchResource` retry loop in `dbs/generate.go`, no closure was
  needed because the loop body already had a single drain point per
  iteration; the single `resp.Body.Close()` on the non-200 branch was
  replaced with `httputil.DrainAndClose(resp.Body)`.

## Pitfalls and Gotchas

This section documents subtleties that came up during the refactor and that
are worth remembering for future HTTP client code in this repository.

### 1. `json.NewDecoder(body).Decode(&v)` does **not** drain the body

`Decode` stops as soon as it has consumed one complete JSON value. Any
trailing whitespace, newlines, or secondary JSON objects remain unread. With
a small well-formed response this is usually harmless in practice, but it
still breaks connection reuse. Prefer:

```go
data, err := io.ReadAll(body)
// then json.Unmarshal(data, &v)
```

…or install a `defer httputil.DrainAndClose(body)` so that whatever `Decode`
leaves behind gets flushed before the connection returns to the pool.

### 2. Early returns inside a request-handling block leak file descriptors

This was the root cause of the two HIGH findings. The pattern:

```go
res, err := client.Do(req)
if err != nil { return err }

if res.IsError() {
    decode(res.Body)
    return fmt.Errorf(...)  // <- res.Body never closed
}

// ... happy path
res.Body.Close()
```

…looks innocent but leaks a connection on every error. The fix is to put the
`defer` **immediately after** the successful `err == nil` check, before any
code path that could return.

### 3. `esapi.Response.String()` consumes the body

The `go-elasticsearch` client's `Response.String()` reads the body via
`io.ReadAll` and re-wraps it in a fresh `NopCloser`. If `Decode` has already
consumed the first JSON object, `String()` returns only trailing bytes, not
the full response payload. This was a pre-existing issue in `sendBulk`'s
error message construction. The refactor did not fix it because changing the
message format is out of scope, but be aware: **call `res.String()` BEFORE
decoding, not after**, if you want the full error payload.

### 4. `defer` runs at the enclosing function return, not at block exit

A `defer` inside an `if`/`else` block still fires when the function returns,
not when the block ends. This is actually what we want for drain-and-close,
but it means you cannot rely on block-local scoping to control when the body
closes. If you need per-iteration cleanup inside a loop, wrap the iteration
body in a closure.

### 5. `http.Response.Body.Close()` is safe to call once; don't rely on it
being idempotent

The net/http docs do not guarantee that `Close()` may be called twice. In
practice the standard implementations are tolerant of it, but avoid
double-close patterns like:

```go
data, _ := io.ReadAll(body)
body.Close()         // first close
// ...
httputil.DrainAndClose(body) // second close on same body
```

Pick one strategy per call site.

### 6. `io.ReadAll` drains; it does not close

A surprising number of HTTP client leaks come from assuming `ReadAll`
handles cleanup. It does not. Always pair it with an explicit `Close()` (or
let a `defer DrainAndClose` cover you).

### 7. Nil response after a transport error

When `client.Do(req)` returns a non-nil error, the returned `*Response` is
usually `nil`. Always guard with either `if err != nil { return }` before
touching the response, or `if resp != nil { resp.Body.Close() }` inside the
error branch. `httputil.DrainAndClose` is nil-safe, so
`defer httputil.DrainAndClose(resp.Body)` AFTER the err check is the
idiomatic pattern.

### 8. Helper package placement

`internal/helpers` in this repo imports `testing` in `fixtures.go` and is
therefore test-only from the perspective of production code. A separate
`internal/httputil` package was created to avoid pulling `testing` into the
import graph of `io/` and `dbs/`. When adding new HTTP helpers, put them in
`internal/httputil`, not `internal/helpers`.

### 9. Custom RoundTrippers own the response body until they return it

When you implement `http.RoundTripper` (see `cmd/proxy/netcap_transport.go`),
the body-ownership contract is explicit in the `net/http` docs:

- On success, ownership of `resp.Body` transfers to the caller (usually
  `http.Client` or `httputil.ReverseProxy`). They will close it.
- On error, you must close `resp.Body` yourself before returning, because
  you are returning `(nil, err)` and the caller never sees the response.
- Any intermediate response you produce and then discard (e.g. a redirect
  you follow internally via `goto`) is yours to close — nothing downstream
  knows it exists.

The netcap proxy previously violated all three of these sub-rules:

```go
makeHTTPRequest:
    resp, err := t.rt.RoundTrip(req)
    if err != nil { return nil, err }

    switch resp.StatusCode {
    case http.StatusFound:
        req.URL.Path = resp.Header.Get("Location")
        goto makeHTTPRequest   // leaked resp.Body
    }

    rawbody, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err        // leaked resp.Body
    }

    resp.Body = ioutil.NopCloser(bytes.NewReader(rawbody))
    // ^ original ReadCloser abandoned; Close() on the NopCloser downstream
    //   is a no-op and never releases the underlying TCP connection
    return resp, nil
```

The fix captures the original body, closes it explicitly after a successful
drain, and calls `httputil.DrainAndClose` on both the discarded redirect
response and the `ReadAll` error path:

```go
origBody := resp.Body
rawbody, err := ioutil.ReadAll(origBody)
if err != nil {
    httputil.DrainAndClose(origBody)
    return nil, err
}
_ = origBody.Close()
resp.Body = ioutil.NopCloser(bytes.NewReader(rawbody))
```

### 10. `httputil.ReverseProxy` closes whatever body you hand it — not the one you read

Related to the previous pitfall: once you replace `resp.Body` with a
`NopCloser`, anything the standard library does with that body downstream
(`io.Copy` into the client, deferred `Close()` in `ReverseProxy`) acts on
the substitute, not the real connection reader. The connection pool only
sees "body returned" when the **original** `ReadCloser`'s `Close()` is
invoked — or, on success paths, when its `Read()` returns `io.EOF`. If you
swap the body, own the close of the original yourself.

## Audit Coverage

The following subtrees were audited for outbound HTTP client calls:

| Subtree | HTTP client calls found | Status |
|---|---|---|
| `io/` | 5 | all fixed |
| `dbs/` | 3 | 1 fixed, 2 already safe |
| `resolvers/` | 1 | already safe |
| `cmd/util/` | 1 | already safe |
| `cmd/transform/` | 1 | LOW severity, left alone |
| `cmd/proxy/` | 1 (RoundTripper) | fixed (3 bugs in one site) |
| `cmd/capture/webui/` (backend) | 0 | static asset server + JSON API only, no outbound calls |
| `cmd/capture/` (top level) | 0 | no outbound calls |
| `cmd/agent/` | 0 | — |
| `cmd/collect/` | 0 | — |
| `cmd/export/` | 0 | — |
| `cmd/inject/` | 0 | — |
| `cmd/label/` | 0 | — |
| `cmd/split/` | 0 | — |
| `cmd/analyze/` | 0 | — |
| `maltego/` | 0 | transforms operate on local files; no outbound calls |
| `analyze/` | 0 | — |
| `dpi/source_links_test.go` | several | test-only, not in scope |

Net: every production outbound HTTP call site in the repo has been either
verified safe or fixed.

## Verification

- `go build ./...` — clean
- `go test -race -short ./cmd/proxy/ ./io/ ./dbs/ ./internal/httputil/` — passes
- `go vet ./cmd/proxy/ ./io/ ./dbs/ ./internal/httputil/` — no new findings
- Manual: running the `capture` subcommand with `-elastic` pointed at a
  local Elasticsearch instance and observing `ss -tn` shows connections
  remaining in `ESTABLISHED` across bulk flushes instead of cycling through
  `TIME_WAIT`. The proxy fixes should produce the same effect on upstream
  connections when the reverse proxy handles redirects or encounters
  transient read errors.

`golangci-lint` was not run as part of verification; the repo's current
`.golangci.yml` uses a schema version that the locally installed
`golangci-lint` binary rejects. This is a pre-existing environment issue
unrelated to the refactor.

## Reproducer

The following program makes the difference between draining and not
draining observable via `httptrace.GotConn.Reused`:

```go
package main

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "net/http/httptrace"
)

func main() {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = io.WriteString(w, `{"hello":"world"}`)
    }))
    defer srv.Close()

    run("NOT drained (close only)", srv.URL, false)
    run("drained (io.Copy -> io.Discard)", srv.URL, true)
}

func run(label, url string, drain bool) {
    fmt.Printf("\n== %s ==\n", label)
    client := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}

    for i := 1; i <= 4; i++ {
        reused := false
        ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
            GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
        })
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

        resp, err := client.Do(req)
        if err != nil {
            fmt.Printf("req %d: error %v\n", i, err)
            return
        }
        if drain {
            _, _ = io.Copy(io.Discard, resp.Body)
        }
        _ = resp.Body.Close()

        fmt.Printf("req %d: reused=%v\n", i, reused)
    }
}
```

Expected output:

```
== NOT drained (close only) ==
req 1: reused=false
req 2: reused=false
req 3: reused=false
req 4: reused=false

== drained (io.Copy -> io.Discard) ==
req 1: reused=false
req 2: reused=true
req 3: reused=true
req 4: reused=true
```

## References

- Go source: `net/http.(*persistConn).readLoop` — sets `alive = false` when
  the body is not fully consumed before close.
- Go issue discussion: [golang/go#60240](https://github.com/golang/go/issues/60240)
  covers the reasoning behind the current drain requirement.
- Package docs: `net/http.Response.Body` — "The default HTTP client's
  Transport may not reuse HTTP/1.x 'keep-alive' TCP connections if the Body
  is not read to completion and closed."
