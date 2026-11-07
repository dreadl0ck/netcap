package firewallstate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func pgStateConfig(raw, namespace string) Config {
	return Config{DatabaseURL: raw, DatabaseNamespace: namespace, Principals: []Principal{{ID: "a", Token: testToken, Scope: testScope}, {ID: "b", Token: "principal-b-secret-token", Scope: Scope{Tenant: "tenant-b", App: "web"}}}}
}
func postgresConfig(t *testing.T) Config {
	t.Helper()
	raw := os.Getenv("NETCAP_POSTGRES_TEST_URL")
	if raw == "" {
		t.Skip("NETCAP_POSTGRES_TEST_URL required for real PostgreSQL tests")
	}
	u, err := url.Parse(raw)
	if err != nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("PostgreSQL tests require a literal loopback host")
	}
	namespace := fmt.Sprintf("ncf_state_%d_%x", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d, err := OpenPostgres(ctx, raw, namespace)
		if err != nil {
			t.Errorf("cleanup connection: %v", err)
			return
		}
		defer d.Close()
		if _, err = d.DB.ExecContext(ctx, `DROP SCHEMA "`+namespace+`" CASCADE`); err != nil {
			t.Errorf("cleanup schema: %v", err)
		}
	})
	return pgStateConfig(raw, namespace)
}

func TestPostgresRebindLexicalBoundaries(t *testing.T) {
	d := &Database{postgres: true}
	for _, tc := range []struct{ sql, want string }{
		{`SELECT ?, '?', "?", 'it''s ?', $$?$$, $body$?$body$, ?`, `SELECT $1, '?', "?", 'it''s ?', $$?$$, $body$?$body$, $2`},
		{"SELECT ? -- ?\n, ? /* ? /* ? */ ? */", "SELECT $1 -- ?\n, $2 /* ? /* ? */ ? */"},
		{`SELECT E'it\'s ?', ?, '\', ?`, `SELECT E'it\'s ?', $1, '\', $2`},
	} {
		if got := d.Rebind(tc.sql); got != tc.want {
			t.Fatalf("rebind: %q want %q", got, tc.want)
		}
		if got := (&Database{}).Rebind(tc.sql); got != tc.sql {
			t.Fatal("SQLite query changed")
		}
	}
}

func TestPostgresURLAdmissionDoesNotDiscloseSecrets(t *testing.T) {
	for _, raw := range []string{"postgres://user:secret-do-not-log@example.com/db?sslmode=disable", "postgres://user:secret-do-not-log@127.0.0.1/db?options=unsafe", "postgres://user:secret-do-not-log@%zz/db", "postgres://user:secret-do-not-log@example.com/db?sslmode=verify-full&sslmode=disable"} {
		_, err := OpenPostgres(context.Background(), raw, "ncf_test")
		if err == nil || strings.Contains(err.Error(), "secret-do-not-log") {
			t.Fatalf("unsafe URL admission: %v", err)
		}
	}
}

func TestPostgresPinsSessionAndWriterReadiness(t *testing.T) {
	cfg := postgresConfig(t)
	t.Setenv("PGOPTIONS", "-c search_path=public -c synchronous_commit=off -c statement_timeout=0")
	t.Setenv("PGHOSTADDR", "203.0.113.200")
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.disk.DB.SetMaxOpenConns(1)
	var path, commit, statement, lock, idle string
	if err = s.disk.DB.QueryRow(`SELECT current_setting('search_path'),current_setting('synchronous_commit'),current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('idle_in_transaction_session_timeout')`).Scan(&path, &commit, &statement, &lock, &idle); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, cfg.DatabaseNamespace) || commit != "on" || statement != "5s" || lock != "5s" || idle != "5s" {
		t.Fatalf("unpinned PostgreSQL session: %q %q %q %q %q", path, commit, statement, lock, idle)
	}
	var oldPID, newPID int
	if err = s.disk.DB.QueryRow(`SELECT pg_backend_pid()`).Scan(&oldPID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.disk.DB.Exec(`SET default_transaction_read_only=on`); err != nil {
		t.Fatal(err)
	}
	if err = s.Bind(testScope).(healthStore).Probe(context.Background()); err == nil {
		t.Fatal("read-only database connection reported authoritative readiness")
	}
	if _, err = s.disk.DB.Exec(`SET default_transaction_read_only=off`); err != nil {
		t.Fatal(err)
	}
	if err = s.disk.DB.QueryRow(`SELECT pg_backend_pid()`).Scan(&newPID); err != nil {
		t.Fatal(err)
	}
	if oldPID == newPID {
		t.Fatal("unwritable connection remained pooled after readiness failure")
	}
	if err = s.Bind(testScope).(healthStore).Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCountersActiveActive(t *testing.T) {
	cfg := postgresConfig(t)
	var services [2]*Service
	errs := make(chan error, 2)
	var startup sync.WaitGroup
	for i := range services {
		startup.Add(1)
		go func() {
			defer startup.Done()
			s, err := New(cfg)
			if err != nil {
				errs <- err
				return
			}
			services[i] = s
		}()
	}
	startup.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, s := range services {
		t.Cleanup(func() { _ = s.Close() })
	}
	servers := []*httptest.Server{httptest.NewServer(services[0].Handler()), httptest.NewServer(services[1].Handler())}
	for _, srv := range servers {
		defer srv.Close()
	}
	key := Key{Digest("concurrent-revision"), Digest("concurrent-group")}
	window := Window{Mode: "fixed", Duration: time.Hour}
	first, err := services[0].Bind(testScope).Count(context.Background(), Key{Digest("clock"), Digest("authority")}, window, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || first.Expires.Before(time.Now().Add(59*time.Minute)) || first.Expires.After(time.Now().Add(61*time.Minute)) {
		t.Fatalf("process timestamp overrode database clock: %+v %v", first, err)
	}
	counts := make(chan int64, 100)
	errors := make(chan error, 100)
	gate := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			c, err := NewClient(ClientConfig{URL: servers[i%2].URL, Token: testToken})
			if err != nil {
				errors <- err
				return
			}
			defer c.Close()
			v, err := c.Count(context.Background(), key, window, time.Time{})
			if err != nil {
				errors <- err
				return
			}
			counts <- v.Count
		}()
	}
	wg.Wait()
	close(counts)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for n := range counts {
		if seen[n] {
			t.Fatalf("duplicate committed count %d", n)
		}
		seen[n] = true
	}
	if len(seen) != 100 || !seen[100] {
		t.Fatalf("count coverage: %d", len(seen))
	}
	for _, s := range services {
		if err := s.Bind(testScope).(healthStore).Probe(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	v, err := services[1].Bind(Scope{Tenant: "tenant-b", App: "web"}).Count(context.Background(), key, window, time.Time{})
	if err != nil || v.Count != 1 {
		t.Fatalf("scope isolation %+v %v", v, err)
	}
	changed := cfg
	changed.Principals = append([]Principal(nil), cfg.Principals...)
	changed.Principals[0].Scope.App = "foreign"
	if s, err := New(changed); err == nil {
		_ = s.Close()
		t.Fatal("bootstrap scope drift accepted")
	}
	changed = cfg
	changed.Principals = append([]Principal(nil), cfg.Principals...)
	slices.Reverse(changed.Principals)
	replica, err := New(changed)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	v, err = replica.Bind(testScope).Count(context.Background(), key, window, time.Time{})
	if err != nil || v.Count != 101 {
		t.Fatalf("replica restart lost state %+v %v", v, err)
	}
	if err = replica.Backup(context.Background(), "/not-created.sqlite"); err == nil {
		t.Fatal("PostgreSQL attempted SQLite backup")
	}
}

func TestPostgresCounterWorker(t *testing.T) {
	if os.Getenv("NETCAP_COUNTER_WORKER") != "1" {
		t.Skip("subprocess helper")
	}
	s, err := New(pgStateConfig(os.Getenv("NETCAP_POSTGRES_TEST_URL"), os.Getenv("NETCAP_COUNTER_NAMESPACE")))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fmt.Println("HA_READY")
	if _, err = io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	counts := make([]int64, 0, 20)
	for range 20 {
		v, err := s.Bind(testScope).Count(context.Background(), Key{Digest("process"), Digest("process")}, Window{Mode: "fixed", Duration: time.Hour}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		counts = append(counts, v.Count)
	}
	raw, _ := json.Marshal(counts)
	fmt.Printf("HA_RESULT %s\n", raw)
}

func TestPostgresCounterMultiProcess(t *testing.T) {
	cfg := postgresConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresCounterWorker$")
	cmd.Env = append(os.Environ(), "NETCAP_COUNTER_WORKER=1", "NETCAP_COUNTER_NAMESPACE="+cfg.DatabaseNamespace)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "HA_READY" {
		_ = cmd.Wait()
		t.Fatalf("child readiness: %v %s", err, stderr.String())
	}
	if _, err = stdin.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	seen := map[int64]bool{}
	for range 20 {
		v, err := s.Bind(testScope).Count(ctx, Key{Digest("process"), Digest("process")}, Window{Mode: "fixed", Duration: time.Hour}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		seen[v.Count] = true
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		t.Fatalf("child failed: %v %s", err, stderr.String())
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "HA_RESULT ") {
			var counts []int64
			if err = json.Unmarshal([]byte(strings.TrimPrefix(line, "HA_RESULT ")), &counts); err != nil {
				t.Fatal(err)
			}
			for _, v := range counts {
				if seen[v] {
					t.Fatal("duplicate count across processes")
				}
				seen[v] = true
			}
			found = true
		}
	}
	if !found || len(seen) != 40 || !seen[40] {
		t.Fatalf("multi-process count coverage: %d", len(seen))
	}
}

func TestPostgresCounterCapacityIsGlobal(t *testing.T) {
	cfg := postgresConfig(t)
	cfg.MaxKeys = 1
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	w := Window{Mode: "fixed", Duration: time.Hour}
	key := Key{Digest("capacity"), Digest("first")}
	if _, err = a.Bind(testScope).Count(context.Background(), key, w, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Bind(testScope).Count(context.Background(), Key{key.Revision, Digest("second")}, w, time.Time{}); err == nil {
		t.Fatal("replica bypassed global key capacity")
	}
	v, err := b.Bind(testScope).Count(context.Background(), key, w, time.Time{})
	if err != nil || v.Count != 2 {
		t.Fatalf("capacity eviction %+v %v", v, err)
	}
}

func TestPostgresCancelledNamespaceWaitDoesNotWrite(t *testing.T) {
	cfg := postgresConfig(t)
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	lock, err := a.disk.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	key := Key{Digest("cancelled"), Digest("wait")}
	window := Window{Mode: "fixed", Duration: time.Hour}
	if _, err = b.Bind(testScope).Count(ctx, key, window, time.Time{}); err == nil {
		t.Fatal("other instance bypassed transaction lock")
	}
	if err = lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	v, err := b.Bind(testScope).Count(context.Background(), key, window, time.Time{})
	if err != nil || v.Count != 1 {
		t.Fatalf("cancelled operation wrote or retained lock %+v %v", v, err)
	}
}
