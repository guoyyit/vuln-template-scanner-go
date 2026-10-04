package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
)

// newTestServer starts a loopback HTTP server with the given handler.
func newTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func simpleTemplate(id, path string, status int, word string) *template.Template {
	return &template.Template{
		ID:      id,
		Version: template.FormatV2,
		Info:    template.Info{Name: id, Severity: template.SeverityHigh, Tags: []string{"test", "rce"}},
		Request: template.Request{Method: "GET", Path: path},
		Variants: []template.Variant{{
			ID:      "default",
			Request: template.Request{Method: "GET", Path: path},
		}},
		Matchers: []template.MatcherSpec{
			{ID: "s", Type: "status", Status: []int{status}},
			{ID: "w", Type: "word", Words: []string{word}},
		},
	}
}

func TestBasicScanHit(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x:0:0:root")
	})
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	eng := New(Options{})
	res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	if res.Status != "completed" {
		t.Fatalf("status = %q", res.Status)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("want 1 hit, got %d: %+v", len(res.Hits), res.Hits)
	}
	h := res.Hits[0]
	if h.TemplateID != "t1" || h.Target != srv.URL || h.Severity != template.SeverityHigh {
		t.Fatalf("bad hit: %+v", h)
	}
	if len(h.Evidence) != 2 {
		t.Fatalf("want 2 evidence nodes, got %d", len(h.Evidence))
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", res.Errors)
	}
}

func TestNoHitWhenResponseDiffers(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	})
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	eng := New(Options{})
	res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	if len(res.Hits) != 0 {
		t.Fatalf("want 0 hits, got %+v", res.Hits)
	}
}

func TestDeterminismAcrossRuns(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x:0:0:root")
	})
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	eng := New(Options{Seed: 7})

	var first []byte
	for i := 0; i < 3; i++ {
		res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
		data, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = data
			continue
		}
		if string(data) != string(first) {
			t.Fatalf("run %d differs:\n%s\nvs\n%s", i, data, first)
		}
	}
}

func TestRateLimiting(t *testing.T) {
	var mu sync.Mutex
	times := []time.Time{}
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		w.WriteHeader(200)
	})
	tmpl := multiVariantTemplate("t1", 10)
	eng := New(Options{RateLimit: 20, RateBurst: 1, Concurrency: 10})
	start := time.Now()
	eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	elapsed := time.Since(start)
	mu.Lock()
	n := len(times)
	mu.Unlock()
	if n < 5 {
		t.Fatalf("want at least 5 requests, got %d", n)
	}
	// 20 req/s with burst 1 should take ~200ms for 5 requests; allow slack.
	if elapsed < 150*time.Millisecond {
		t.Fatalf("rate limiting did not slow requests: %d requests in %v", n, elapsed)
	}
}

func multiVariantTemplate(id string, n int) *template.Template {
	values := make([]string, n)
	for i := 0; i < n; i++ {
		values[i] = fmt.Sprintf("/%d", i)
	}
	return &template.Template{
		ID:        id,
		Version:   template.FormatV2,
		Info:      template.Info{Name: id, Severity: template.SeverityInfo},
		Variables: []template.Variable{{Name: "p", Values: values}},
		Variants: []template.Variant{{
			ID:      "v",
			Request: template.Request{Method: "GET", Path: "/{{p}}"},
		}},
		Matchers: []template.MatcherSpec{{ID: "s", Type: "status", Status: []int{200}}},
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var mu sync.Mutex
	inflight := 0
	maxInflight := 0
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inflight++
		if inflight > maxInflight {
			maxInflight = inflight
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
		w.WriteHeader(200)
	})
	tmpl := simpleTemplate("t1", "/", 200, "x")
	eng := New(Options{Concurrency: 3})
	eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	mu.Lock()
	defer mu.Unlock()
	if maxInflight > 3 {
		t.Fatalf("concurrency exceeded: max inflight = %d, want <= 3", maxInflight)
	}
}

func TestCancellationStopsPromptly(t *testing.T) {
	var mu sync.Mutex
	started := 0
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		started++
		mu.Unlock()
		time.Sleep(2 * time.Second)
	})
	tmpl := simpleTemplate("t1", "/", 200, "x")
	eng := New(Options{Concurrency: 1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *Result, 1)
	go func() { done <- eng.Scan(ctx, []*template.Template{tmpl}, []string{srv.URL}) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case res := <-done:
		if res.Status != "running" {
			t.Fatalf("cancelled scan should stay running, got %q", res.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not stop promptly after cancellation")
	}
}

func TestTimeoutProducesErrorNotHang(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	})
	tmpl := simpleTemplate("t1", "/", 200, "x")
	eng := New(Options{Timeout: 100 * time.Millisecond})
	res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	if len(res.Hits) != 0 {
		t.Fatalf("timeout must not produce hits, got %+v", res.Hits)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("want 1 timeout error, got %d: %+v", len(res.Errors), res.Errors)
	}
	if res.Errors[0].Phase != "request" {
		t.Fatalf("timeout error phase = %q", res.Errors[0].Phase)
	}
}

func TestUnreachableTargetIsErrorNotHit(t *testing.T) {
	tmpl := simpleTemplate("t1", "/", 200, "x")
	eng := New(Options{Timeout: 500 * time.Millisecond})
	res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{"http://127.0.0.1:1"})
	if len(res.Hits) != 0 {
		t.Fatalf("connection failure must not be a hit: %+v", res.Hits)
	}
	if len(res.Errors) != 1 || res.Errors[0].Phase != "request" {
		t.Fatalf("want 1 request error, got %+v", res.Errors)
	}
	if !strings.Contains(res.Errors[0].Message, "connection") {
		t.Fatalf("error message should mention connection: %q", res.Errors[0].Message)
	}
}

func TestCompileErrorIsolated(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x")
	})
	bad := simpleTemplate("bad", "/", 200, "root:")
	bad.Matchers[1] = template.MatcherSpec{ID: "r", Type: "regex", Regex: []string{"[invalid"}}
	good := simpleTemplate("good", "/", 200, "root:")
	eng := New(Options{})
	res := eng.Scan(context.Background(), []*template.Template{bad, good}, []string{srv.URL})
	if len(res.Hits) != 1 || res.Hits[0].TemplateID != "good" {
		t.Fatalf("only good template should hit, got %+v", res.Hits)
	}
	if len(res.Errors) != 1 || res.Errors[0].TemplateID != "bad" || res.Errors[0].Phase != "compile" {
		t.Fatalf("want 1 compile error for bad, got %+v", res.Errors)
	}
}

func TestCheckpointResumeNoDuplicatesNoLoss(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x:0:0:root")
	})
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	dir := t.TempDir()
	cpPath := filepath.Join(dir, "checkpoint.json")

	// Pre-populate a checkpoint with one completed task and one hit.
	store := NewFileCheckpointStore(cpPath)
	seed := int64(99)
	scanID := scanID(seed, []string{srv.URL}, []string{"t1"})
	pre := &Result{
		ScanID:    scanID,
		Status:    "running",
		Seed:      seed,
		Targets:   []string{srv.URL},
		Templates: []string{"t1"},
		Hits: []Hit{{
			TemplateID: "t1", Target: srv.URL, VariantID: "default",
			Severity: template.SeverityHigh, Tags: []string{"test"},
			Evidence: []EvidenceNode{{MatcherID: "s", Type: "status", Detail: "preexisting"}},
		}},
	}
	key := TaskKey(srv.URL, "t1", "default")
	pre.Completed = []string{key}
	if err := store.Save(pre); err != nil {
		t.Fatal(err)
	}

	eng := New(Options{Seed: seed, Checkpoint: store})
	res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	if res.Status != "completed" {
		t.Fatalf("resumed scan should complete, got %q", res.Status)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("want exactly 1 hit after resume (no duplicates), got %d: %+v", len(res.Hits), res.Hits)
	}
	if res.Hits[0].Evidence[0].Detail != "preexisting" {
		t.Fatalf("preexisting hit was lost/changed: %+v", res.Hits[0])
	}
}

func TestCheckpointResumeAfterInterrupt(t *testing.T) {
	var mu sync.Mutex
	served := 0
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x:0:0:root")
	})
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	dir := t.TempDir()
	cpPath := filepath.Join(dir, "checkpoint.json")
	store := NewFileCheckpointStore(cpPath)

	// First run: cancel immediately so nothing completes, then verify resume
	// produces the same result as a clean run.
	eng1 := New(Options{Seed: 5, Checkpoint: store, Concurrency: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	interrupted := eng1.Scan(ctx, []*template.Template{tmpl}, []string{srv.URL})
	if interrupted.Status != "running" {
		t.Fatalf("interrupted scan should stay running, got %q", interrupted.Status)
	}

	eng2 := New(Options{Seed: 5, Checkpoint: store, Concurrency: 1})
	resumed := eng2.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	if resumed.Status != "completed" {
		t.Fatalf("resumed scan should complete, got %q", resumed.Status)
	}

	// Clean run for comparison.
	eng3 := New(Options{Seed: 5})
	clean := eng3.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})

	if len(resumed.Hits) != len(clean.Hits) {
		t.Fatalf("resumed hits %d != clean hits %d", len(resumed.Hits), len(clean.Hits))
	}
	for i := range resumed.Hits {
		if resumed.Hits[i].Target != clean.Hits[i].Target ||
			resumed.Hits[i].TemplateID != clean.Hits[i].TemplateID ||
			resumed.Hits[i].VariantID != clean.Hits[i].VariantID {
			t.Fatalf("resumed hit %d differs from clean: %+v vs %+v", i, resumed.Hits[i], clean.Hits[i])
		}
	}
}

func TestFilterBySeverityAndTags(t *testing.T) {
	hits := []Hit{
		{TemplateID: "a", Severity: template.SeverityHigh, Tags: []string{"rce"}},
		{TemplateID: "b", Severity: template.SeverityLow, Tags: []string{"info"}},
		{TemplateID: "c", Severity: template.SeverityCritical, Tags: []string{"rce", "sqli"}},
	}
	high := ApplyFilter(hits, Filter{Severities: []string{"high", "critical"}})
	if len(high) != 2 {
		t.Fatalf("severity filter: want 2, got %d", len(high))
	}
	tagged := ApplyFilter(hits, Filter{Tags: []string{"sqli"}})
	if len(tagged) != 1 || tagged[0].TemplateID != "c" {
		t.Fatalf("tag filter: want 1, got %+v", tagged)
	}
}

func TestDedupeAndSortDeterministic(t *testing.T) {
	hits := []Hit{
		{Target: "b", TemplateID: "t1", VariantID: "v#2", Evidence: []EvidenceNode{{MatcherID: "w"}}},
		{Target: "a", TemplateID: "t1", VariantID: "v#10", Evidence: []EvidenceNode{{MatcherID: "w"}}},
		{Target: "a", TemplateID: "t1", VariantID: "v#2", Evidence: []EvidenceNode{{MatcherID: "w"}}},
		{Target: "a", TemplateID: "t1", VariantID: "v#2", Evidence: []EvidenceNode{{MatcherID: "w", Detail: "dup"}}},
	}
	out := DedupeAndSort(hits)
	if len(out) != 3 {
		t.Fatalf("want 3 after dedupe, got %d", len(out))
	}
	wantOrder := []string{"a|t1|v#2", "a|t1|v#10", "b|t1|v#2"}
	for i, want := range wantOrder {
		got := out[i].Target + "|" + out[i].TemplateID + "|" + out[i].VariantID
		if got != want {
			t.Fatalf("position %d: got %s, want %s", i, got, want)
		}
	}
}

func TestMultipleTargetsProgressIndependently(t *testing.T) {
	fast := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x")
	})
	slow := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x")
	})
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	eng := New(Options{Concurrency: 2, Timeout: 2 * time.Second})
	start := time.Now()
	res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{slow.URL, fast.URL})
	elapsed := time.Since(start)
	if len(res.Hits) != 2 {
		t.Fatalf("want 2 hits (one per target), got %d", len(res.Hits))
	}
	// Both targets should be served concurrently, not sequentially (600ms+).
	if elapsed > 500*time.Millisecond {
		t.Fatalf("targets did not progress independently: took %v", elapsed)
	}
}

func TestVariantDerivationEndToEnd(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" || r.URL.Path == "/b" {
			w.WriteHeader(200)
			fmt.Fprint(w, "root:x")
			return
		}
		w.WriteHeader(404)
	})
	tmpl := &template.Template{
		ID:      "multi",
		Version: template.FormatV2,
		Info:    template.Info{Name: "multi", Severity: template.SeverityMedium},
		Variables: []template.Variable{
			{Name: "p", Values: []string{"a", "b", "c"}},
		},
		Variants: []template.Variant{{
			ID:      "v",
			Request: template.Request{Method: "GET", Path: "/{{p}}"},
		}},
		Matchers: []template.MatcherSpec{
			{ID: "s", Type: "status", Status: []int{200}},
			{ID: "w", Type: "word", Words: []string{"root:"}},
		},
	}
	eng := New(Options{})
	res := eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	if len(res.Hits) != 2 {
		t.Fatalf("want 2 hits (paths a and b), got %d: %+v", len(res.Hits), res.Hits)
	}
	gotPaths := []string{}
	for _, h := range res.Hits {
		gotPaths = append(gotPaths, h.VariantID)
	}
	sort.Strings(gotPaths)
	want := []string{"v#0", "v#1"}
	if strings.Join(gotPaths, ",") != strings.Join(want, ",") {
		t.Fatalf("variant hits = %v, want %v", gotPaths, want)
	}
}

func TestCheckpointFileIsValidJSON(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	tmpl := simpleTemplate("t1", "/", 200, "x")
	dir := t.TempDir()
	cpPath := filepath.Join(dir, "checkpoint.json")
	store := NewFileCheckpointStore(cpPath)
	eng := New(Options{Checkpoint: store})
	eng.Scan(context.Background(), []*template.Template{tmpl}, []string{srv.URL})
	data, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("checkpoint is not valid JSON: %v", err)
	}
	if parsed["status"] != "completed" {
		t.Fatalf("final checkpoint status = %v", parsed["status"])
	}
}

func TestNoGoroutineLeakOnCancel(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
		}
	})
	tmpl := multiVariantTemplate("t1", 20)
	eng := New(Options{Concurrency: 4, Timeout: 30 * time.Second})

	baseline := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *Result, 1)
	go func() { done <- eng.Scan(ctx, []*template.Template{tmpl}, []string{srv.URL}) }()
	time.Sleep(150 * time.Millisecond)
	cancel()
	t0 := time.Now()
	select {
	case <-done:
		t.Logf("scan stopped after %v", time.Since(t0))
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not stop after cancel")
	}
	// Allow time for worker goroutines to wind down.
	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > baseline+4 {
		t.Fatalf("possible goroutine leak: baseline %d, after cancel %d", baseline, after)
	}
}
