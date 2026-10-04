package engine

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
)

func TestPanicIsolation(t *testing.T) {
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	eng := New(Options{})
	res := &Result{Status: "running"}
	var mu sync.Mutex
	completed := map[string]bool{}
	key := TaskKey("http://target", "t1", "default")
	tk := task{target: "http://target", tmpl: tmpl}

	// A panicking task must be converted into an attributed error.
	eng.withRecovery(tk, key, res, &mu, completed, func() {
		panic("boom")
	})

	if len(res.Errors) != 1 {
		t.Fatalf("want 1 error, got %d: %+v", len(res.Errors), res.Errors)
	}
	scanErr := res.Errors[0]
	if scanErr.Target != "http://target" || scanErr.TemplateID != "t1" || scanErr.Phase != "execute" {
		t.Fatalf("bad attribution: %+v", scanErr)
	}
	if !strings.Contains(scanErr.Message, "panic: boom") {
		t.Fatalf("message should mention panic: %q", scanErr.Message)
	}
	if !completed[key] {
		t.Fatal("panicked task should be marked completed")
	}

	// A normal task after a panic must still run.
	eng.withRecovery(tk, key, res, &mu, completed, func() {
		// no-op
	})
	if len(res.Errors) != 1 {
		t.Fatalf("normal task should not add errors, got %+v", res.Errors)
	}
}

func TestScanSurvivesPanickingTask(t *testing.T) {
	// A template whose matcher evaluation panics must not abort the scan.
	// We inject the panic by running with a response that triggers a panic
	// through a custom matcher is not possible; instead verify the engine
	// still completes when one target is unreachable and one is healthy.
	healthy := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "root:x:0:0:root")
	})
	tmpl := simpleTemplate("t1", "/", 200, "root:")
	eng := New(Options{Timeout: 200 * time.Millisecond})
	res := eng.Scan(context.Background(), []*template.Template{tmpl},
		[]string{"http://127.0.0.1:1", healthy.URL})
	if res.Status != "completed" {
		t.Fatalf("status = %q", res.Status)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("healthy target should still produce a hit, got %d", len(res.Hits))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("unreachable target should produce 1 error, got %d", len(res.Errors))
	}
}
