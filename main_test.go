package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEndToEndCLI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>admin login dashboard</html>"))
	})
	mux.HandleFunc("/administrator", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	mux.HandleFunc("/wp-admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	mux.HandleFunc("/manage", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("APP_KEY=base64:abc\nDB_PASSWORD=secret\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("welcome"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "result.json")
	cpPath := filepath.Join(dir, "checkpoint.json")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--templates", "examples/templates",
		"--targets", srv.URL,
		"--output", outPath,
		"--checkpoint", cpPath,
		"--seed", "42",
		"--concurrency", "2",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Status string `json:"status"`
		Hits   []struct {
			TemplateID string `json:"template_id"`
			Severity   string `json:"severity"`
			Target     string `json:"target"`
			Evidence   []struct {
				Detail string `json:"detail"`
			} `json:"evidence"`
		} `json:"hits"`
		Errors []struct {
			TemplateID string `json:"template_id"`
			Phase      string `json:"phase"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("status = %q", res.Status)
	}
	// All three templates should hit: admin-panel, env-file, server-header.
	if len(res.Hits) != 3 {
		t.Fatalf("want 3 hits, got %d: %+v (errors: %+v)", len(res.Hits), res.Hits, res.Errors)
	}
	got := map[string]bool{}
	for _, h := range res.Hits {
		got[h.TemplateID] = true
		if h.Target != srv.URL {
			t.Fatalf("hit target = %q", h.Target)
		}
		if len(h.Evidence) == 0 {
			t.Fatalf("hit %s has no evidence", h.TemplateID)
		}
	}
	for _, id := range []string{"admin-panel-exposed", "env-file-exposure", "server-header-disclosure"} {
		if !got[id] {
			t.Fatalf("missing hit for template %q", id)
		}
	}

	// Resume run: should complete with identical hits, no duplicates.
	var stdout2, stderr2 bytes.Buffer
	if err := run([]string{
		"--templates", "examples/templates",
		"--targets", srv.URL,
		"--output", outPath,
		"--checkpoint", cpPath,
		"--seed", "42",
	}, &stdout2, &stderr2); err != nil {
		t.Fatalf("resume run failed: %v", err)
	}
	data2, _ := os.ReadFile(outPath)
	var res2 struct {
		Status string `json:"status"`
		Hits   []struct {
			TemplateID string `json:"template_id"`
		} `json:"hits"`
	}
	_ = json.Unmarshal(data2, &res2)
	if res2.Status != "completed" {
		t.Fatalf("resume status = %q", res2.Status)
	}
	if len(res2.Hits) != 3 {
		t.Fatalf("resume produced %d hits, want 3 (no duplicates)", len(res2.Hits))
	}
}

func TestCLIFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("APP_KEY=x\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "result.json")
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"--templates", "examples/templates",
		"--targets", srv.URL,
		"--output", outPath,
		"--severity", "critical",
	}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(outPath)
	var res struct {
		Hits []struct {
			TemplateID string `json:"template_id"`
			Severity   string `json:"severity"`
		} `json:"hits"`
	}
	_ = json.Unmarshal(data, &res)
	if len(res.Hits) != 1 || res.Hits[0].TemplateID != "env-file-exposure" {
		t.Fatalf("severity filter should leave only critical hit, got %+v", res.Hits)
	}
}

func TestCLIRequiresTemplates(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--targets", "http://127.0.0.1:1"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --templates missing")
	}
}
