package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

const cpTemplateA = `
id: cp-a
version: 2
info: {name: A, severity: high, tags: [demo]}
variables: {w: [hit, miss]}
requests: [{path: "/a/{{w}}"}]
match: {conditions: [{type: body, contains: ["vulnerable"]}]}
`

const cpTemplateB = `
id: cp-b
version: 2
info: {name: B, severity: low, tags: [demo]}
variables: {w: [hit, miss]}
requests: [{path: "/b/{{w}}"}]
match: {conditions: [{type: body, contains: ["vulnerable"]}]}
`

func cpServer(t *testing.T, counter *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if counter != nil {
			atomic.AddInt32(counter, 1)
		}
		if len(r.URL.Path) >= 5 && r.URL.Path[3:6] == "hit" {
			w.Write([]byte("vulnerable"))
			return
		}
		w.WriteHeader(404)
	}))
}

func fullRunFindings(t *testing.T, targets []string) string {
	t.Helper()
	tpls := []*template.Template{mustParse(t, cpTemplateA), mustParse(t, cpTemplateB)}
	eng := New(DefaultOptions(), tpls)
	rep, err := eng.Run(context.Background(), targets)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != "completed" {
		t.Fatalf("完整扫描应完成: %s", rep.State)
	}
	data, _ := json.Marshal(rep.Findings)
	return string(data)
}

// TestCheckpointResume 中断后从检查点恢复，结果须与一次完整扫描一致。
func TestCheckpointResume(t *testing.T) {
	srv1 := cpServer(t, nil)
	defer srv1.Close()
	srv2 := cpServer(t, nil)
	defer srv2.Close()
	targets := []string{srv1.URL, srv2.URL}

	want := fullRunFindings(t, targets)

	cpPath := filepath.Join(t.TempDir(), "scan.checkpoint.json")
	tpls := []*template.Template{mustParse(t, cpTemplateA), mustParse(t, cpTemplateB)}

	// 第一次运行：等到至少一个 (目标,模板) 对提交后取消。
	ctx, cancel := context.WithCancel(context.Background())
	opts1 := DefaultOptions()
	opts1.CheckpointPath = cpPath
	opts1.PerTargetRate = 5 // 拉长执行窗口，确保能中断在中途
	eng1 := New(opts1, tpls)
	done := make(chan struct{})
	go func() {
		_, _ = eng1.Run(ctx, targets)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		cp, _ := loadCheckpoint(cpPath)
		if cp != nil && len(cp.Completed) >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("检查点未及时提交")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	cp, err := loadCheckpoint(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp.State != "interrupted" && cp.State != "running" {
		t.Fatalf("中断后的检查点状态应为 running/interrupted, got %s", cp.State)
	}
	if len(cp.Completed) == 0 || len(cp.Completed) >= 4 {
		t.Fatalf("应只完成部分 (目标,模板) 对: %d", len(cp.Completed))
	}

	// 第二次运行：从检查点恢复。
	opts2 := DefaultOptions()
	opts2.CheckpointPath = cpPath
	opts2.Resume = true
	eng2 := New(opts2, tpls)
	rep2, err := eng2.Run(context.Background(), targets)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.State != "completed" {
		t.Fatalf("恢复后应完成, got %s", rep2.State)
	}
	got, _ := json.Marshal(rep2.Findings)
	if string(got) != want {
		t.Fatalf("恢复扫描结果应与完整扫描一致:\n got %s\nwant %s", got, want)
	}

	// 最终检查点状态为 completed，且命中无重复。
	cp, err = loadCheckpoint(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp.State != "completed" {
		t.Fatalf("完成后检查点状态应为 completed, got %s", cp.State)
	}
	seen := map[string]bool{}
	for _, f := range rep2.Findings {
		if seen[f.Key()] {
			t.Fatalf("命中重复: %+v", f)
		}
		seen[f.Key()] = true
	}
}

// TestResumeCompletedCheckpoint 已完成的检查点恢复时不重复执行请求。
func TestResumeCompletedCheckpoint(t *testing.T) {
	var count int32
	srv := cpServer(t, &count)
	defer srv.Close()

	cpPath := filepath.Join(t.TempDir(), "cp.json")
	tpls := []*template.Template{mustParse(t, cpTemplateA)}
	opts := DefaultOptions()
	opts.CheckpointPath = cpPath
	eng := New(opts, tpls)
	rep, err := eng.Run(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != "completed" {
		t.Fatal("应完成")
	}
	n1 := atomic.LoadInt32(&count)
	if n1 == 0 {
		t.Fatal("应发出过请求")
	}

	// 恢复已完成的扫描：不应再发请求，结果一致。
	opts2 := DefaultOptions()
	opts2.CheckpointPath = cpPath
	opts2.Resume = true
	eng2 := New(opts2, tpls)
	rep2, err := eng2.Run(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&count) != n1 {
		t.Fatalf("已完成的扫描恢复时不应重复请求: %d -> %d", n1, atomic.LoadInt32(&count))
	}
	f1, _ := json.Marshal(rep.Findings)
	f2, _ := json.Marshal(rep2.Findings)
	if string(f1) != string(f2) {
		t.Fatal("恢复结果应与首次一致")
	}
}
