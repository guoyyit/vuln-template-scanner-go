package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guoyyit/vuln-template-scanner-go/internal/result"
	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

func mustParse(t *testing.T, y string) *template.Template {
	t.Helper()
	tpl, err := template.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

const basicTemplate = `
id: t-basic
version: 2
info: {name: Basic, severity: high, tags: [demo]}
requests:
  - path: /vuln
match:
  combinator: all
  conditions:
    - {id: st, type: status, status: [200]}
    - {id: bd, type: body, contains: ["vulnerable"]}
`

func TestEndToEndFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("this host is vulnerable"))
	}))
	defer srv.Close()

	eng := New(DefaultOptions(), []*template.Template{mustParse(t, basicTemplate)})
	rep, err := eng.Run(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != "completed" {
		t.Fatalf("应完成, got %s", rep.State)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("应有 1 条命中, got %+v", rep.Findings)
	}
	f0 := rep.Findings[0]
	if f0.TemplateID != "t-basic" || f0.Target != srv.URL || f0.Severity != template.SeverityHigh {
		t.Fatalf("命中应携带模板/目标/严重级别: %+v", f0)
	}
	if len(f0.Matched) != 2 || !strings.Contains(f0.Evidence, "vulnerable") {
		t.Fatalf("命中应可解释: %+v", f0)
	}
}

func TestPerTargetConcurrencyLimit(t *testing.T) {
	var cur, max int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&cur, 1)
		for {
			m := atomic.LoadInt32(&max)
			if c <= m || atomic.CompareAndSwapInt32(&max, m, c) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tpl := mustParse(t, `
id: t-conc
version: 2
variables: {w: [a, b, c, d, e, f, g, h]}
requests: [{path: "/{{w}}"}]
match: {conditions: [{type: status, status: [200]}]}
`)
	opts := DefaultOptions()
	opts.PerTargetConcurrency = 2
	eng := New(opts, []*template.Template{tpl})
	if _, err := eng.Run(context.Background(), []string{srv.URL}); err != nil {
		t.Fatal(err)
	}
	if m := atomic.LoadInt32(&max); m > 2 {
		t.Fatalf("单目标并发超过上限: %d", m)
	}
}

func TestPerTargetRateLimit(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tpl := mustParse(t, `
id: t-rate
version: 2
variables: {w: [a, b, c, d, e]}
requests: [{path: "/{{w}}"}, {path: "/x{{w}}"}]
match: {conditions: [{type: status, status: [200]}]}
`)
	opts := DefaultOptions()
	opts.PerTargetRate = 20 // 20/s => 10 个请求至少约 450ms
	opts.PerTargetConcurrency = 8
	eng := New(opts, []*template.Template{tpl})
	start := time.Now()
	if _, err := eng.Run(context.Background(), []string{srv.URL}); err != nil {
		t.Fatal(err)
	}
	el := time.Since(start)
	if got := atomic.LoadInt32(&count); got != 10 {
		t.Fatalf("应发出 10 个请求, got %d", got)
	}
	if el < 400*time.Millisecond {
		t.Fatalf("速率限制未生效, 10 请求仅耗时 %v", el)
	}
}

func TestRequestTimeoutClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	tpl := mustParse(t, `
id: t-slow
version: 2
requests: [{path: /slow}]
match: {conditions: [{type: status, status: [200]}]}
`)
	opts := DefaultOptions()
	opts.RequestTimeout = 0.2
	eng := New(opts, []*template.Template{tpl})
	rep, err := eng.Run(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Fatal("超时不得判定为命中")
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Kind != result.ErrTimeout {
		t.Fatalf("应归类为超时错误: %+v", rep.Errors)
	}
	if rep.Errors[0].TemplateID != "t-slow" || rep.Errors[0].Target != srv.URL {
		t.Fatalf("错误应归因到模板与目标: %+v", rep.Errors[0])
	}
}

func TestConnectionErrorNotFinding(t *testing.T) {
	// 启动后立即关闭，得到可连接但已拒绝对端口。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	tpl := mustParse(t, basicTemplate)
	eng := New(DefaultOptions(), []*template.Template{tpl})
	rep, err := eng.Run(context.Background(), []string{url})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Fatal("连接中断不得判定为命中")
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Kind != result.ErrConnection {
		t.Fatalf("应归类为连接错误: %+v", rep.Errors)
	}
}

func TestPanicIsolated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this host is vulnerable"))
	}))
	defer srv.Close()

	good := mustParse(t, basicTemplate)
	bad := mustParse(t, strings.Replace(basicTemplate, "t-basic", "t-panic", 1))
	eng := New(DefaultOptions(), []*template.Template{bad, good})
	var once int32
	eng.beforeVariant = func(job pairJob) {
		if job.tpl.ID == "t-panic" && atomic.CompareAndSwapInt32(&once, 0, 1) {
			panic("boom")
		}
	}
	rep, err := eng.Run(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	var panicErr bool
	for _, e := range rep.Errors {
		if e.Kind == result.ErrPanic && e.TemplateID == "t-panic" {
			panicErr = true
		}
	}
	if !panicErr {
		t.Fatalf("崩溃应被记录为 panic 错误: %+v", rep.Errors)
	}
	// 其余模板不受影响。
	found := false
	for _, f := range rep.Findings {
		if f.TemplateID == "t-basic" {
			found = true
		}
	}
	if !found {
		t.Fatalf("单个模板崩溃不应影响其他模板: %+v", rep.Findings)
	}
}

func TestTemplateVariantOverflowIsolated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this host is vulnerable"))
	}))
	defer srv.Close()

	big := mustParse(t, `
id: t-big
version: 2
variables: {a: [1,2,3,4,5], b: [1,2,3,4,5]}
requests: [{path: "/{{a}}/{{b}}"}]
match: {conditions: [{type: status, status: [200]}]}
`)
	good := mustParse(t, basicTemplate)
	opts := DefaultOptions()
	opts.MaxVariants = 10
	eng := New(opts, []*template.Template{big, good})
	rep, err := eng.Run(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	var tplErr bool
	for _, e := range rep.Errors {
		if e.Kind == result.ErrTemplate && e.TemplateID == "t-big" {
			tplErr = true
		}
	}
	if !tplErr {
		t.Fatalf("变体超限应记录模板级错误: %+v", rep.Errors)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].TemplateID != "t-basic" {
		t.Fatalf("其余模板应正常执行: %+v", rep.Findings)
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/hit") {
			w.Write([]byte("this host is vulnerable"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	tpl := mustParse(t, `
id: t-det
version: 2
info: {name: D, severity: medium, tags: [demo]}
variables: {w: [hit1, miss1, hit2, miss2, hit3]}
requests: [{path: "/{{w}}"}]
match: {conditions: [{type: body, contains: ["vulnerable"]}]}
`)
	run := func(concurrency int) string {
		opts := DefaultOptions()
		opts.Concurrency = concurrency
		opts.Seed = 42
		eng := New(opts, []*template.Template{tpl})
		rep, err := eng.Run(context.Background(), []string{srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(rep.Findings)
		return string(data)
	}
	first := run(1)
	for _, c := range []int{4, 16, 4} {
		if got := run(c); got != first {
			t.Fatalf("并发度 %d 下结果不一致:\n%s\n%s", c, got, first)
		}
	}
}

func TestCancelInterruptsAndNoLeak(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // 阻塞直到测试结束
	}))
	defer srv.Close()
	defer close(block)

	tpl := mustParse(t, `
id: t-block
version: 2
variables: {w: [a, b, c, d, e, f, g, h]}
requests: [{path: "/{{w}}"}]
match: {conditions: [{type: status, status: [200]}]}
`)
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	opts := DefaultOptions()
	opts.RequestTimeout = 30
	eng := New(opts, []*template.Template{tpl})
	done := make(chan *result.Report, 1)
	go func() {
		rep, _ := eng.Run(ctx, []string{srv.URL})
		done <- rep
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case rep := <-done:
		if rep.State != "interrupted" {
			t.Fatalf("取消后状态应为 interrupted, got %s", rep.State)
		}
		if len(rep.Findings) != 0 {
			t.Fatal("被中断的请求不得产生命中")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后扫描未能及时结束")
	}
	// 等待协程退出，确认无残留。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("存在残留协程: before=%d now=%d", before, runtime.NumGoroutine())
}
