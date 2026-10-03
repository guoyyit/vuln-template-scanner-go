// Package engine 编排多目标多模板的并发扫描。
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guoyyit/vuln-template-scanner-go/internal/matcher"
	"github.com/guoyyit/vuln-template-scanner-go/internal/result"
	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

// Options 扫描配置。
type Options struct {
	Concurrency          int     // 全局工作协程数
	PerTargetConcurrency int     // 单目标并发请求上限
	PerTargetRate        float64 // 单目标每秒请求数上限，<=0 表示不限速
	RequestTimeout       float64 // 单请求超时秒数
	MaxBodyBytes         int64   // 响应正文读取上限
	MaxVariants          int     // 单模板变体上限，<=0 用默认值
	CheckpointPath       string  // 检查点文件路径，空表示不启用
	Resume               bool    // 是否从检查点恢复
	Seed                 int64   // 固定随机种子，保证可复现
}

// DefaultOptions 返回默认配置。
func DefaultOptions() Options {
	return Options{
		Concurrency:          16,
		PerTargetConcurrency: 4,
		PerTargetRate:        0,
		RequestTimeout:       10,
		MaxBodyBytes:         1 << 20,
		MaxVariants:          template.DefaultMaxVariants,
		Seed:                 1,
	}
}

// pairJob 一个 (目标, 模板) 执行单元，也是检查点提交粒度。
type pairJob struct {
	target string
	tpl    *template.Template
}

// Engine 扫描引擎。
type Engine struct {
	opts      Options
	templates []*template.Template
	variants  map[string][]template.Variant // 模板 ID -> 预派生变体
	tplErrs   []result.ScanError            // 模板级错误（加载后展开失败等）
	client    *http.Client

	mu       sync.Mutex
	limiters map[string]*limiter
	findings []result.Finding
	errs     []result.ScanError
	done     map[string]bool // 已提交的 (目标,模板) 对

	// beforeVariant 测试钩子：每个变体执行前调用，用于注入崩溃等异常。
	beforeVariant func(job pairJob)
}

// New 创建引擎并预派生所有模板变体；变体非法的模板被隔离为模板级错误。
func New(opts Options, templates []*template.Template) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}
	if opts.PerTargetConcurrency <= 0 {
		opts.PerTargetConcurrency = 4
	}
	if opts.MaxVariants <= 0 {
		opts.MaxVariants = template.DefaultMaxVariants
	}
	e := &Engine{
		opts:      opts,
		templates: templates,
		variants:  map[string][]template.Variant{},
		limiters:  map[string]*limiter{},
		done:      map[string]bool{},
		client: &http.Client{
			// 超时由每请求 context 控制，便于区分取消与超时。
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
	for _, t := range templates {
		vs, err := t.Expand(opts.MaxVariants)
		if err != nil {
			e.tplErrs = append(e.tplErrs, result.ScanError{
				TemplateID: t.ID, Kind: result.ErrTemplate, Message: err.Error(),
			})
			continue
		}
		e.variants[t.ID] = vs
	}
	return e
}

// Run 执行扫描，返回确定性排序后的报告。ctx 取消时返回已完成部分的报告，
// 状态标记为 interrupted，检查点可用于恢复。
func (e *Engine) Run(ctx context.Context, targets []string) (*result.Report, error) {
	targets = normalizeTargets(targets)
	var prior *checkpoint
	if e.opts.Resume {
		cp, err := loadCheckpoint(e.opts.CheckpointPath)
		if err != nil {
			return nil, err
		}
		prior = cp
	}
	if prior != nil {
		e.findings = append(e.findings, prior.Findings...)
		e.errs = append(e.errs, prior.Errors...)
		for _, k := range prior.Completed {
			e.done[k] = true
		}
	}
	e.errs = append(e.errs, e.tplErrs...)

	// 生成任务列表，跳过已完成的 (目标,模板) 对。
	var jobs []pairJob
	for _, target := range targets {
		for _, t := range e.templates {
			if _, ok := e.variants[t.ID]; !ok {
				continue // 模板级失败，已记录错误
			}
			if e.done[pairKey(target, t.ID)] {
				continue
			}
			jobs = append(jobs, pairJob{target: target, tpl: t})
		}
	}

	e.commit("running") // 初始检查点

	jobCh := make(chan pairJob)
	var wg sync.WaitGroup
	for i := 0; i < e.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if ctx.Err() != nil {
					continue
				}
				e.runPair(ctx, job)
				e.commit("running")
			}
		}()
	}
loop:
	for _, job := range jobs {
		select {
		case jobCh <- job:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobCh)
	wg.Wait()

	state := "completed"
	if ctx.Err() != nil || len(e.done) < len(targets)*len(e.variants) {
		state = "interrupted"
	}
	e.commit(state)
	e.client.CloseIdleConnections()

	rep := &result.Report{State: state}
	rep.Findings = result.Dedup(e.findings)
	result.Sort(rep.Findings)
	rep.Errors = sortedErrors(e.errs)
	return rep, nil
}

// runPair 执行一个 (目标,模板) 对，内部对崩溃做隔离恢复。
func (e *Engine) runPair(ctx context.Context, job pairJob) {
	defer func() {
		if r := recover(); r != nil {
			e.addError(result.ScanError{
				TemplateID: job.tpl.ID, Target: job.target,
				Kind: result.ErrPanic, Message: fmt.Sprintf("运行期崩溃: %v", r),
			})
		}
	}()
	lim := e.limiterFor(job.target)
	for _, v := range e.variants[job.tpl.ID] {
		if ctx.Err() != nil {
			return
		}
		if e.beforeVariant != nil {
			e.beforeVariant(job)
		}
		if err := lim.acquire(ctx); err != nil {
			return // 取消/超时，停止该目标后续请求
		}
		outcome, ferr := e.doRequest(ctx, job, v)
		lim.release()
		if ferr != nil {
			e.addError(*ferr)
			continue // 单请求失败不影响其余变体
		}
		if outcome.Matched {
			e.addFinding(result.Finding{
				TemplateID: job.tpl.ID,
				Target:     job.target,
				Severity:   job.tpl.Info.Severity,
				Tags:       job.tpl.Info.Tags,
				VariantKey: v.Key,
				Matched:    outcome.ConditionIDs,
				Evidence:   outcome.Evidence,
			})
		}
	}
	e.mu.Lock()
	e.done[pairKey(job.target, job.tpl.ID)] = true
	e.mu.Unlock()
}

// doRequest 执行单个变体请求并判定；请求失败返回归因错误，绝不产生命中。
func (e *Engine) doRequest(ctx context.Context, job pairJob, v template.Variant) (matcher.Outcome, *result.ScanError) {
	reqCtx := ctx
	cancel := func() {}
	if e.opts.RequestTimeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, seconds(e.opts.RequestTimeout))
	}
	defer cancel()

	url := strings.TrimRight(job.target, "/") + "/" + strings.TrimLeft(v.Path, "/")
	req, err := http.NewRequestWithContext(reqCtx, v.Method, url, strings.NewReader(v.Body))
	if err != nil {
		return matcher.Outcome{}, &result.ScanError{
			TemplateID: job.tpl.ID, Target: job.target,
			Kind: result.ErrTemplate, Message: "构造请求失败: " + err.Error(),
		}
	}
	for k, val := range v.Headers {
		req.Header.Set(k, val)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return matcher.Outcome{}, &result.ScanError{
			TemplateID: job.tpl.ID, Target: job.target,
			Kind: classifyError(ctx, err), Message: err.Error(),
		}
	}
	defer resp.Body.Close()
	snap, err := matcher.NewSnapshot(resp, e.opts.MaxBodyBytes)
	if err != nil {
		return matcher.Outcome{}, &result.ScanError{
			TemplateID: job.tpl.ID, Target: job.target,
			Kind: result.ErrConnection, Message: err.Error(),
		}
	}
	return matcher.Evaluate(job.tpl.Match, snap), nil
}

// classifyError 区分取消、超时与连接错误。
func classifyError(parent context.Context, err error) result.ErrorKind {
	if parent.Err() != nil {
		return result.ErrCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return result.ErrTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return result.ErrTimeout
	}
	return result.ErrConnection
}

func (e *Engine) limiterFor(target string) *limiter {
	e.mu.Lock()
	defer e.mu.Unlock()
	if l, ok := e.limiters[target]; ok {
		return l
	}
	l := newLimiter(e.opts.PerTargetConcurrency, e.opts.PerTargetRate)
	e.limiters[target] = l
	return l
}

func (e *Engine) addFinding(f result.Finding) {
	e.mu.Lock()
	e.findings = append(e.findings, f)
	e.mu.Unlock()
}

func (e *Engine) addError(se result.ScanError) {
	e.mu.Lock()
	e.errs = append(e.errs, se)
	e.mu.Unlock()
}

// commit 将当前进度原子写入检查点。
func (e *Engine) commit(state string) {
	if e.opts.CheckpointPath == "" {
		return
	}
	e.mu.Lock()
	cp := &checkpoint{
		State:    state,
		Seed:     e.opts.Seed,
		Findings: append([]result.Finding(nil), e.findings...),
		Errors:   append([]result.ScanError(nil), e.errs...),
	}
	for k := range e.done {
		cp.Completed = append(cp.Completed, k)
	}
	sort.Strings(cp.Completed)
	e.mu.Unlock()
	_ = saveCheckpoint(e.opts.CheckpointPath, cp) // 检查点写失败不中断扫描
}

func sortedErrors(errs []result.ScanError) []result.ScanError {
	out := append([]result.ScanError(nil), errs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TemplateID != b.TemplateID {
			return a.TemplateID < b.TemplateID
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Message < b.Message
	})
	return out
}

func normalizeTargets(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out) // 调度顺序固定，进一步保证可复现
	return out
}

func seconds(f float64) (d time.Duration) {
	return time.Duration(f * float64(time.Second))
}
