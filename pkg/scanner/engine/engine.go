// Package engine orchestrates concurrent, rate limited scanning of multiple
// targets with multiple templates. It provides deterministic result ordering,
// error isolation, cancellation, timeouts and checkpoint based resume.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/matcher"
	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/variant"
	"golang.org/x/time/rate"
)

// Options controls a scan run.
type Options struct {
	Concurrency int           // per target concurrent requests; <=0 default 4
	RateLimit   float64       // per target requests per second; <=0 unlimited
	RateBurst   int           // per target burst; <=0 default
	Timeout     time.Duration // per request timeout; <=0 default 10s
	BodyCap     int           // max body bytes buffered per response
	MaxVariants int           // max derived requests per template
	Seed        int64         // random seed for deterministic derivation
	HTTPClient  *http.Client  // optional custom client
	Checkpoint  CheckpointStore
}

// Hit is a single confirmed match.
type Hit struct {
	TemplateID string            `json:"template_id"`
	Target     string            `json:"target"`
	VariantID  string            `json:"variant_id"`
	Severity   template.Severity `json:"severity"`
	Tags       []string          `json:"tags"`
	Evidence   []EvidenceNode    `json:"evidence"`
}

// EvidenceNode is a flattened evidence tree node.
type EvidenceNode struct {
	MatcherID string `json:"matcher_id"`
	Type      string `json:"type"`
	Detail    string `json:"detail,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// ScanError attributes a failure to a template and target.
type ScanError struct {
	Target     string `json:"target"`
	TemplateID string `json:"template_id,omitempty"`
	VariantID  string `json:"variant_id,omitempty"`
	Phase      string `json:"phase"`
	Message    string `json:"message"`
}

// Result is the outcome of a scan run.
type Result struct {
	ScanID    string      `json:"scan_id"`
	Status    string      `json:"status"` // "running" or "completed"
	Seed      int64       `json:"seed"`
	Targets   []string    `json:"targets"`
	Templates []string    `json:"templates"`
	Hits      []Hit       `json:"hits"`
	Errors    []ScanError `json:"errors"`
	Completed []string    `json:"completed,omitempty"`
}

// task is a single concrete scan unit: one derived request of one template
// against one target.
type task struct {
	target   string
	tmpl     *template.Template
	request  variant.Request
	matchers []matcher.Matcher
}

// Engine runs scans.
type Engine struct {
	opts Options
}

// New creates an Engine with the given options.
func New(opts Options) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.RateBurst <= 0 {
		opts.RateBurst = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.HTTPClient == nil {
		transport := &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: opts.Concurrency + opts.RateBurst,
			IdleConnTimeout:     90 * time.Second,
		}
		opts.HTTPClient = &http.Client{Transport: transport}
	}
	return &Engine{opts: opts}
}

// Scan executes all templates against all targets. It returns when every task
// has finished or the context is cancelled.
func (e *Engine) Scan(ctx context.Context, templates []*template.Template, targets []string) *Result {
	templateIDs := make([]string, 0, len(templates))
	for _, t := range templates {
		templateIDs = append(templateIDs, t.ID)
	}
	sort.Strings(templateIDs)

	seed := e.opts.Seed
	res := &Result{
		ScanID:    scanID(seed, targets, templateIDs),
		Status:    "running",
		Seed:      seed,
		Targets:   append([]string(nil), targets...),
		Templates: templateIDs,
	}
	completed := map[string]bool{}

	// Resume from checkpoint if one exists.
	if e.opts.Checkpoint != nil {
		if loaded, err := e.opts.Checkpoint.Load(); err == nil && loaded != nil {
			if loaded.Status == "completed" {
				return loaded
			}
			if loaded.Seed != 0 {
				seed = loaded.Seed
				res.Seed = seed
			}
			res.Hits = append(res.Hits, loaded.Hits...)
			res.Errors = append(res.Errors, loaded.Errors...)
			completed = RebuildCompleted(loaded)
		}
	}

	// Compile matchers and derive variants once per template so that template
	// level failures are recorded once and attributed to the template.
	type prepared struct {
		tmpl     *template.Template
		matchers []matcher.Matcher
		requests []variant.Request
	}
	preparedTemplates := make([]prepared, 0, len(templates))
	for _, tmpl := range templates {
		ms, err := matcher.CompileAll(tmpl.Matchers)
		if err != nil {
			res.Errors = append(res.Errors, ScanError{
				TemplateID: tmpl.ID, Phase: "compile", Message: err.Error(),
			})
			continue
		}
		reqs, err := variant.Derive(tmpl, seed, e.opts.MaxVariants)
		if err != nil {
			res.Errors = append(res.Errors, ScanError{
				TemplateID: tmpl.ID, Phase: "derive", Message: err.Error(),
			})
			continue
		}
		preparedTemplates = append(preparedTemplates, prepared{tmpl: tmpl, matchers: ms, requests: reqs})
	}

	// Build the task list: every prepared template against every target.
	tasks := make([]task, 0)
	for _, target := range targets {
		for _, p := range preparedTemplates {
			for _, req := range p.requests {
				tasks = append(tasks, task{target: target, tmpl: p.tmpl, request: req, matchers: p.matchers})
			}
		}
	}

	// Group tasks by target so targets progress independently.
	byTarget := make(map[string][]task, len(targets))
	for _, t := range tasks {
		byTarget[t.target] = append(byTarget[t.target], t)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, target := range targets {
		targetTasks := byTarget[target]
		wg.Add(1)
		go func(target string, targetTasks []task) {
			defer wg.Done()
			e.runTarget(ctx, target, targetTasks, res, &mu, &wg, completed)
		}(target, targetTasks)
	}
	wg.Wait()

	if ctx.Err() == nil {
		res.Status = "completed"
	}
	res.Hits = DedupeAndSort(res.Hits)
	res.Errors = SortErrors(res.Errors)
	if e.opts.Checkpoint != nil {
		_ = e.opts.Checkpoint.Save(res)
	}
	// Close idle connections so cancellation does not leak sockets.
	e.opts.HTTPClient.CloseIdleConnections()
	return res
}

// runTarget processes one target's tasks with its own concurrency semaphore
// and rate limiter.
func (e *Engine) runTarget(ctx context.Context, target string, tasks []task, res *Result, mu *sync.Mutex, wg *sync.WaitGroup, completed map[string]bool) {
	sem := make(chan struct{}, e.opts.Concurrency)
	var limiter *rate.Limiter
	if e.opts.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(e.opts.RateLimit), e.opts.RateBurst)
	}

	for _, t := range tasks {
		if ctx.Err() != nil {
			return
		}
		key := TaskKey(t.target, t.tmpl.ID, t.request.VariantID)
		mu.Lock()
		done := completed[key]
		mu.Unlock()
		if done {
			continue
		}
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return
			}
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			defer func() { <-sem }()
			e.runTask(ctx, t, res, mu, completed)
		}(t)
	}
}

// runTask executes one concrete task with panic recovery.
func (e *Engine) runTask(ctx context.Context, t task, res *Result, mu *sync.Mutex, completed map[string]bool) {
	key := TaskKey(t.target, t.tmpl.ID, t.request.VariantID)
	e.withRecovery(t, key, res, mu, completed, func() {
		e.executeTask(ctx, t, res, mu, completed, key)
	})
}

// withRecovery runs fn and converts a runtime panic into an attributed scan
// error so a single task crash cannot abort the whole scan.
func (e *Engine) withRecovery(t task, key string, res *Result, mu *sync.Mutex, completed map[string]bool, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			e.recordError(mu, res, ScanError{
				Target: t.target, TemplateID: t.tmpl.ID, VariantID: t.request.VariantID,
				Phase: "execute", Message: fmt.Sprintf("panic: %v", r),
			})
			e.commit(mu, res, completed, key)
		}
	}()
	fn()
}

func (e *Engine) executeTask(ctx context.Context, t task, res *Result, mu *sync.Mutex, completed map[string]bool, key string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	httpReq, err := buildRequest(timeoutCtx, t.target, t.request)
	if err != nil {
		e.recordError(mu, res, ScanError{
			Target: t.target, TemplateID: t.tmpl.ID, VariantID: t.request.VariantID,
			Phase: "request", Message: err.Error(),
		})
		e.commit(mu, res, completed, key)
		return
	}

	resp, err := e.opts.HTTPClient.Do(httpReq)
	if err != nil {
		// Connection failures are upstream errors, never hits.
		e.recordError(mu, res, ScanError{
			Target: t.target, TemplateID: t.tmpl.ID, VariantID: t.request.VariantID,
			Phase: "request", Message: err.Error(),
		})
		e.commit(mu, res, completed, key)
		return
	}
	mresp := matcher.ReadResponse(resp, e.opts.BodyCap)

	var evidence []EvidenceNode
	for _, m := range t.matchers {
		ev := m.Match(mresp)
		if ev.Matched {
			evidence = append(evidence, flattenEvidence(ev)...)
		}
	}
	if len(evidence) > 0 {
		tags := t.tmpl.Info.Tags
		if tags == nil {
			tags = []string{}
		}
		mu.Lock()
		res.Hits = append(res.Hits, Hit{
			TemplateID: t.tmpl.ID,
			Target:     t.target,
			VariantID:  t.request.VariantID,
			Severity:   t.tmpl.Info.Severity,
			Tags:       append([]string(nil), tags...),
			Evidence:   evidence,
		})
		mu.Unlock()
	}
	e.commit(mu, res, completed, key)
}

func (e *Engine) recordError(mu *sync.Mutex, res *Result, scanErr ScanError) {
	mu.Lock()
	defer mu.Unlock()
	res.Errors = append(res.Errors, scanErr)
}

// commit marks a task completed and persists the checkpoint. The mutex is
// held across the snapshot and write so concurrent appends cannot race with
// marshaling.
func (e *Engine) commit(mu *sync.Mutex, res *Result, completed map[string]bool, key string) {
	mu.Lock()
	defer mu.Unlock()
	completed[key] = true
	if e.opts.Checkpoint != nil {
		keys := make([]string, 0, len(completed))
		for k := range completed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		res.Completed = keys
		_ = e.opts.Checkpoint.Save(res)
	}
}

// flattenEvidence turns an evidence tree into a flat node list.
func flattenEvidence(ev matcher.Evidence) []EvidenceNode {
	out := []EvidenceNode{{
		MatcherID: ev.MatcherID,
		Type:      ev.Type,
		Detail:    ev.Detail,
		Snippet:   ev.Snippet,
	}}
	for _, c := range ev.Children {
		out = append(out, flattenEvidence(c)...)
	}
	return out
}

// buildRequest joins a target base URL with a derived request path.
func buildRequest(ctx context.Context, target string, req variant.Request) (*http.Request, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	path := req.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, base.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	return httpReq, nil
}

// scanID derives a stable identifier from the scan inputs so that re-runs
// with the same arguments resume from the same checkpoint.
func scanID(seed int64, targets, templateIDs []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "seed=%d\n", seed)
	for _, t := range targets {
		fmt.Fprintln(h, t)
	}
	for _, t := range templateIDs {
		fmt.Fprintln(h, t)
	}
	return "scan-" + hex.EncodeToString(h.Sum(nil))[:16]
}
