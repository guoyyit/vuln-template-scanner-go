// Package result 定义扫描结果、去重排序与导出。
package result

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

// Finding 一条命中结果。
type Finding struct {
	TemplateID string            `json:"template_id"`
	Target     string            `json:"target"`
	Severity   template.Severity `json:"severity"`
	Tags       []string          `json:"tags,omitempty"`
	VariantKey string            `json:"variant_key"`
	Matched    []string          `json:"matched_conditions"` // 命中的条件 ID，可解释
	Evidence   string            `json:"evidence"`           // 命中证据摘要
}

// ErrorKind 错误类别，便于区分呈现。
type ErrorKind string

const (
	ErrTimeout    ErrorKind = "timeout"
	ErrConnection ErrorKind = "connection"
	ErrPanic      ErrorKind = "panic"
	ErrTemplate   ErrorKind = "template"
	ErrCancelled  ErrorKind = "cancelled"
)

// ScanError 归因到具体模板与目标的错误。
type ScanError struct {
	TemplateID string    `json:"template_id"`
	Target     string    `json:"target"`
	Kind       ErrorKind `json:"kind"`
	Message    string    `json:"message"`
}

// Report 一次扫描的最终报告。
type Report struct {
	State    string      `json:"state"` // completed | interrupted
	Findings []Finding   `json:"findings"`
	Errors   []ScanError `json:"errors,omitempty"`
}

// Key 返回命中的去重键：同一模板在同一目标上的同一变体只算一次。
func (f Finding) Key() string {
	return f.TemplateID + "\x00" + f.Target + "\x00" + f.VariantKey
}

// Dedup 按既定规则去重：同一 (模板,目标,变体) 保留首条，
// 并将其余重复项的命中条件合并进来（条件 ID 排序去重），保证与产出顺序无关。
func Dedup(in []Finding) []Finding {
	seen := map[string]int{}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		k := f.Key()
		if i, ok := seen[k]; ok {
			merged := map[string]bool{}
			for _, id := range out[i].Matched {
				merged[id] = true
			}
			for _, id := range f.Matched {
				merged[id] = true
			}
			ids := make([]string, 0, len(merged))
			for id := range merged {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			out[i].Matched = ids
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	return out
}

// Sort 对命中集合做确定性排序：严重级别降序，再按模板、目标、变体键升序。
// 排序只依赖内容，不依赖并发调度顺序。
func Sort(in []Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		ra, rb := template.SeverityRank(a.Severity), template.SeverityRank(b.Severity)
		if ra != rb {
			return ra > rb
		}
		if a.TemplateID != b.TemplateID {
			return a.TemplateID < b.TemplateID
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.VariantKey < b.VariantKey
	})
}

// Filter 按严重级别集合与标签集合过滤；空集合表示不过滤。
// 标签过滤语义：命中任一给定标签即保留。
func Filter(in []Finding, severities map[template.Severity]bool, tags map[string]bool) []Finding {
	if len(tags) > 0 {
		norm := make(map[string]bool, len(tags))
		for t := range tags {
			norm[strings.ToLower(t)] = true
		}
		tags = norm
	}
	out := in[:0:0]
	for _, f := range in {
		if len(severities) > 0 && !severities[f.Severity] {
			continue
		}
		if len(tags) > 0 && !hasAnyTag(f.Tags, tags) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func hasAnyTag(have []string, want map[string]bool) bool {
	for _, t := range have {
		if want[strings.ToLower(t)] {
			return true
		}
	}
	return false
}

// WriteJSON 将报告以结构化 JSON 导出。
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
