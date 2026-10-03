package template

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var placeholderRe = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)

// Expand 将模板派生为稳定的具体请求序列。
// 派生顺序：请求定义顺序为主序，变量组合按变量名字典序做笛卡尔积（值按声明顺序）。
// 组合数超过 maxVariants 时返回错误，由调用方按模板级失败隔离处理。
func (t *Template) Expand(maxVariants int) ([]Variant, error) {
	if maxVariants <= 0 {
		maxVariants = DefaultMaxVariants
	}
	names := sortedKeys(t.Variables)
	combos := 1
	for _, n := range names {
		if len(t.Variables[n]) == 0 {
			return nil, fmt.Errorf("模板 %q 变量 %q 的取值列表为空", t.ID, n)
		}
		combos *= len(t.Variables[n])
		if combos > maxVariants {
			return nil, fmt.Errorf("模板 %q 变量组合数超过上限 %d", t.ID, maxVariants)
		}
	}
	total := combos * len(t.Requests)
	if total > maxVariants {
		return nil, fmt.Errorf("模板 %q 派生请求数 %d 超过上限 %d", t.ID, total, maxVariants)
	}

	var out []Variant
	idx := 0
	for ri, req := range t.Requests {
		for _, assign := range cartesian(names, t.Variables) {
			v := Variant{
				TemplateID: t.ID,
				Index:      idx,
				Method:     req.Method,
				Path:       substitute(req.Path, assign),
				Headers:    map[string]string{},
				Body:       substitute(req.Body, assign),
			}
			for k, val := range req.Headers {
				v.Headers[k] = substitute(val, assign)
			}
			v.Key = fmt.Sprintf("r%d/%s", ri, keyOf(names, assign))
			out = append(out, v)
			idx++
		}
	}
	return out, nil
}

// substitute 替换占位符；未定义变量保留原文，保证可预期行为。
func substitute(s string, assign map[string]string) string {
	return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		name := placeholderRe.FindStringSubmatch(m)[1]
		if v, ok := assign[name]; ok {
			return v
		}
		return m
	})
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cartesian 按变量名字典序生成笛卡尔积，最后一个变量变化最快，顺序稳定。
func cartesian(names []string, vars map[string][]string) []map[string]string {
	if len(names) == 0 {
		return []map[string]string{{}}
	}
	out := []map[string]string{}
	var rec func(i int, cur map[string]string)
	rec = func(i int, cur map[string]string) {
		if i == len(names) {
			cp := make(map[string]string, len(cur))
			for k, v := range cur {
				cp[k] = v
			}
			out = append(out, cp)
			return
		}
		for _, val := range vars[names[i]] {
			cur[names[i]] = val
			rec(i+1, cur)
		}
	}
	rec(0, map[string]string{})
	return out
}

func keyOf(names []string, assign map[string]string) string {
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, n+"="+assign[n])
	}
	return strings.Join(parts, ",")
}
