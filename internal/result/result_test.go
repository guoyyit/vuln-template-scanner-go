package result

import (
	"reflect"
	"testing"

	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

func f(id, target, key string, sev template.Severity, matched ...string) Finding {
	return Finding{TemplateID: id, Target: target, VariantKey: key, Severity: sev, Matched: matched}
}

func TestDedupMergesConditions(t *testing.T) {
	in := []Finding{
		f("t1", "h1", "r0/", template.SeverityHigh, "c1"),
		f("t1", "h1", "r0/", template.SeverityHigh, "c2"),
		f("t1", "h1", "r1/", template.SeverityHigh, "c1"),
	}
	out := Dedup(in)
	if len(out) != 2 {
		t.Fatalf("应去重为 2 条, got %d", len(out))
	}
	if !reflect.DeepEqual(out[0].Matched, []string{"c1", "c2"}) {
		t.Fatalf("重复命中应合并条件: %v", out[0].Matched)
	}
}

func TestSortDeterministic(t *testing.T) {
	a := []Finding{
		f("b", "h2", "r0/", template.SeverityLow),
		f("a", "h1", "r0/", template.SeverityCritical),
		f("a", "h1", "r0/", template.SeverityHigh),
	}
	b := []Finding{a[2], a[0], a[1]} // 不同到达顺序
	Dedup(a)
	Sort(a)
	Sort(b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("排序不应依赖到达顺序:\n%v\n%v", a, b)
	}
	// 严重级别降序优先。
	if a[0].Severity != template.SeverityCritical {
		t.Fatalf("critical 应排最前: %+v", a[0])
	}
}

func TestFilter(t *testing.T) {
	in := []Finding{
		{TemplateID: "t1", Severity: template.SeverityHigh, Tags: []string{"sqli"}},
		{TemplateID: "t2", Severity: template.SeverityLow, Tags: []string{"xss"}},
	}
	out := Filter(in, map[template.Severity]bool{template.SeverityHigh: true}, nil)
	if len(out) != 1 || out[0].TemplateID != "t1" {
		t.Fatalf("严重级别过滤失败: %+v", out)
	}
	out = Filter(in, nil, map[string]bool{"XSS": true})
	if len(out) != 1 || out[0].TemplateID != "t2" {
		t.Fatalf("标签过滤失败（应大小写不敏感）: %+v", out)
	}
	if len(Filter(in, nil, nil)) != 2 {
		t.Fatal("空过滤条件应保留全部")
	}
}
