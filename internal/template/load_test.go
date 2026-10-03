package template

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadV1TemplateDefaults(t *testing.T) {
	tpl, err := Parse([]byte(`
id: old-style
info:
  name: Old
requests:
  - path: /a
match:
  conditions:
    - type: status
      status: [200]
`))
	if err != nil {
		t.Fatalf("v1 模板应可加载: %v", err)
	}
	if tpl.Version != Version1 {
		t.Fatalf("缺省版本应为 1, got %d", tpl.Version)
	}
	if tpl.Match.Combinator != "any" {
		t.Fatalf("v1 缺省 combinator 应为 any, got %q", tpl.Match.Combinator)
	}
	if tpl.Requests[0].Method != "GET" {
		t.Fatalf("缺省方法应为 GET, got %q", tpl.Requests[0].Method)
	}
	if tpl.Info.Severity != SeverityInfo {
		t.Fatalf("缺省严重级别应为 info, got %q", tpl.Info.Severity)
	}
	if tpl.Match.Conditions[0].ID != "c0" {
		t.Fatalf("缺省条件 ID 应为 c0, got %q", tpl.Match.Conditions[0].ID)
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	tpl, err := Parse([]byte(`
id: future
version: 2
future_field: whatever
info:
  name: F
  severity: high
  unknown_nested: 1
requests:
  - path: /x
    new_request_option: true
match:
  conditions:
    - type: body
      contains: [ok]
      future_condition_field: [1,2]
`))
	if err != nil {
		t.Fatalf("未知字段不应导致失败: %v", err)
	}
	if tpl.ID != "future" {
		t.Fatal("模板应正常解析")
	}
}

func TestLoadDirIsolatesFailures(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "good.yaml", `
id: good
version: 2
info: {name: G, severity: low}
requests: [{path: /g}]
match:
  conditions: [{type: status, status: [200]}]
`)
	write(t, dir, "bad-yaml.yaml", "id: [unclosed")
	write(t, dir, "bad-cond.yaml", `
id: badcond
version: 2
requests: [{path: /b}]
match:
  conditions: [{type: teleport}]
`)
	write(t, dir, "not-a-template.txt", "id: ignored")

	tpls, errs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tpls) != 1 || tpls[0].ID != "good" {
		t.Fatalf("应只加载成功模板, got %+v", tpls)
	}
	if len(errs) != 2 {
		t.Fatalf("应有 2 个加载错误, got %d: %v", len(errs), errs)
	}
	for _, le := range errs {
		if le.Path == "" || le.Reason == "" {
			t.Fatalf("错误应携带路径与原因: %+v", le)
		}
	}
}

func TestInvalidVersionRejected(t *testing.T) {
	_, err := Parse([]byte("id: x\nversion: 99\nrequests: [{path: /}]\nmatch: {conditions: [{type: status, status: [200]}]}\n"))
	if err == nil {
		t.Fatal("不支持的版本应报错")
	}
}

func TestV1RejectsHeaderCondition(t *testing.T) {
	_, err := Parse([]byte(`
id: v1hdr
requests: [{path: /}]
match:
  conditions: [{type: header, header: X-A, contains: [b]}]
`))
	if err == nil {
		t.Fatal("v1 模板使用 header 匹配应报可读错误")
	}
}
