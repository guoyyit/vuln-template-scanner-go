package matcher

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

func snap(status int, header map[string]string, body string) *Snapshot {
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	return &Snapshot{StatusCode: status, Header: h, Body: body}
}

func TestStatusMatch(t *testing.T) {
	m := template.MatchBlock{Combinator: "any", Conditions: []template.Condition{
		{ID: "s", Type: "status", Status: []int{200, 302}},
	}}
	o := Evaluate(m, snap(302, nil, ""))
	if !o.Matched || o.ConditionIDs[0] != "s" {
		t.Fatalf("状态码应命中: %+v", o)
	}
	if Evaluate(m, snap(404, nil, "")).Matched {
		t.Fatal("404 不应命中")
	}
}

func TestHeaderAndBodyMatch(t *testing.T) {
	m := template.MatchBlock{Combinator: "all", Conditions: []template.Condition{
		{ID: "h", Type: "header", Header: "x-server", Contains: []string{"mini"}},
		{ID: "b", Type: "body", Regex: []string{"wel+ome"}},
	}}
	s := snap(200, map[string]string{"X-Server": "mini/1.0"}, "say wellome")
	o := Evaluate(m, s)
	if !o.Matched || len(o.ConditionIDs) != 2 {
		t.Fatalf("all 组合应全部命中: %+v", o)
	}
	if !strings.Contains(o.Evidence, "[h]") || !strings.Contains(o.Evidence, "[b]") {
		t.Fatalf("证据应可解释到条件: %q", o.Evidence)
	}
	// 任一不满足则 all 不命中。
	if Evaluate(m, snap(200, map[string]string{"X-Server": "other"}, "say wellome")).Matched {
		t.Fatal("all 组合在部分不满足时不应命中")
	}
}

func TestNegate(t *testing.T) {
	m := template.MatchBlock{Combinator: "any", Conditions: []template.Condition{
		{ID: "n", Type: "body", Contains: []string{"error"}, Negate: true},
	}}
	if !Evaluate(m, snap(200, nil, "all good")).Matched {
		t.Fatal("取反条件：不含 error 应命中")
	}
	if Evaluate(m, snap(200, nil, "an error occurred")).Matched {
		t.Fatal("取反条件：含 error 不应命中")
	}
}

func TestAnyCombinator(t *testing.T) {
	m := template.MatchBlock{Combinator: "any", Conditions: []template.Condition{
		{ID: "a", Type: "status", Status: []int{500}},
		{ID: "b", Type: "body", Contains: []string{"token"}},
	}}
	o := Evaluate(m, snap(200, nil, "here is token"))
	if !o.Matched || len(o.ConditionIDs) != 1 || o.ConditionIDs[0] != "b" {
		t.Fatalf("any 组合应命中 b: %+v", o)
	}
}

func TestCharsetGBKBody(t *testing.T) {
	var gbkBody []byte
	r := transform.NewReader(strings.NewReader("后台管理系统登录成功"), simplifiedchinese.GBK.NewEncoder())
	gbkBody, _ = io.ReadAll(r)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=gbk"}},
		Body:       io.NopCloser(strings.NewReader(string(gbkBody))),
	}
	s, err := NewSnapshot(resp, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	m := template.MatchBlock{Combinator: "any", Conditions: []template.Condition{
		{ID: "g", Type: "body", Contains: []string{"登录成功"}},
	}}
	if !Evaluate(m, s).Matched {
		t.Fatalf("GBK 编码正文应能正确匹配, body=%q", s.Body)
	}
}

func TestBodyTruncation(t *testing.T) {
	big := strings.Repeat("A", 1<<20) // 1MB
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(big)),
	}
	s, err := NewSnapshot(resp, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Truncated || len(s.Body) != 1024 {
		t.Fatalf("大响应应被截断到上限: truncated=%v len=%d", s.Truncated, len(s.Body))
	}
}

func TestInvalidRegexTolerated(t *testing.T) {
	m := template.MatchBlock{Combinator: "any", Conditions: []template.Condition{
		{ID: "r", Type: "body", Regex: []string{"(["}},
	}}
	if Evaluate(m, snap(200, nil, "anything")).Matched {
		t.Fatal("非法正则应视为不命中")
	}
}
