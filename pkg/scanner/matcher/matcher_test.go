package matcher

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func resp(status int, headers map[string]string, body string) *Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &Response{StatusCode: status, Headers: h, Body: []byte(body)}
}

func TestStatusMatcher(t *testing.T) {
	m, err := Compile(template.MatcherSpec{ID: "s", Type: "status", Status: []int{200, 204}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(resp(200, nil, "")).Matched {
		t.Fatal("200 should match")
	}
	if m.Match(resp(500, nil, "")).Matched {
		t.Fatal("500 should not match")
	}
}

func TestWordMatcher(t *testing.T) {
	m, err := Compile(template.MatcherSpec{ID: "w", Type: "word", Part: "body", Words: []string{"root:", "bin/"}})
	if err != nil {
		t.Fatal(err)
	}
	ev := m.Match(resp(200, nil, "root:x:0:0:root:/root:/bin/bash"))
	if !ev.Matched || ev.Snippet == "" {
		t.Fatalf("should match with snippet, got %+v", ev)
	}
	if m.Match(resp(200, nil, "nothing here")).Matched {
		t.Fatal("should not match")
	}

	all, err := Compile(template.MatcherSpec{ID: "w2", Type: "word", Words: []string{"root:", "nologin"}, Operator: "and"})
	if err != nil {
		t.Fatal(err)
	}
	if all.Match(resp(200, nil, "root:x root:/bin/nologin")).Matched != true {
		t.Fatal("and word match should match")
	}
	if all.Match(resp(200, nil, "root:x")).Matched {
		t.Fatal("and word match should fail with one word missing")
	}
}

func TestWordMatcherCaseInsensitive(t *testing.T) {
	m, err := Compile(template.MatcherSpec{ID: "w", Type: "word", Words: []string{"ROOT"}, Case: "insensitive"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(resp(200, nil, "root:x")).Matched {
		t.Fatal("case insensitive match failed")
	}
}

func TestRegexMatcher(t *testing.T) {
	m, err := Compile(template.MatcherSpec{ID: "r", Type: "regex", Regex: []string{`root:.*:0:0`}})
	if err != nil {
		t.Fatal(err)
	}
	ev := m.Match(resp(200, nil, "root:x:0:0:root"))
	if !ev.Matched || ev.Snippet == "" {
		t.Fatalf("regex should match with snippet, got %+v", ev)
	}
	if m.Match(resp(200, nil, "bin:x:1:1")).Matched {
		t.Fatal("regex should not match")
	}
}

func TestHeaderMatcher(t *testing.T) {
	m, err := Compile(template.MatcherSpec{ID: "h", Type: "header", Header: "Server", Words: []string{"nginx"}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(resp(200, map[string]string{"Server": "nginx/1.25"}, "")).Matched {
		t.Fatal("header word should match")
	}
	if m.Match(resp(200, map[string]string{"Server": "apache"}, "")).Matched {
		t.Fatal("header word should not match")
	}

	yes := true
	exists, err := Compile(template.MatcherSpec{ID: "h2", Type: "header", Header: "X-Powered-By", Exists: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if !exists.Match(resp(200, map[string]string{"X-Powered-By": "PHP"}, "")).Matched {
		t.Fatal("exists should match")
	}
	if exists.Match(resp(200, nil, "")).Matched {
		t.Fatal("exists should not match when header absent")
	}
}

func TestLogicMatcher(t *testing.T) {
	spec := template.MatcherSpec{
		ID: "logic1", Type: "logic", Operator: "and",
		Matchers: []template.MatcherSpec{
			{ID: "s", Type: "status", Status: []int{200}},
			{ID: "w", Type: "word", Words: []string{"root:"}},
		},
	}
	m, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(resp(200, nil, "root:x")).Matched {
		t.Fatal("and logic should match")
	}
	if m.Match(resp(200, nil, "bin/x")).Matched {
		t.Fatal("and logic should fail")
	}
	if m.Match(resp(404, nil, "root:x")).Matched {
		t.Fatal("and logic should fail on status")
	}

	orSpec := spec
	orSpec.ID = "logic2"
	orSpec.Operator = "or"
	orM, err := Compile(orSpec)
	if err != nil {
		t.Fatal(err)
	}
	if !orM.Match(resp(404, nil, "root:x")).Matched {
		t.Fatal("or logic should match via word")
	}

	notSpec := template.MatcherSpec{
		ID: "logic3", Type: "logic", Operator: "not",
		Matchers: []template.MatcherSpec{{ID: "s", Type: "status", Status: []int{404}}},
	}
	notM, err := Compile(notSpec)
	if err != nil {
		t.Fatal(err)
	}
	if !notM.Match(resp(200, nil, "")).Matched {
		t.Fatal("not logic should match")
	}
	if notM.Match(resp(404, nil, "")).Matched {
		t.Fatal("not logic should fail")
	}
}

func TestNegateMatcher(t *testing.T) {
	m, err := Compile(template.MatcherSpec{ID: "s", Type: "status", Status: []int{200}, Negate: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.Match(resp(200, nil, "")).Matched {
		t.Fatal("negated status should not match 200")
	}
	if !m.Match(resp(500, nil, "")).Matched {
		t.Fatal("negated status should match 500")
	}
}

func TestEvidenceTree(t *testing.T) {
	spec := template.MatcherSpec{
		ID: "root", Type: "logic", Operator: "and",
		Matchers: []template.MatcherSpec{
			{ID: "s", Type: "status", Status: []int{200}},
			{ID: "w", Type: "word", Words: []string{"secret"}},
		},
	}
	m, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	ev := m.Match(resp(200, nil, "the secret data"))
	if !ev.Matched {
		t.Fatal("should match")
	}
	if len(ev.Children) != 2 {
		t.Fatalf("evidence should carry 2 children, got %d", len(ev.Children))
	}
}

func TestInvalidRegex(t *testing.T) {
	if _, err := Compile(template.MatcherSpec{ID: "r", Type: "regex", Regex: []string{"[invalid"}}); err == nil {
		t.Fatal("invalid regex should fail compile")
	}
}

func TestCharsetDecoding(t *testing.T) {
	gbk := simplifiedchinese.GBK.NewEncoder()
	encoded, err := gbk.Bytes([]byte("管理员密码"))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewReader(encoded)
	r := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=gbk"}},
		Body:       io.NopCloser(body),
	}
	out := ReadResponse(r, 0)
	if out.Charset != "gbk" {
		t.Fatalf("want gbk, got %q", out.Charset)
	}
	if string(out.Body) != "管理员密码" {
		t.Fatalf("decoded body mismatch: %q", string(out.Body))
	}
}

func TestBodyCapAndTruncation(t *testing.T) {
	large := bytes.Repeat([]byte("a"), 100)
	r := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(bytes.NewReader(large)),
	}
	out := ReadResponse(r, 10)
	if len(out.Body) != 10 {
		t.Fatalf("body should be capped at 10 bytes, got %d", len(out.Body))
	}
	if !out.Truncated {
		t.Fatal("truncated should be true")
	}
}
