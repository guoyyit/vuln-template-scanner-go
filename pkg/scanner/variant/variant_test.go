package variant

import (
	"strings"
	"testing"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
)

func TestNoVariablesSingleVariant(t *testing.T) {
	tmpl := &template.Template{
		ID:       "t",
		Request:  template.Request{Method: "GET", Path: "/"},
		Variants: []template.Variant{{ID: "default", Request: template.Request{Method: "GET", Path: "/"}}},
	}
	reqs, err := Derive(tmpl, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].VariantID != "default" {
		t.Fatalf("want 1 default variant, got %+v", reqs)
	}
}

func TestCartesianProductOrder(t *testing.T) {
	tmpl := &template.Template{
		ID: "t",
		Variables: []template.Variable{
			{Name: "a", Values: []string{"a1", "a2"}},
			{Name: "b", Values: []string{"b1", "b2", "b3"}},
		},
		Variants: []template.Variant{{
			ID: "v",
			Request: template.Request{
				Method:  "GET",
				Path:    "/{{a}}/{{b}}",
				Headers: map[string]string{"X": "{{a}}-{{b}}"},
			},
		}},
	}
	reqs, err := Derive(tmpl, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 6 {
		t.Fatalf("want 6 derived requests, got %d", len(reqs))
	}
	wantPaths := []string{"/a1/b1", "/a1/b2", "/a1/b3", "/a2/b1", "/a2/b2", "/a2/b3"}
	for i, want := range wantPaths {
		if reqs[i].Path != want {
			t.Fatalf("req %d path = %q, want %q", i, reqs[i].Path, want)
		}
		if reqs[i].VariantID != "v#"+itoa(i) {
			t.Fatalf("req %d variant id = %q", i, reqs[i].VariantID)
		}
		wantHeader := strings.ReplaceAll(strings.TrimPrefix(want, "/"), "/", "-")
		if reqs[i].Headers["X"] != wantHeader {
			t.Fatalf("req %d header = %q, want %q", i, reqs[i].Headers["X"], wantHeader)
		}
	}
}

func TestRangeVariable(t *testing.T) {
	tmpl := &template.Template{
		ID: "t",
		Variables: []template.Variable{
			{Name: "p", Range: &template.Range{Min: 1, Max: 3, Step: 1}},
		},
		Variants: []template.Variant{{ID: "v", Request: template.Request{Path: "/{{p}}"}}},
	}
	reqs, err := Derive(tmpl, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 3 {
		t.Fatalf("want 3, got %d", len(reqs))
	}
	for i, want := range []string{"/1", "/2", "/3"} {
		if reqs[i].Path != want {
			t.Fatalf("req %d = %q, want %q", i, reqs[i].Path, want)
		}
	}
}

func TestRandomDeterministic(t *testing.T) {
	tmpl := &template.Template{
		ID: "t",
		Variables: []template.Variable{
			{Name: "r", Random: &template.Random{Type: "string", Length: 6, Count: 3}},
		},
		Variants: []template.Variant{{ID: "v", Request: template.Request{Path: "/{{r}}"}}},
	}
	a, err := Derive(tmpl, 42, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Derive(tmpl, 42, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 3 || len(b) != 3 {
		t.Fatalf("want 3 each, got %d/%d", len(a), len(b))
	}
	for i := range a {
		if a[i].Path != b[i].Path {
			t.Fatalf("random not deterministic at %d: %q vs %q", i, a[i].Path, b[i].Path)
		}
		if len(a[i].Path) != 7 { // "/" + 6 chars
			t.Fatalf("random string length wrong: %q", a[i].Path)
		}
	}
	c, _ := Derive(tmpl, 43, 0)
	if a[0].Path == c[0].Path {
		t.Fatal("different seeds should produce different values")
	}
}

func TestVariantCap(t *testing.T) {
	tmpl := &template.Template{
		ID: "t",
		Variables: []template.Variable{
			{Name: "a", Values: []string{"a1", "a2", "a3"}},
			{Name: "b", Values: []string{"b1", "b2", "b3"}},
			{Name: "c", Values: []string{"c1", "c2", "c3"}},
		},
		Variants: []template.Variant{
			{ID: "v1", Request: template.Request{Path: "/"}},
			{ID: "v2", Request: template.Request{Path: "/"}},
		},
	}
	// 3*3*3 = 27 per variant, 2 variants = 54 total.
	if _, err := Derive(tmpl, 1, 50); err == nil {
		t.Fatal("should fail when total variants exceed cap")
	}
	reqs, err := Derive(tmpl, 1, 54)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 54 {
		t.Fatalf("want 54, got %d", len(reqs))
	}
}

func TestMultipleVariantsOrder(t *testing.T) {
	tmpl := &template.Template{
		ID: "t",
		Variants: []template.Variant{
			{ID: "alpha", Request: template.Request{Path: "/a"}},
			{ID: "beta", Request: template.Request{Path: "/b"}},
		},
	}
	reqs, err := Derive(tmpl, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 || reqs[0].VariantID != "alpha" || reqs[1].VariantID != "beta" {
		t.Fatalf("bad order: %+v", reqs)
	}
}

func TestInvalidVariable(t *testing.T) {
	tmpl := &template.Template{
		ID:        "t",
		Variables: []template.Variable{{Name: "x"}},
		Variants:  []template.Variant{{ID: "v", Request: template.Request{Path: "/"}}},
	}
	if _, err := Derive(tmpl, 1, 0); err == nil {
		t.Fatal("variable without values/range/random should fail")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
