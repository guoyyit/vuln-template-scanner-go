package template

import (
	"reflect"
	"testing"
)

func TestExpandStableOrder(t *testing.T) {
	tpl := &Template{
		ID: "v",
		Variables: map[string][]string{
			"zeta":  {"1", "2"},
			"alpha": {"a", "b"},
		},
		Requests: []RequestDef{
			{Method: "GET", Path: "/u/{{alpha}}/{{zeta}}"},
			{Method: "POST", Path: "/p", Body: "x={{alpha}}"},
		},
	}
	vs, err := tpl.Expand(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 8 {
		t.Fatalf("应派生 2*2*2=8 个变体, got %d", len(vs))
	}
	var paths []string
	for _, v := range vs {
		paths = append(paths, v.Method+" "+v.Path+" "+v.Body)
	}
	// 变量按名字典序(alpha, zeta)，zeta 变化最快；请求定义顺序为主序。
	want := []string{
		"GET /u/a/1 ", "GET /u/a/2 ", "GET /u/b/1 ", "GET /u/b/2 ",
		"POST /p x=a", "POST /p x=a", "POST /p x=b", "POST /p x=b",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("派生顺序不稳定:\n got %v\nwant %v", paths, want)
	}
	// 序号连续且 Key 稳定。
	for i, v := range vs {
		if v.Index != i {
			t.Fatalf("序号不连续: %d != %d", v.Index, i)
		}
		if v.Key == "" {
			t.Fatal("Key 不应为空")
		}
	}
	// 再次展开结果一致（map 迭代不影响顺序）。
	vs2, _ := tpl.Expand(0)
	if !reflect.DeepEqual(vs, vs2) {
		t.Fatal("两次展开结果不一致")
	}
}

func TestExpandCapExceeded(t *testing.T) {
	tpl := &Template{
		ID:        "big",
		Variables: map[string][]string{"w": {"a", "b", "c", "d", "e"}},
		Requests:  []RequestDef{{Path: "/{{w}}"}},
	}
	if _, err := tpl.Expand(3); err == nil {
		t.Fatal("超过上限应报错")
	}
}

func TestExpandEmptyVariableValues(t *testing.T) {
	tpl := &Template{
		ID:        "empty",
		Variables: map[string][]string{"w": {}},
		Requests:  []RequestDef{{Path: "/{{w}}"}},
	}
	if _, err := tpl.Expand(0); err == nil {
		t.Fatal("空取值列表应报错")
	}
}

func TestExpandUndefinedPlaceholderKept(t *testing.T) {
	tpl := &Template{
		ID:       "undef",
		Requests: []RequestDef{{Path: "/{{missing}}/x"}},
	}
	vs, err := tpl.Expand(0)
	if err != nil {
		t.Fatal(err)
	}
	if vs[0].Path != "/{{missing}}/x" {
		t.Fatalf("未定义变量应保留原文, got %q", vs[0].Path)
	}
}

func TestExpandHeaderSubstitution(t *testing.T) {
	tpl := &Template{
		ID:        "hdr",
		Variables: map[string][]string{"tok": {"abc"}},
		Requests:  []RequestDef{{Path: "/", Headers: map[string]string{"X-T": "{{tok}}"}}},
	}
	vs, err := tpl.Expand(0)
	if err != nil {
		t.Fatal(err)
	}
	if vs[0].Headers["X-T"] != "abc" {
		t.Fatalf("请求头变量未替换: %+v", vs[0].Headers)
	}
}
