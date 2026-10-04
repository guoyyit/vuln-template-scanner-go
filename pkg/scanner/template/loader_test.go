package template

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadV2Template(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "v2.yaml", `
schema_version: "2"
id: v2-demo
info:
  name: V2 Demo
  author: tester
  severity: high
  tags: [rce, web]
  description: a demo
variables:
  token:
    values: ["a", "b"]
request:
  method: POST
  path: /login
  headers:
    X-Token: "{{token}}"
  body: "x={{token}}"
matchers:
  - id: s
    type: status
    status: [200]
  - id: w
    type: word
    part: body
    words: ["ok"]
`)
	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Templates) != 1 {
		t.Fatalf("got %d templates, want 1", len(res.Templates))
	}
	tmpl := res.Templates[0]
	if tmpl.ID != "v2-demo" || tmpl.Version != FormatV2 {
		t.Fatalf("bad id/version: %q %v", tmpl.ID, tmpl.Version)
	}
	if tmpl.Info.Severity != SeverityHigh || len(tmpl.Info.Tags) != 2 {
		t.Fatalf("bad info: %+v", tmpl.Info)
	}
	if len(tmpl.Variables) != 1 || tmpl.Variables[0].Name != "token" || len(tmpl.Variables[0].Values) != 2 {
		t.Fatalf("bad variables: %+v", tmpl.Variables)
	}
	if tmpl.Request.Method != "POST" || tmpl.Request.Path != "/login" {
		t.Fatalf("bad request: %+v", tmpl.Request)
	}
	if len(tmpl.Matchers) != 2 {
		t.Fatalf("bad matchers: %+v", tmpl.Matchers)
	}
}

func TestLoadV1LegacyTemplate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "legacy.yaml", `
id: legacy-demo
name: Legacy Demo
author: old
severity: medium
tags: [legacy]
request:
  method: GET
  path: /
matchers:
  - type: status
    values: [200, 204]
  - type: word
    words: ["root:"]
`)
	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Templates) != 1 {
		t.Fatalf("got %d templates, want 1", len(res.Templates))
	}
	tmpl := res.Templates[0]
	if tmpl.Version != FormatV1 {
		t.Fatalf("want v1, got %v", tmpl.Version)
	}
	if tmpl.Info.Name != "Legacy Demo" || tmpl.Info.Severity != SeverityMedium {
		t.Fatalf("v1 info not normalized: %+v", tmpl.Info)
	}
	if len(tmpl.Matchers[0].Status) != 2 || tmpl.Matchers[0].Status[0] != 200 {
		t.Fatalf("v1 values->status not normalized: %+v", tmpl.Matchers[0])
	}
	if len(tmpl.Variants) != 1 || tmpl.Variants[0].ID != "default" {
		t.Fatalf("v1 should get a default variant: %+v", tmpl.Variants)
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "extra.yaml", `
schema_version: "2"
id: extra-fields
info:
  name: Extra
  severity: low
  future_field: whatever
totally_unknown_block:
  nested: [1, 2, 3]
request:
  path: /
matchers:
  - type: status
    status: [200]
    unknown_matcher_field: 42
`)
	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Templates) != 1 {
		t.Fatalf("unknown fields should be ignored, got %d templates and %d errors: %v",
			len(res.Templates), len(res.Errors), res.Errors)
	}
}

func TestBadTemplateIsolated(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", `
id: good-one
info: {name: Good, severity: info}
request: {path: /}
matchers:
  - {type: status, status: [200]}
`)
	writeFile(t, dir, "bad.yaml", `
id: bad-one
info: {name: Bad}
request: {path: /}
matchers:
  - {type: status}
`)
	writeFile(t, dir, "broken.yaml", `
id: broken
this is not: [valid yaml
`)
	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Templates) != 1 || res.Templates[0].ID != "good-one" {
		t.Fatalf("only good template should load, got %+v", res.Templates)
	}
	if len(res.Errors) != 2 {
		t.Fatalf("want 2 load errors, got %d: %v", len(res.Errors), res.Errors)
	}
	for _, e := range res.Errors {
		if e.File == "" || e.Reason == "" {
			t.Fatalf("load error missing file/reason: %+v", e)
		}
	}
}

func TestDefaultMethodAndPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "d.yaml", `
id: defaults
info: {name: D}
matchers:
  - {type: word, words: ["x"]}
`)
	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := res.Templates[0]
	if tmpl.Request.Method != "GET" || tmpl.Request.Path != "/" {
		t.Fatalf("bad defaults: %+v", tmpl.Request)
	}
}

func TestLoadJSONTemplate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "t.json", `{
		"id": "json-tmpl",
		"info": {"name": "JSON", "severity": "low"},
		"request": {"path": "/json"},
		"matchers": [{"type": "status", "status": [200]}]
	}`)
	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Templates) != 1 || res.Templates[0].ID != "json-tmpl" {
		t.Fatalf("JSON template should load, got %+v (errors: %v)", res.Templates, res.Errors)
	}
}

func TestV1ConditionNormalized(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "v1c.yaml", `
id: v1-condition
name: V1 Condition
severity: medium
request: {path: /}
matchers:
  - type: word
    words: ["a", "b"]
    condition: and
`)
	res, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Templates) != 1 {
		t.Fatalf("got %d templates, errors: %v", len(res.Templates), res.Errors)
	}
	if res.Templates[0].Matchers[0].Operator != "and" {
		t.Fatalf("v1 condition should normalize to operator, got %q", res.Templates[0].Matchers[0].Operator)
	}
}
