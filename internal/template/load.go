package template

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadError 单个模板的加载失败，携带文件路径与可读原因。
type LoadError struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func (e LoadError) Error() string { return fmt.Sprintf("%s: %s", e.Path, e.Reason) }

// LoadDir 从目录批量加载模板（*.yaml/*.yml，按文件名排序保证顺序稳定）。
// 单个模板失败不影响其余模板，失败信息以 LoadError 返回。
func LoadDir(dir string) ([]*Template, []LoadError, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("扫描模板目录: %w", err)
	}
	sort.Strings(paths)

	var templates []*Template
	var errs []LoadError
	for _, p := range paths {
		t, err := LoadFile(p)
		if err != nil {
			errs = append(errs, LoadError{Path: p, Reason: err.Error()})
			continue
		}
		templates = append(templates, t)
	}
	return templates, errs, nil
}

// LoadFile 加载并校验单个模板。未知字段被忽略，缺失的新版本字段使用默认值。
func LoadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件: %w", err)
	}
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	t.SourcePath = path
	return t, nil
}

// Parse 解析模板字节流并做版本兼容与校验。
func Parse(data []byte) (*Template, error) {
	// 非严格模式：未知字段不导致失败。
	var t Template
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if t.Version == 0 {
		t.Version = Version1 // 缺省按旧版处理
	}
	if t.Version < Version1 || t.Version > Version2 {
		return nil, fmt.Errorf("不支持的模板版本 %d（支持 %d-%d）", t.Version, Version1, Version2)
	}
	if strings.TrimSpace(t.ID) == "" {
		return nil, fmt.Errorf("缺少模板 id")
	}
	if len(t.Requests) == 0 {
		return nil, fmt.Errorf("模板 %q 未定义任何请求", t.ID)
	}
	if len(t.Match.Conditions) == 0 {
		return nil, fmt.Errorf("模板 %q 未定义任何命中条件", t.ID)
	}
	// 版本兼容：v1 模板缺少 combinator 时默认为 any；v1 不允许新特性字段。
	if t.Match.Combinator == "" {
		t.Match.Combinator = "any"
	}
	if t.Match.Combinator != "any" && t.Match.Combinator != "all" {
		return nil, fmt.Errorf("模板 %q 的 combinator 非法: %q（仅支持 any|all）", t.ID, t.Match.Combinator)
	}
	if t.Info.Severity == "" {
		t.Info.Severity = SeverityInfo
	}
	for i, c := range t.Match.Conditions {
		if c.ID == "" {
			t.Match.Conditions[i].ID = fmt.Sprintf("c%d", i)
		}
		switch c.Type {
		case "status":
			if len(c.Status) == 0 {
				return nil, fmt.Errorf("模板 %q 条件 %s: status 类型缺少 status 列表", t.ID, c.ID)
			}
		case "header":
			if t.Version < Version2 {
				return nil, fmt.Errorf("模板 %q 条件 %s: header 匹配需要 version: 2", t.ID, c.ID)
			}
			if c.Header == "" {
				return nil, fmt.Errorf("模板 %q 条件 %s: header 类型缺少 header 名", t.ID, c.ID)
			}
		case "body":
			if len(c.Contains) == 0 && len(c.Regex) == 0 {
				return nil, fmt.Errorf("模板 %q 条件 %s: body 类型缺少 contains 或 regex", t.ID, c.ID)
			}
		default:
			return nil, fmt.Errorf("模板 %q 条件 %s: 未知条件类型 %q", t.ID, c.ID, c.Type)
		}
	}
	for i, r := range t.Requests {
		if r.Path == "" {
			return nil, fmt.Errorf("模板 %q 第 %d 个请求缺少 path", t.ID, i)
		}
		if r.Method == "" {
			t.Requests[i].Method = "GET"
		}
	}
	return &t, nil
}
