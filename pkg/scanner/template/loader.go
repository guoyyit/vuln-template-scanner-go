package template

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadError describes a failure to load a single template file.
type LoadError struct {
	File   string
	Reason string
}

func (e *LoadError) Error() string {
	return "template " + e.File + ": " + e.Reason
}

// LoadResult is the outcome of loading a template directory.
type LoadResult struct {
	Templates []*Template
	Errors    []*LoadError
}

// rawTemplate is the on-disk representation used for both format versions.
// Fields unique to the legacy v1 format are flattened here.
type rawTemplate struct {
	SchemaVersion string        `yaml:"schema_version"`
	ID            string        `yaml:"id"`
	Info          Info          `yaml:"info"`
	Name          string        `yaml:"name"`
	Author        string        `yaml:"author"`
	Severity      Severity      `yaml:"severity"`
	Tags          []string      `yaml:"tags"`
	Description   string        `yaml:"description"`
	Variables     rawVariables  `yaml:"variables"`
	Request       Request       `yaml:"request"`
	Variants      []Variant     `yaml:"variants"`
	Matchers      []MatcherSpec `yaml:"matchers"`
}

// rawVariables accepts variables either as a list or as a map of
// name -> variable definition.
type rawVariables []Variable

func (rv *rawVariables) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		var list []Variable
		if err := value.Decode(&list); err != nil {
			return err
		}
		*rv = list
	case yaml.MappingNode:
		var m map[string]Variable
		if err := value.Decode(&m); err != nil {
			return err
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]Variable, 0, len(keys))
		for _, k := range keys {
			v := m[k]
			v.Name = k
			out = append(out, v)
		}
		*rv = out
	case 0: // null node
		*rv = nil
	default:
		return nil
	}
	return nil
}

// LoadDir loads every .yaml/.yml/.json template found under dir recursively.
// A failure to parse or validate one template is recorded in Errors and does
// not prevent the remaining templates from loading.
func LoadDir(dir string) (*LoadResult, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	res := &LoadResult{}
	for _, f := range files {
		tmpl, err := LoadFile(f)
		if err != nil {
			res.Errors = append(res.Errors, &LoadError{File: f, Reason: err.Error()})
			continue
		}
		res.Templates = append(res.Templates, tmpl)
	}
	return res, nil
}

// LoadFile parses a single template file. Unknown fields are ignored.
func LoadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := &rawTemplate{}
	if err := yaml.Unmarshal(data, raw); err != nil {
		return nil, err
	}

	version := detectVersion(raw)
	tmpl := normalize(raw, version)
	tmpl.Source = path

	if err := validate(tmpl); err != nil {
		return nil, err
	}
	return tmpl, nil
}

func detectVersion(raw *rawTemplate) FormatVersion {
	switch strings.TrimSpace(raw.SchemaVersion) {
	case "1":
		return FormatV1
	case "2":
		return FormatV2
	}
	// Legacy templates have no info block and no schema_version.
	if raw.Info.Name != "" || raw.Info.Severity != "" || len(raw.Info.Tags) > 0 {
		return FormatV2
	}
	return FormatV1
}

func normalize(raw *rawTemplate, version FormatVersion) *Template {
	tmpl := &Template{
		ID:        raw.ID,
		Version:   version,
		Variables: []Variable(raw.Variables),
		Request:   raw.Request,
		Variants:  raw.Variants,
		Matchers:  raw.Matchers,
	}

	if version == FormatV1 {
		tmpl.Info = Info{
			Name:        raw.Name,
			Author:      raw.Author,
			Severity:    raw.Severity,
			Tags:        raw.Tags,
			Description: raw.Description,
		}
		// v1 used "values" for status codes and "condition" for the
		// and/or operator; normalize to the v2 field names.
		for i := range tmpl.Matchers {
			m := &tmpl.Matchers[i]
			if len(m.Status) == 0 && len(m.Values) > 0 {
				m.Status = m.Values
			}
			if m.Operator == "" && m.Condition != "" {
				m.Operator = m.Condition
			}
		}
	} else {
		tmpl.Info = raw.Info
	}

	if tmpl.Info.Severity == "" {
		tmpl.Info.Severity = SeverityInfo
	}
	if tmpl.Request.Method == "" {
		tmpl.Request.Method = "GET"
	}
	if tmpl.Request.Path == "" {
		tmpl.Request.Path = "/"
	}
	if len(tmpl.Variants) == 0 {
		tmpl.Variants = []Variant{{ID: "default", Request: tmpl.Request}}
	}
	return tmpl
}
