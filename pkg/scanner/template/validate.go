package template

import (
	"fmt"
	"regexp"
	"strings"
)

// validate checks a normalized template for structural problems. It never
// panics; every problem is returned as a readable error so the loader can
// attribute it to the template file.
func validate(t *Template) error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("template id is required")
	}
	if len(t.Matchers) == 0 {
		return fmt.Errorf("template %q defines no matchers", t.ID)
	}
	seenVariant := map[string]bool{}
	for i := range t.Variants {
		v := &t.Variants[i]
		if v.ID == "" {
			v.ID = fmt.Sprintf("variant-%d", i)
		}
		if seenVariant[v.ID] {
			return fmt.Errorf("template %q has duplicate variant id %q", t.ID, v.ID)
		}
		seenVariant[v.ID] = true
		if v.Request.Method == "" {
			v.Request.Method = "GET"
		}
		if v.Request.Path == "" {
			v.Request.Path = "/"
		}
	}
	seenMatcher := map[string]bool{}
	for i := range t.Matchers {
		m := &t.Matchers[i]
		if m.ID == "" {
			m.ID = fmt.Sprintf("matcher-%d", i)
		}
		if seenMatcher[m.ID] {
			return fmt.Errorf("template %q has duplicate matcher id %q", t.ID, m.ID)
		}
		seenMatcher[m.ID] = true
		if err := validateMatcher(t.ID, m); err != nil {
			return err
		}
	}
	return nil
}

func validateMatcher(templateID string, m *MatcherSpec) error {
	switch strings.ToLower(strings.TrimSpace(m.Type)) {
	case "status":
		if len(m.Status) == 0 {
			return fmt.Errorf("template %q matcher %q: status matcher requires a non-empty status list", templateID, m.ID)
		}
		for _, code := range m.Status {
			if code < 100 || code > 599 {
				return fmt.Errorf("template %q matcher %q: invalid status code %d", templateID, m.ID, code)
			}
		}
	case "word":
		if len(m.Words) == 0 {
			return fmt.Errorf("template %q matcher %q: word matcher requires a non-empty words list", templateID, m.ID)
		}
	case "regex":
		if len(m.Regex) == 0 {
			return fmt.Errorf("template %q matcher %q: regex matcher requires a non-empty regex list", templateID, m.ID)
		}
		for _, p := range m.Regex {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("template %q matcher %q: invalid regex %q: %v", templateID, m.ID, p, err)
			}
		}
	case "header":
		if strings.TrimSpace(m.Header) == "" {
			return fmt.Errorf("template %q matcher %q: header matcher requires a header name", templateID, m.ID)
		}
		if m.Exists == nil && len(m.Words) == 0 {
			return fmt.Errorf("template %q matcher %q: header matcher requires words or exists", templateID, m.ID)
		}
	case "logic":
		if len(m.Matchers) == 0 {
			return fmt.Errorf("template %q matcher %q: logic matcher requires nested matchers", templateID, m.ID)
		}
		switch strings.ToLower(m.Operator) {
		case "and", "or", "not":
		default:
			return fmt.Errorf("template %q matcher %q: logic operator must be and/or/not, got %q", templateID, m.ID, m.Operator)
		}
		for i := range m.Matchers {
			child := &m.Matchers[i]
			if child.ID == "" {
				child.ID = fmt.Sprintf("%s-child-%d", m.ID, i)
			}
			if err := validateMatcher(templateID, child); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("template %q matcher %q: unknown matcher type %q", templateID, m.ID, m.Type)
	}
	return nil
}
