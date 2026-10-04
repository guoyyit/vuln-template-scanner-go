package matcher

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
)

// DefaultBodyCap is the default maximum number of body bytes buffered for
// matching. Responses larger than this are streamed and truncated, so a large
// response body is never fully loaded into memory.
const DefaultBodyCap = 1 << 20 // 1 MiB

// Response is the normalized view of an HTTP response used by matchers.
type Response struct {
	StatusCode int
	Headers    http.Header
	// Body is the decoded (UTF-8) response body, capped at BodyCap bytes.
	Body []byte
	// Truncated reports whether the response body exceeded the cap.
	Truncated bool
	// Charset is the detected source charset (e.g. "gbk").
	Charset string
	// URL is the final request URL (after redirects).
	URL string
}

// Evidence explains why a matcher matched.
type Evidence struct {
	MatcherID string     `json:"matcher_id"`
	Type      string     `json:"type"`
	Matched   bool       `json:"matched"`
	Detail    string     `json:"detail,omitempty"`
	Snippet   string     `json:"snippet,omitempty"`
	Children  []Evidence `json:"children,omitempty"`
}

// Matcher evaluates a single condition tree against a response.
type Matcher interface {
	ID() string
	Match(resp *Response) Evidence
}

// Compile builds a Matcher tree from a template matcher spec.
func Compile(spec template.MatcherSpec) (Matcher, error) {
	m, err := compile(spec)
	if err != nil {
		return nil, err
	}
	if spec.Negate {
		m = &negateMatcher{inner: m}
	}
	return m, nil
}

func compile(spec template.MatcherSpec) (Matcher, error) {
	id := spec.ID
	switch strings.ToLower(strings.TrimSpace(spec.Type)) {
	case "status":
		return &statusMatcher{id: id, codes: spec.Status}, nil
	case "word":
		return &wordMatcher{
			id:          id,
			part:        spec.Part,
			words:       spec.Words,
			all:         strings.EqualFold(spec.Operator, "and"),
			insensitive: strings.EqualFold(spec.Case, "insensitive"),
		}, nil
	case "regex":
		patterns := make([]*regexp.Regexp, 0, len(spec.Regex))
		for _, p := range spec.Regex {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("matcher %q: invalid regexp %q: %w", id, p, err)
			}
			patterns = append(patterns, re)
		}
		return &regexMatcher{
			id:          id,
			part:        spec.Part,
			patterns:    patterns,
			all:         strings.EqualFold(spec.Operator, "and"),
			insensitive: strings.EqualFold(spec.Case, "insensitive"),
		}, nil
	case "header":
		return &headerMatcher{
			id:          id,
			name:        spec.Header,
			words:       spec.Words,
			exists:      spec.Exists,
			all:         strings.EqualFold(spec.Operator, "and"),
			insensitive: strings.EqualFold(spec.Case, "insensitive"),
		}, nil
	case "logic":
		children := make([]Matcher, 0, len(spec.Matchers))
		for i := range spec.Matchers {
			child, err := Compile(spec.Matchers[i])
			if err != nil {
				return nil, err
			}
			children = append(children, child)
		}
		op := strings.ToLower(spec.Operator)
		if op == "" {
			op = "and"
		}
		return &logicMatcher{id: id, operator: op, children: children}, nil
	default:
		return nil, fmt.Errorf("matcher %q: unknown matcher type %q", id, spec.Type)
	}
}

// CompileAll compiles every matcher of a template.
func CompileAll(specs []template.MatcherSpec) ([]Matcher, error) {
	out := make([]Matcher, 0, len(specs))
	for i := range specs {
		m, err := Compile(specs[i])
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func partText(resp *Response, part string) string {
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "header":
		var b strings.Builder
		for k, vs := range resp.Headers {
			b.WriteString(k)
			b.WriteString(": ")
			for _, v := range vs {
				b.WriteString(v)
				b.WriteByte(' ')
			}
		}
		return b.String()
	case "all":
		var b strings.Builder
		for k, vs := range resp.Headers {
			b.WriteString(k)
			b.WriteString(": ")
			for _, v := range vs {
				b.WriteString(v)
				b.WriteByte(' ')
			}
			b.WriteByte('\n')
		}
		b.Write(resp.Body)
		return b.String()
	default: // "body"
		return string(resp.Body)
	}
}

func normalize(s string, insensitive bool) string {
	if insensitive {
		return strings.ToLower(s)
	}
	return s
}

// ---- status matcher ----

type statusMatcher struct {
	id    string
	codes []int
}

func (m *statusMatcher) ID() string { return m.id }

func (m *statusMatcher) Match(resp *Response) Evidence {
	for _, c := range m.codes {
		if resp.StatusCode == c {
			return Evidence{
				MatcherID: m.id,
				Type:      "status",
				Matched:   true,
				Detail:    fmt.Sprintf("response status %d is in %v", resp.StatusCode, m.codes),
			}
		}
	}
	return Evidence{
		MatcherID: m.id,
		Type:      "status",
		Detail:    fmt.Sprintf("response status %d is not in %v", resp.StatusCode, m.codes),
	}
}

// ---- word matcher ----

type wordMatcher struct {
	id          string
	part        string
	words       []string
	all         bool
	insensitive bool
}

func (m *wordMatcher) ID() string { return m.id }

func (m *wordMatcher) Match(resp *Response) Evidence {
	text := normalize(partText(resp, m.part), m.insensitive)
	matched := make([]string, 0, len(m.words))
	for _, w := range m.words {
		if strings.Contains(text, normalize(w, m.insensitive)) {
			matched = append(matched, w)
			if !m.all {
				return Evidence{
					MatcherID: m.id,
					Type:      "word",
					Matched:   true,
					Detail:    fmt.Sprintf("word %q found in %s", w, m.part),
					Snippet:   snippet([]byte(text), normalize(w, m.insensitive)),
				}
			}
		}
	}
	if m.all && len(matched) == len(m.words) {
		return Evidence{
			MatcherID: m.id,
			Type:      "word",
			Matched:   true,
			Detail:    fmt.Sprintf("all words %v found in %s", m.words, m.part),
			Snippet:   snippet([]byte(text), normalize(m.words[0], m.insensitive)),
		}
	}
	return Evidence{
		MatcherID: m.id,
		Type:      "word",
		Detail:    fmt.Sprintf("matched %d/%d words in %s", len(matched), len(m.words), m.part),
	}
}

// ---- regex matcher ----

type regexMatcher struct {
	id          string
	part        string
	patterns    []*regexp.Regexp
	all         bool
	insensitive bool
}

func (m *regexMatcher) ID() string { return m.id }

func (m *regexMatcher) Match(resp *Response) Evidence {
	text := partText(resp, m.part)
	if m.insensitive {
		text = strings.ToLower(text)
	}
	matched := 0
	for _, re := range m.patterns {
		loc := re.FindStringIndex(text)
		if loc != nil {
			matched++
			if !m.all {
				return Evidence{
					MatcherID: m.id,
					Type:      "regex",
					Matched:   true,
					Detail:    fmt.Sprintf("pattern %q matched in %s", re.String(), m.part),
					Snippet:   strings.ReplaceAll(strings.ReplaceAll(text[loc[0]:loc[1]], "\n", " "), "\r", " "),
				}
			}
		}
	}
	if m.all && matched == len(m.patterns) {
		return Evidence{
			MatcherID: m.id,
			Type:      "regex",
			Matched:   true,
			Detail:    fmt.Sprintf("all %d patterns matched in %s", matched, m.part),
		}
	}
	return Evidence{
		MatcherID: m.id,
		Type:      "regex",
		Detail:    fmt.Sprintf("matched %d/%d patterns in %s", matched, len(m.patterns), m.part),
	}
}

// ---- header matcher ----

type headerMatcher struct {
	id          string
	name        string
	words       []string
	exists      *bool
	all         bool
	insensitive bool
}

func (m *headerMatcher) ID() string { return m.id }

func (m *headerMatcher) Match(resp *Response) Evidence {
	values, ok := resp.Headers[http.CanonicalHeaderKey(m.name)]
	if !ok {
		// Header keys are canonicalized by net/http; also try a direct lookup.
		values, ok = resp.Headers[m.name]
	}
	if m.exists != nil {
		present := ok && len(values) > 0
		if present == *m.exists {
			return Evidence{
				MatcherID: m.id,
				Type:      "header",
				Matched:   present,
				Detail:    fmt.Sprintf("header %q presence=%v", m.name, present),
			}
		}
		return Evidence{
			MatcherID: m.id,
			Type:      "header",
			Detail:    fmt.Sprintf("header %q presence=%v, want %v", m.name, present, *m.exists),
		}
	}
	if !ok {
		return Evidence{MatcherID: m.id, Type: "header", Detail: fmt.Sprintf("header %q absent", m.name)}
	}
	joined := normalize(strings.Join(values, " "), m.insensitive)
	matched := 0
	for _, w := range m.words {
		if strings.Contains(joined, normalize(w, m.insensitive)) {
			matched++
			if !m.all {
				return Evidence{
					MatcherID: m.id,
					Type:      "header",
					Matched:   true,
					Detail:    fmt.Sprintf("header %q contains %q", m.name, w),
					Snippet:   joined,
				}
			}
		}
	}
	if m.all && matched == len(m.words) {
		return Evidence{
			MatcherID: m.id,
			Type:      "header",
			Matched:   true,
			Detail:    fmt.Sprintf("header %q contains all words", m.name),
		}
	}
	return Evidence{
		MatcherID: m.id,
		Type:      "header",
		Detail:    fmt.Sprintf("header %q matched %d/%d words", m.name, matched, len(m.words)),
	}
}

// ---- logic matcher ----

type logicMatcher struct {
	id       string
	operator string
	children []Matcher
}

func (m *logicMatcher) ID() string { return m.id }

func (m *logicMatcher) Match(resp *Response) Evidence {
	children := make([]Evidence, 0, len(m.children))
	matched := 0
	for _, c := range m.children {
		ev := c.Match(resp)
		children = append(children, ev)
		if ev.Matched {
			matched++
		}
	}
	var result bool
	switch m.operator {
	case "and":
		result = matched == len(m.children)
	case "or":
		result = matched > 0
	case "not":
		result = matched == 0
	}
	return Evidence{
		MatcherID: m.id,
		Type:      "logic",
		Matched:   result,
		Detail:    fmt.Sprintf("logic %s: %d/%d children matched", m.operator, matched, len(m.children)),
		Children:  children,
	}
}

// ---- negation wrapper ----

type negateMatcher struct {
	inner Matcher
}

func (m *negateMatcher) ID() string { return m.inner.ID() }

func (m *negateMatcher) Match(resp *Response) Evidence {
	ev := m.inner.Match(resp)
	ev.Matched = !ev.Matched
	ev.Detail = "negated: " + ev.Detail
	return ev
}
