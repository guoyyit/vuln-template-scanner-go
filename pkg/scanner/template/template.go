// Package template defines the declarative scan template format and its
// versioning. Templates describe HTTP requests together with the match
// conditions that decide whether a target is vulnerable.
package template

// FormatVersion enumerates the supported template format revisions.
type FormatVersion int

const (
	// FormatV1 is the legacy, minimal template format.
	FormatV1 FormatVersion = 1
	// FormatV2 is the current format with info, variables and variants.
	FormatV2 FormatVersion = 2
)

// Severity is the impact level assigned to a template.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Request is a single HTTP request definition.
type Request struct {
	Method  string            `yaml:"method" json:"method"`
	Path    string            `yaml:"path" json:"path"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Body    string            `yaml:"body" json:"body"`
}

// Info carries human readable metadata about a template.
type Info struct {
	Name        string   `yaml:"name" json:"name"`
	Author      string   `yaml:"author" json:"author"`
	Severity    Severity `yaml:"severity" json:"severity"`
	Tags        []string `yaml:"tags" json:"tags"`
	Description string   `yaml:"description" json:"description"`
}

// Variable is a named value source used during request derivation.
type Variable struct {
	Name   string   `yaml:"name" json:"name"`
	Values []string `yaml:"values" json:"values"`
	Range  *Range   `yaml:"range" json:"range,omitempty"`
	Random *Random  `yaml:"random" json:"random,omitempty"`
}

// Range generates integer values from Min to Max (inclusive) with Step.
type Range struct {
	Min  int `yaml:"min" json:"min"`
	Max  int `yaml:"max" json:"max"`
	Step int `yaml:"step" json:"step"`
}

// Random generates deterministic pseudo random values.
type Random struct {
	Type   string `yaml:"type" json:"type"` // "int" or "string"
	Min    int    `yaml:"min" json:"min"`
	Max    int    `yaml:"max" json:"max"`
	Length int    `yaml:"length" json:"length"`
	Count  int    `yaml:"count" json:"count"`
}

// Variant is a named request definition that is combined with variable
// assignments to derive concrete requests.
type Variant struct {
	ID      string  `yaml:"id" json:"id"`
	Request Request `yaml:"request" json:"request"`
}

// MatcherSpec describes a single match condition.
type MatcherSpec struct {
	ID     string `yaml:"id" json:"id"`
	Type   string `yaml:"type" json:"type"`
	Part   string `yaml:"part" json:"part"`
	Status []int  `yaml:"status" json:"status,omitempty"`
	// Values is the legacy v1 name for Status; it is normalized on load.
	Values   []int    `yaml:"values" json:"-"`
	Words    []string `yaml:"words" json:"words,omitempty"`
	Regex    []string `yaml:"regex" json:"regex,omitempty"`
	Header   string   `yaml:"header" json:"header,omitempty"`
	Exists   *bool    `yaml:"exists" json:"exists,omitempty"`
	Case     string   `yaml:"case" json:"case"`
	Operator string   `yaml:"operator" json:"operator"`
	// Condition is the legacy v1 name for Operator.
	Condition string        `yaml:"condition" json:"-"`
	Negate    bool          `yaml:"negate" json:"negate"`
	Matchers  []MatcherSpec `yaml:"matchers" json:"matchers,omitempty"`
}

// Template is the normalized, version-independent representation of a scan
// template.
type Template struct {
	ID        string        `yaml:"id" json:"id"`
	Version   FormatVersion `yaml:"-" json:"version"`
	Info      Info          `yaml:"info" json:"info"`
	Variables []Variable    `yaml:"variables" json:"variables"`
	Request   Request       `yaml:"request" json:"request"`
	Variants  []Variant     `yaml:"variants" json:"variants"`
	Matchers  []MatcherSpec `yaml:"matchers" json:"matchers"`
	Source    string        `yaml:"-" json:"source"`
}

// SeverityRank returns a numeric rank for ordering and filtering.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return -1
	}
}
