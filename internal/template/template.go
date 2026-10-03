// Package template 定义声明式漏洞扫描模板的数据结构与解析逻辑。
package template

// 支持的模板格式版本。
const (
	Version1 = 1 // 旧版：仅支持 status/body 匹配，无变量、无取反、无组合子
	Version2 = 2 // 新版：支持变量、变体、header 匹配、negate 与 combinator
)

// DefaultMaxVariants 单个模板派生请求变体的默认上限。
const DefaultMaxVariants = 256

// Severity 严重级别。
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityRank 返回严重级别排序权重，未知级别按 info 处理。
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Info 模板元信息。
type Info struct {
	Name     string   `yaml:"name" json:"name"`
	Severity Severity `yaml:"severity" json:"severity"`
	Tags     []string `yaml:"tags" json:"tags"`
}

// RequestDef 单个请求定义，Path/Header/Body 中可使用 {{变量名}} 占位符。
type RequestDef struct {
	Method  string            `yaml:"method" json:"method"`
	Path    string            `yaml:"path" json:"path"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Body    string            `yaml:"body" json:"body"`
}

// Condition 单条命中条件。
type Condition struct {
	ID      string   `yaml:"id" json:"id"`
	Type    string   `yaml:"type" json:"type"` // status | header | body
	Negate  bool     `yaml:"negate" json:"negate"`
	Status  []int    `yaml:"status" json:"status"`     // type=status
	Header  string   `yaml:"header" json:"header"`     // type=header：响应头名
	Contains []string `yaml:"contains" json:"contains"` // type=header/body：子串（任一命中）
	Regex   []string `yaml:"regex" json:"regex"`       // type=header/body：正则（任一命中）
}

// MatchBlock 命中判定块。
type MatchBlock struct {
	Combinator string      `yaml:"combinator" json:"combinator"` // any | all，缺省 any
	Conditions []Condition `yaml:"conditions" json:"conditions"`
}

// Template 一份扫描模板。
type Template struct {
	ID        string              `yaml:"id" json:"id"`
	Version   int                 `yaml:"version" json:"version"`
	Info      Info                `yaml:"info" json:"info"`
	Variables map[string][]string `yaml:"variables" json:"variables"`
	Requests  []RequestDef        `yaml:"requests" json:"requests"`
	Match     MatchBlock          `yaml:"match" json:"match"`

	// SourcePath 记录模板来源文件，便于错误归因。
	SourcePath string `yaml:"-" json:"-"`
}

// Variant 由模板派生的一个具体请求。
type Variant struct {
	TemplateID string
	Index      int // 派生序号，从 0 开始，顺序稳定
	Key        string // 稳定标识：请求序号+变量赋值
	Method     string
	Path       string
	Headers    map[string]string
	Body       string
}
