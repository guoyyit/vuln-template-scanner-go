// Package matcher 对响应快照执行模板命中条件判定。
package matcher

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

// Snapshot 是响应的受限快照：状态、响应头与限长、按字符集解码后的正文。
type Snapshot struct {
	StatusCode int
	Header     http.Header
	Body       string // 已按响应字符集解码，长度受上限截断
	Truncated  bool
}

// Outcome 一次判定的可解释结果。
type Outcome struct {
	Matched      bool
	ConditionIDs []string // 命中的条件 ID
	Evidence     string
}

// NewSnapshot 从 HTTP 响应构造快照。正文通过 LimitReader 读取 maxBytes+1，
// 超出即截断，绝不整段载入内存；随后按 Content-Type 字符集解码为 UTF-8。
func NewSnapshot(resp *http.Response, maxBytes int64) (*Snapshot, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	s := &Snapshot{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}
	if resp.Body == nil {
		return s, nil
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("读取响应正文: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		raw = raw[:maxBytes]
		s.Truncated = true
	}
	decoded, err := decodeCharset(raw, resp.Header.Get("Content-Type"))
	if err != nil {
		// 字符集解码失败不致命，退化为原始字节。
		decoded = raw
	}
	s.Body = string(decoded)
	return s, nil
}

// decodeCharset 按 Content-Type 中的 charset 解码；未知字符集回退 UTF-8。
func decodeCharset(raw []byte, contentType string) ([]byte, error) {
	charset := "utf-8"
	if contentType != "" {
		if mt, params, err := mime.ParseMediaType(contentType); err == nil {
			_ = mt
			if cs, ok := params["charset"]; ok && cs != "" {
				charset = strings.ToLower(strings.TrimSpace(cs))
			}
		}
	}
	var enc encoding.Encoding
	switch charset {
	case "utf-8", "utf8", "":
		return raw, nil
	case "gbk", "gb2312", "gb18030":
		enc = simplifiedchinese.GBK
	case "big5":
		enc = traditionalchinese.Big5
	case "latin1", "iso-8859-1", "windows-1252":
		enc = charmap.Windows1252
	case "utf-16", "utf-16le":
		enc = unicode.UTF16(unicode.LittleEndian, unicode.UseBOM)
	case "utf-16be":
		enc = unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)
	default:
		return raw, nil
	}
	out, _, err := transform.Bytes(enc.NewDecoder(), raw)
	return out, err
}

// Evaluate 按 MatchBlock 对快照求值，返回可解释结果。
func Evaluate(m template.MatchBlock, s *Snapshot) Outcome {
	combinator := m.Combinator
	if combinator == "" {
		combinator = "any"
	}
	o := Outcome{}
	if combinator == "all" {
		o.Matched = true
	}
	var evidences []string
	for _, c := range m.Conditions {
		hit, ev := evalCondition(c, s)
		if c.Negate {
			hit = !hit
			if hit {
				ev = "未出现（取反命中）: " + ev
			}
		}
		if hit {
			o.ConditionIDs = append(o.ConditionIDs, c.ID)
			evidences = append(evidences, fmt.Sprintf("[%s] %s", c.ID, ev))
		}
		switch combinator {
		case "any":
			if hit {
				o.Matched = true
			}
		case "all":
			if !hit {
				o.Matched = false
			}
		}
	}
	o.Evidence = strings.Join(evidences, "; ")
	return o
}

func evalCondition(c template.Condition, s *Snapshot) (bool, string) {
	switch c.Type {
	case "status":
		for _, want := range c.Status {
			if s.StatusCode == want {
				return true, fmt.Sprintf("状态码 %d", want)
			}
		}
		return false, ""
	case "header":
		return matchStrings(headerValues(s.Header, c.Header), c)
	case "body":
		return matchStrings([]string{s.Body}, c)
	}
	return false, ""
}

func headerValues(h http.Header, name string) []string {
	var out []string
	for k, vs := range h {
		if strings.EqualFold(k, name) {
			out = append(out, vs...)
		}
	}
	return out
}

// matchStrings contains/regex 各自任一命中即成立；两者都给出时任一命中即成立。
func matchStrings(values []string, c template.Condition) (bool, string) {
	for _, sub := range c.Contains {
		for _, v := range values {
			if strings.Contains(v, sub) {
				return true, fmt.Sprintf("包含 %q（证据: %q）", sub, snippet(v, sub))
			}
		}
	}
	for _, pat := range c.Regex {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue // 非法正则视为不命中，避免崩溃
		}
		for _, v := range values {
			if loc := re.FindStringIndex(v); loc != nil {
				return true, fmt.Sprintf("正则 %q 命中（证据: %q）", pat, v[loc[0]:loc[1]])
			}
		}
	}
	return false, ""
}

// snippet 截取命中位置附近的片段作为证据，避免输出整段正文。
func snippet(s, sub string) string {
	i := strings.Index(s, sub)
	if i < 0 {
		return ""
	}
	start := i - 20
	if start < 0 {
		start = 0
	}
	end := i + len(sub) + 20
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
