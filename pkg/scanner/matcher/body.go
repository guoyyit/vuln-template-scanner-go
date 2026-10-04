package matcher

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"

	"golang.org/x/net/html/charset"
)

// ReadResponse reads and decodes an HTTP response into a normalized Response.
// The body is streamed and capped at bodyCap bytes; bodyCap <= 0 selects the
// default cap. Non UTF-8 responses are decoded using their detected charset.
func ReadResponse(resp *http.Response, bodyCap int) *Response {
	if bodyCap <= 0 {
		bodyCap = DefaultBodyCap
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}
	if resp.Request != nil && resp.Request.URL != nil {
		out.URL = resp.Request.URL.String()
	}

	raw := make([]byte, bodyCap+1)
	n, _ := io.ReadFull(resp.Body, raw)
	raw = raw[:n]
	if n > bodyCap {
		out.Truncated = true
		raw = raw[:bodyCap]
	}
	// Drain and close the connection so it can be reused / does not leak.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	out.Body, out.Charset = decodeBody(raw, resp.Header.Get("Content-Type"))
	return out
}

// decodeBody converts raw response bytes to UTF-8. It first honors an
// explicit charset in the Content-Type header, then falls back to content
// sniffing. Unknown encodings are left untouched.
func decodeBody(raw []byte, contentType string) ([]byte, string) {
	if len(raw) == 0 {
		return raw, ""
	}
	if enc := charsetFromHeader(contentType); enc != "" {
		if decoded, name, ok := decode(raw, enc); ok {
			return decoded, name
		}
	}
	if e, name, _ := charset.DetermineEncoding(raw, contentType); e != nil {
		if decoded, err := e.NewDecoder().Bytes(raw); err == nil {
			return decoded, name
		}
	}
	return raw, "utf-8"
}

func charsetFromHeader(contentType string) string {
	if contentType == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Fall back to a naive scan for malformed headers.
		if i := strings.Index(strings.ToLower(contentType), "charset="); i >= 0 {
			cs := strings.TrimSpace(contentType[i+len("charset="):])
			return strings.Trim(cs, "\"'")
		}
		return ""
	}
	return params["charset"]
}

func decode(raw []byte, name string) ([]byte, string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "utf-8" || name == "utf8" {
		return raw, "utf-8", true
	}
	e, _ := charset.Lookup(name)
	if e == nil {
		return nil, "", false
	}
	decoded, err := e.NewDecoder().Bytes(raw)
	if err != nil {
		return nil, "", false
	}
	return decoded, name, true
}

// snippet returns a compact, single-line excerpt around the first occurrence
// of needle in haystack.
func snippet(haystack []byte, needle string) string {
	idx := bytes.Index(haystack, []byte(needle))
	if idx < 0 {
		return ""
	}
	start := idx - 24
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + 48
	if end > len(haystack) {
		end = len(haystack)
	}
	s := string(haystack[start:end])
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}
