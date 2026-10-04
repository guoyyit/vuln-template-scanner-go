// Package target parses and validates scan targets. Targets are HTTP(S) base
// URLs; the scanner is intended to run against local loopback services.
package target

import (
	"net/url"
	"strings"
)

// Parse normalizes a list of target strings.
func Parse(raw []string) ([]string, error) {
	var out []string
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		u, err := url.Parse(t)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, &ParseError{Target: t}
		}
		out = append(out, strings.TrimRight(t, "/"))
	}
	return out, nil
}

// ParseError reports an invalid target.
type ParseError struct {
	Target string
}

func (e *ParseError) Error() string {
	return "invalid target: " + e.Target
}
