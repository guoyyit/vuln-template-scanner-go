package engine

import (
	"sort"
	"strconv"
	"strings"
)

// Filter selects hits by severity and tags.
type Filter struct {
	Severities []string
	Tags       []string // any of these tags match
}

// ApplyFilter returns hits matching the filter.
func ApplyFilter(hits []Hit, f Filter) []Hit {
	out := make([]Hit, 0, len(hits))
	for _, h := range hits {
		if len(f.Severities) > 0 {
			ok := false
			for _, s := range f.Severities {
				if string(h.Severity) == s {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if len(f.Tags) > 0 {
			ok := false
			for _, want := range f.Tags {
				for _, got := range h.Tags {
					if got == want {
						ok = true
						break
					}
				}
				if ok {
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

// variantSortKey splits a variant id into its prefix and numeric derivation
// index so that "v#9" sorts before "v#10".
func variantSortKey(variantID string) (string, int) {
	if i := strings.LastIndex(variantID, "#"); i >= 0 {
		if n, err := strconv.Atoi(variantID[i+1:]); err == nil {
			return variantID[:i], n
		}
	}
	return variantID, 0
}

func hitLess(a, b Hit) bool {
	if a.Target != b.Target {
		return a.Target < b.Target
	}
	if a.TemplateID != b.TemplateID {
		return a.TemplateID < b.TemplateID
	}
	ap, an := variantSortKey(a.VariantID)
	bp, bn := variantSortKey(b.VariantID)
	if ap != bp {
		return ap < bp
	}
	if an != bn {
		return an < bn
	}
	return evidenceKey(a) < evidenceKey(b)
}

func evidenceKey(h Hit) string {
	parts := make([]string, 0, len(h.Evidence))
	for _, e := range h.Evidence {
		parts = append(parts, e.MatcherID+"|"+e.Detail+"|"+e.Snippet)
	}
	return strings.Join(parts, ";")
}

func firstMatcherID(h Hit) string {
	if len(h.Evidence) == 0 {
		return ""
	}
	return h.Evidence[0].MatcherID
}

// DedupeAndSort returns a deterministic, de duplicated copy of hits. Hits are
// ordered by target, template, variant and evidence so the result does not
// depend on concurrent scheduling. Duplicates (same target/template/variant/
// matcher) keep the lexicographically smallest evidence.
func DedupeAndSort(hits []Hit) []Hit {
	sort.SliceStable(hits, func(i, j int) bool { return hitLess(hits[i], hits[j]) })
	out := make([]Hit, 0, len(hits))
	seen := make(map[string]bool, len(hits))
	for _, h := range hits {
		key := h.Target + "|" + h.TemplateID + "|" + h.VariantID + "|" + firstMatcherID(h)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}

// SortErrors returns errors in a stable, deterministic order.
func SortErrors(errs []ScanError) []ScanError {
	out := make([]ScanError, len(errs))
	copy(out, errs)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.TemplateID != b.TemplateID {
			return a.TemplateID < b.TemplateID
		}
		if a.VariantID != b.VariantID {
			return a.VariantID < b.VariantID
		}
		if a.Phase != b.Phase {
			return a.Phase < b.Phase
		}
		return a.Message < b.Message
	})
	return out
}
