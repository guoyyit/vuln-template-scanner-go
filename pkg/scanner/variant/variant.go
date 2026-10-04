// Package variant derives concrete HTTP requests from a template's variables
// and request variants. Derivation order is stable and the total number of
// derived requests per template is bounded.
package variant

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
)

// DefaultMaxVariants is the default upper bound of derived requests per
// template.
const DefaultMaxVariants = 256

// Request is a concrete, fully substituted HTTP request.
type Request struct {
	VariantID string
	Method    string
	Path      string
	Headers   map[string]string
	Body      string
}

// Derive expands a template into concrete requests. The seed drives any
// random variable generation. maxVariants limits the number of derived
// requests; values <= 0 select the default.
func Derive(tmpl *template.Template, seed int64, maxVariants int) ([]Request, error) {
	if maxVariants <= 0 {
		maxVariants = DefaultMaxVariants
	}
	if len(tmpl.Variants) == 0 {
		return nil, fmt.Errorf("template %q defines no variants", tmpl.ID)
	}

	// Expand every variable into an ordered value list.
	values := make([][]string, len(tmpl.Variables))
	for i := range tmpl.Variables {
		vals, err := expandVariable(&tmpl.Variables[i], rand.New(rand.NewSource(seed+int64(i))))
		if err != nil {
			return nil, fmt.Errorf("template %q variable %q: %w", tmpl.ID, tmpl.Variables[i].Name, err)
		}
		values[i] = vals
	}

	// Compute the cartesian product size per variant and enforce the cap
	// before generating anything.
	productSize := 1
	for _, v := range values {
		productSize *= len(v)
	}
	total := productSize * len(tmpl.Variants)
	if total > maxVariants {
		return nil, fmt.Errorf("template %q derives %d requests, exceeding the limit of %d",
			tmpl.ID, total, maxVariants)
	}

	out := make([]Request, 0, total)
	for vi := range tmpl.Variants {
		variant := &tmpl.Variants[vi]
		if productSize == 1 {
			req, err := substitute(variant.ID, &variant.Request, tmpl.Variables, values, 0)
			if err != nil {
				return nil, err
			}
			out = append(out, req)
			continue
		}
		for combo := 0; combo < productSize; combo++ {
			req, err := substitute(fmt.Sprintf("%s#%d", variant.ID, combo), &variant.Request, tmpl.Variables, values, combo)
			if err != nil {
				return nil, err
			}
			out = append(out, req)
		}
	}
	return out, nil
}

// expandVariable turns a variable definition into its ordered value list.
func expandVariable(v *template.Variable, rng *rand.Rand) ([]string, error) {
	if len(v.Values) > 0 {
		return v.Values, nil
	}
	if v.Range != nil {
		step := v.Range.Step
		if step <= 0 {
			step = 1
		}
		if v.Range.Max < v.Range.Min {
			return nil, fmt.Errorf("range max %d < min %d", v.Range.Max, v.Range.Min)
		}
		out := []string{}
		for x := v.Range.Min; x <= v.Range.Max; x += step {
			out = append(out, strconv.Itoa(x))
		}
		return out, nil
	}
	if v.Random != nil {
		count := v.Random.Count
		if count <= 0 {
			count = 1
		}
		out := make([]string, 0, count)
		switch strings.ToLower(v.Random.Type) {
		case "int":
			if v.Random.Max < v.Random.Min {
				return nil, fmt.Errorf("random int max %d < min %d", v.Random.Max, v.Random.Min)
			}
			span := v.Random.Max - v.Random.Min + 1
			for i := 0; i < count; i++ {
				out = append(out, strconv.Itoa(v.Random.Min+rng.Intn(span)))
			}
		case "string":
			const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			length := v.Random.Length
			if length <= 0 {
				length = 8
			}
			for i := 0; i < count; i++ {
				b := make([]byte, length)
				for j := range b {
					b[j] = alphabet[rng.Intn(len(alphabet))]
				}
				out = append(out, string(b))
			}
		default:
			return nil, fmt.Errorf("random type must be int or string, got %q", v.Random.Type)
		}
		return out, nil
	}
	return nil, fmt.Errorf("variable %q must define values, range or random", v.Name)
}

// substitute applies the combo-th variable assignment to a request.
func substitute(variantID string, req *template.Request, vars []template.Variable, values [][]string, combo int) (Request, error) {
	repl := make([]string, 0, 2*len(vars))
	for i := range vars {
		idx := 0
		if len(values[i]) > 1 {
			// Decode the mixed-radix combo index for this variable.
			div := 1
			for j := i + 1; j < len(vars); j++ {
				div *= len(values[j])
			}
			idx = (combo / div) % len(values[i])
		}
		repl = append(repl, "{{"+vars[i].Name+"}}", values[i][idx])
	}
	r := strings.NewReplacer(repl...)
	headers := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		headers[k] = r.Replace(v)
	}
	return Request{
		VariantID: variantID,
		Method:    req.Method,
		Path:      r.Replace(req.Path),
		Headers:   headers,
		Body:      r.Replace(req.Body),
	}, nil
}
