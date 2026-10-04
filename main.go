package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/engine"
	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/target"
	"github.com/guoyyit/vuln-template-scanner-go/pkg/scanner/template"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("vuln-scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	templatesDir := fs.String("templates", "", "directory containing template files (required)")
	targetsFlag := fs.String("targets", "", "comma separated target base URLs")
	targetsFile := fs.String("targets-file", "", "file with one target base URL per line")
	output := fs.String("output", "", "output JSON file (default: stdout)")
	checkpoint := fs.String("checkpoint", "", "checkpoint file for resume support")
	concurrency := fs.Int("concurrency", 4, "per target concurrent requests")
	rateLimit := fs.Float64("rate", 0, "per target requests per second (0 = unlimited)")
	timeout := fs.Duration("timeout", 10*time.Second, "per request timeout")
	seed := fs.Int64("seed", 0, "random seed for deterministic derivation")
	bodyCap := fs.Int("max-body", 1<<20, "max body bytes buffered per response")
	maxVariants := fs.Int("max-variants", 256, "max derived requests per template")
	severities := fs.String("severity", "", "comma separated severity filter (info,low,medium,high,critical)")
	tags := fs.String("tags", "", "comma separated tag filter")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *templatesDir == "" {
		return fmt.Errorf("--templates is required")
	}

	rawTargets := splitCSV(*targetsFlag)
	if *targetsFile != "" {
		data, err := os.ReadFile(*targetsFile)
		if err != nil {
			return fmt.Errorf("read targets file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			rawTargets = append(rawTargets, line)
		}
	}
	targets, err := target.Parse(rawTargets)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	loaded, err := template.LoadDir(*templatesDir)
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}
	for _, e := range loaded.Errors {
		fmt.Fprintf(stderr, "warning: %v\n", e)
	}
	if len(loaded.Templates) == 0 {
		return fmt.Errorf("no templates loaded from %q", *templatesDir)
	}

	var store engine.CheckpointStore
	if *checkpoint != "" {
		store = engine.NewFileCheckpointStore(*checkpoint)
	}
	eng := engine.New(engine.Options{
		Concurrency: *concurrency,
		RateLimit:   *rateLimit,
		Timeout:     *timeout,
		BodyCap:     *bodyCap,
		MaxVariants: *maxVariants,
		Seed:        *seed,
		Checkpoint:  store,
	})

	res := eng.Scan(context.Background(), loaded.Templates, targets)

	if *severities != "" || *tags != "" {
		res.Hits = engine.ApplyFilter(res.Hits, engine.Filter{
			Severities: splitCSV(*severities),
			Tags:       splitCSV(*tags),
		})
	}

	var out io.Writer = stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	fmt.Fprintf(stderr, "scan %s: status=%s hits=%d errors=%d templates=%d targets=%d\n",
		res.ScanID, res.Status, len(res.Hits), len(res.Errors), len(loaded.Templates), len(targets))
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
