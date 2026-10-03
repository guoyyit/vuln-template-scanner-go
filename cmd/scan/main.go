// scan 是模板驱动漏洞扫描引擎的命令行入口。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/guoyyit/vuln-template-scanner-go/internal/engine"
	"github.com/guoyyit/vuln-template-scanner-go/internal/result"
	"github.com/guoyyit/vuln-template-scanner-go/internal/template"
)

func main() {
	var (
		tplDir      = flag.String("templates", "templates", "模板目录")
		targetsFlag = flag.String("targets", "", "目标列表，逗号分隔，如 http://127.0.0.1:8080")
		targetsFile = flag.String("targets-file", "", "目标列表文件，每行一个")
		concurrency = flag.Int("concurrency", 16, "全局并发数")
		perTarget   = flag.Int("per-target-concurrency", 4, "单目标并发请求上限")
		rate        = flag.Float64("rate", 0, "单目标每秒请求数上限，0 表示不限")
		timeout     = flag.Float64("timeout", 10, "单请求超时秒数")
		maxVariants = flag.Int("max-variants", template.DefaultMaxVariants, "单模板变体上限")
		checkpoint  = flag.String("checkpoint", "", "检查点文件路径")
		resume      = flag.Bool("resume", false, "从检查点恢复")
		seed        = flag.Int64("seed", 1, "随机种子（固定以保证可复现）")
		severities  = flag.String("severity", "", "按严重级别过滤，逗号分隔")
		tags        = flag.String("tags", "", "按标签过滤，逗号分隔")
		output      = flag.String("o", "", "结果输出文件，缺省输出到标准输出")
	)
	flag.Parse()

	templates, loadErrs, err := template.LoadDir(*tplDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "加载模板目录失败:", err)
		os.Exit(2)
	}
	for _, le := range loadErrs {
		fmt.Fprintln(os.Stderr, "模板加载失败:", le)
	}

	targets, err := collectTargets(*targetsFlag, *targetsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取目标失败:", err)
		os.Exit(2)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "未指定任何目标")
		os.Exit(2)
	}

	opts := engine.DefaultOptions()
	opts.Concurrency = *concurrency
	opts.PerTargetConcurrency = *perTarget
	opts.PerTargetRate = *rate
	opts.RequestTimeout = *timeout
	opts.MaxVariants = *maxVariants
	opts.CheckpointPath = *checkpoint
	opts.Resume = *resume
	opts.Seed = *seed

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng := engine.New(opts, templates)
	rep, err := eng.Run(ctx, targets)
	if err != nil {
		fmt.Fprintln(os.Stderr, "扫描失败:", err)
		os.Exit(2)
	}

	rep.Findings = result.Filter(rep.Findings, parseSeverities(*severities), parseTags(*tags))

	out := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "创建输出文件失败:", err)
			os.Exit(2)
		}
		defer f.Close()
		out = f
	}
	if err := result.WriteJSON(out, rep); err != nil {
		fmt.Fprintln(os.Stderr, "导出结果失败:", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "扫描结束: state=%s findings=%d errors=%d\n",
		rep.State, len(rep.Findings), len(rep.Errors)+len(loadErrs))
}

func collectTargets(list, file string) ([]string, error) {
	var out []string
	for _, t := range strings.Split(list, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
				out = append(out, t)
			}
		}
	}
	return out, nil
}

func parseSeverities(s string) map[template.Severity]bool {
	if s == "" {
		return nil
	}
	m := map[template.Severity]bool{}
	for _, p := range strings.Split(s, ",") {
		m[template.Severity(strings.TrimSpace(p))] = true
	}
	return m
}

func parseTags(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		m[strings.ToLower(strings.TrimSpace(p))] = true
	}
	return m
}
