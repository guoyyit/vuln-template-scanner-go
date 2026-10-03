package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/guoyyit/vuln-template-scanner-go/internal/result"
)

// checkpoint 扫描中断/恢复用的持久化状态。
type checkpoint struct {
	Version   int                `json:"version"`
	State     string             `json:"state"` // running | completed
	Seed      int64              `json:"seed"`
	Completed []string           `json:"completed"` // 已完成的 "target\x00templateID"
	Findings  []result.Finding   `json:"findings"`
	Errors    []result.ScanError `json:"errors"`
}

const checkpointVersion = 1

func pairKey(target, templateID string) string { return target + "\x00" + templateID }

// saveCheckpoint 原子写入检查点文件：先写临时文件再 rename，避免半截文件。
func saveCheckpoint(path string, cp *checkpoint) error {
	if path == "" {
		return nil
	}
	cp.Version = checkpointVersion
	data, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("序列化检查点: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("写入检查点临时文件: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("提交检查点: %w", err)
	}
	return nil
}

// loadCheckpoint 读取检查点；文件不存在时返回 nil, nil。
func loadCheckpoint(path string) (*checkpoint, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取检查点: %w", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("解析检查点: %w", err)
	}
	if cp.Version != checkpointVersion {
		return nil, fmt.Errorf("检查点版本 %d 不受支持", cp.Version)
	}
	return &cp, nil
}
