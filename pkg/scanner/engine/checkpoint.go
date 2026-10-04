package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// CheckpointStore persists scan progress so a scan can resume after
// interruption.
type CheckpointStore interface {
	Load() (*Result, error)
	Save(*Result) error
}

// FileCheckpointStore writes checkpoints atomically to a JSON file.
type FileCheckpointStore struct {
	path string
}

func NewFileCheckpointStore(path string) *FileCheckpointStore {
	return &FileCheckpointStore{path: path}
}

// Load reads the checkpoint. A missing file is reported as (nil, nil).
func (s *FileCheckpointStore) Load() (*Result, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	res := &Result{}
	if err := json.Unmarshal(data, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Save writes the result to a temp file in the same directory and atomically
// renames it over the checkpoint file.
func (s *FileCheckpointStore) Save(r *Result) error {
	if r == nil {
		return nil
	}
	completed := make([]string, 0, len(r.Completed))
	for _, k := range r.Completed {
		completed = append(completed, k)
	}
	sort.Strings(completed)
	r.Completed = completed

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".checkpoint-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.path)
}

// TaskKey identifies a single concrete scan task.
func TaskKey(target, templateID, variantID string) string {
	return target + "|" + templateID + "|" + variantID
}

// RebuildCompleted converts the serialized completed list into a set.
func RebuildCompleted(r *Result) map[string]bool {
	m := make(map[string]bool, len(r.Completed))
	for _, k := range r.Completed {
		m[k] = true
	}
	return m
}
