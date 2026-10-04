package target

import "testing"

func TestParse(t *testing.T) {
	got, err := Parse([]string{"http://127.0.0.1:8080", "  https://localhost:9090/ ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 targets, got %d: %v", len(got), got)
	}
	if got[0] != "http://127.0.0.1:8080" {
		t.Fatalf("bad normalization: %q", got[0])
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse([]string{"not a url"}); err == nil {
		t.Fatal("expected error for invalid target")
	}
	if _, err := Parse([]string{"ftp:///path"}); err == nil {
		t.Fatal("expected error for target without host")
	}
}
