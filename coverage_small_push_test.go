package sweetcookie

import (
	"errors"
	"testing"
)

func TestReadInlineBytes_FileError(t *testing.T) {
	_, _, err := readInlineCookies(InlineCookies{File: "/no/such/file"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNormalizeOrigins_TrimsAndSkipsEmptyOrigins(t *testing.T) {
	origins, err := normalizeOrigins("https://example.com", []string{"   ", "https://a.example.com/x"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 2 {
		t.Fatalf("want 2 origins got %d", len(origins))
	}
	if origins[0].path != "/" {
		t.Fatalf("expected / default path, got %q", origins[0].path)
	}
}

func TestNormalizeOrigins_URLMissingHostErrors(t *testing.T) {
	_, err := normalizeOrigins("https://", nil, true)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrNoOrigin) {
		t.Fatal("expected URL parse error, not ErrNoOrigin")
	}
}
