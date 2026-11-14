package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFirefoxCopyFailureWarns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode 000 does not block the file owner on Windows")
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "cookies.sqlite")
	if err := os.WriteFile(db, []byte("not a database"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(db, 0o600) })
	if f, err := os.Open(db); err == nil {
		_ = f.Close()
		t.Skip("file permissions do not prevent reading on this host")
	}

	result, err := Get(context.Background(), Options{
		URL: "https://example.com/", Browsers: []Browser{BrowserFirefox},
		Profiles: map[Browser]string{BrowserFirefox: db},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(result.Warnings, "\n")
	if !strings.Contains(joined, "failed to copy cookies DB") {
		t.Fatalf("warnings = %q", joined)
	}
}

func TestFirefoxSnapshotDirectoryFailureWarns(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "cookies.sqlite")
	if err := os.WriteFile(db, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	t.Setenv("TMPDIR", missing)
	t.Setenv("TMP", missing)
	t.Setenv("TEMP", missing)
	result, err := Get(context.Background(), Options{
		URL: "https://example.com/", Browsers: []Browser{BrowserFirefox},
		Profiles: map[Browser]string{BrowserFirefox: db},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(result.Warnings, "\n"), "failed to create cookie snapshot dir") {
		t.Fatalf("warnings = %q", result.Warnings)
	}
}
