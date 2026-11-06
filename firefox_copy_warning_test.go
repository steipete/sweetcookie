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

	_, warnings, err := readFirefoxCookies(context.Background(), BrowserFirefox, db, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "failed to copy cookies DB") {
		t.Fatalf("warnings = %q", joined)
	}
}
