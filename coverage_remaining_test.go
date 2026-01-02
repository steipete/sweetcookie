package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadFromBrowser_InlineAndUnknown(t *testing.T) {
	// Inline is handled separately; browser dispatch should be a no-op.
	if cookies, warnings, err := readFromBrowser(context.Background(), BrowserInline, nil, Options{}); err != nil || len(warnings) != 0 || len(cookies) != 0 {
		t.Fatalf("unexpected: %v %v %v", cookies, warnings, err)
	}
	_, warnings, _ := readFromBrowser(context.Background(), Browser("nope"), nil, Options{})
	if len(warnings) == 0 {
		t.Fatal("expected warning")
	}
}

func TestFirefoxRowToCookie_SetsDefaultPath(t *testing.T) {
	c, ok := firefoxRowToCookie(firefoxDB{path: "x", profile: "p"}, firefoxRow{
		host:  ".example.com",
		name:  "a",
		value: "b",
		path:  "",
	})
	if !ok {
		t.Fatal("expected ok")
	}
	if c.Path != "/" {
		t.Fatalf("want / got %q", c.Path)
	}
	if c.Expires != nil {
		t.Fatal("expected nil expires")
	}
}

func TestChromiumHostWhereClause_EmptyHosts(t *testing.T) {
	where, args := chromiumHostWhereClause(nil)
	if where != "1=1" || len(args) != 0 {
		t.Fatalf("unexpected: %q %v", where, args)
	}
}

func TestFirefoxHostWhereClause_EmptyHosts(t *testing.T) {
	where, args := firefoxHostWhereClause(nil)
	if where != "1=1" || len(args) != 0 {
		t.Fatalf("unexpected: %q %v", where, args)
	}
}

func TestChromiumResolveStoreFromOverride_MissingProfileName(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Setenv("HOME", t.TempDir())
	}
	stores, warnings := chromiumResolveStoreFromOverride(BrowserChrome, "NoSuchProfile")
	if len(stores) != 0 || len(warnings) == 0 {
		t.Fatalf("expected warnings: %v %v", stores, warnings)
	}
}

func TestChromiumResolveStoreFromOverride_ProfileDir(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "Default")
	if err := os.MkdirAll(filepath.Join(profileDir, "Network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Network", "Cookies"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	stores, warnings := chromiumResolveStoreFromOverride(BrowserChrome, profileDir)
	if len(warnings) != 0 || len(stores) == 0 {
		t.Fatalf("unexpected: %v %v", stores, warnings)
	}
}
