package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGet_Firefox_DiscoveryViaProfilesINI(t *testing.T) {
	home := t.TempDir()

	var root string
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", home)
		root = filepath.Join(home, "Library", "Application Support", "Firefox")
	case "linux":
		t.Setenv("HOME", home)
		root = filepath.Join(home, ".mozilla", "firefox")
	case "windows":
		root = filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox")
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	default:
		t.Skip("unsupported OS for firefox root discovery")
	}

	profileDir := filepath.Join(root, "Profiles", "abcd.default-release")
	dbPath := filepath.Join(profileDir, "cookies.sqlite")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}

	ini := []byte("[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abcd.default-release\n\n")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), ini, 0o644); err != nil {
		t.Fatal(err)
	}

	db := openTestSQLite(t, dbPath)
	if _, err := db.Exec(`CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER)`); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(24 * time.Hour).Unix()
	if _, err := db.Exec(
		`INSERT INTO moz_cookies(host,name,value,path,expiry,isSecure,isHttpOnly,sameSite) VALUES(?,?,?,?,?,?,?,?)`,
		".example.com", "sid", "firefox", "/", expiry, 1, 1, 2,
	); err != nil {
		t.Fatal(err)
	}

	res, err := Get(context.Background(), Options{
		URL:      "https://app.example.com/",
		Browsers: []Browser{BrowserFirefox},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 1 {
		t.Fatalf("want 1 cookie got %d (warnings=%v)", len(res.Cookies), res.Warnings)
	}
	if res.Cookies[0].Value != "firefox" {
		t.Fatalf("unexpected value %q", res.Cookies[0].Value)
	}
}
