package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestChromiumResolveStoresFromUserDataDir_InvalidLocalStateFallback(t *testing.T) {
	userDataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(userDataDir, "Local State"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(userDataDir, "Default", "Network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDataDir, "Default", "Network", "Cookies"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	stores, warnings := chromiumResolveStoresFromUserDataDir(BrowserChrome, userDataDir)
	if len(stores) == 0 || len(warnings) == 0 {
		t.Fatalf("expected fallback stores+warnings, got %v %v", stores, warnings)
	}
}

func TestGet_AllowAllHosts_ReadsChromiumWithoutOrigins(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

	// Stub `security` in PATH.
	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\necho pw\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Cookies")
	db := openTestSQLite(t, dbPath)
	if _, err := db.Exec(`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key,value) VALUES('version','1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, value TEXT, encrypted_value BLOB, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO cookies(host_key,name,path,value,encrypted_value,expires_utc,is_secure,is_httponly,samesite) VALUES(?,?,?,?,?,?,?,?,?)`,
		".example.com", "plain", "/", "v", nil, 0, 0, 0, 0,
	); err != nil {
		t.Fatal(err)
	}

	res, err := Get(context.Background(), Options{
		AllowAllHosts: true,
		Browsers:      []Browser{BrowserChrome},
		Profiles:      map[Browser]string{BrowserChrome: dbPath},
		Mode:          ModeFirst,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 1 {
		t.Fatalf("want 1 cookie got %d", len(res.Cookies))
	}
}

func TestChromiumDecryptor_EmptyPassword(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\necho \"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	_, warnings := chromiumDecryptor(chromiumVendorForBrowser(BrowserChrome), nil, 50*time.Millisecond)
	if len(warnings) == 0 {
		t.Fatal("expected warnings")
	}
}

func TestHasChromiumVersionPrefix_Branches(t *testing.T) {
	if hasChromiumVersionPrefix([]byte("v1")) {
		t.Fatal("too short")
	}
	if hasChromiumVersionPrefix([]byte("x10")) {
		t.Fatal("bad prefix")
	}
	if hasChromiumVersionPrefix([]byte("v1x")) {
		t.Fatal("bad digit")
	}
	if !hasChromiumVersionPrefix([]byte("v10")) {
		t.Fatal("expected v10")
	}
}
