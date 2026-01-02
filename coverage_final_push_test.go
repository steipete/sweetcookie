package sweetcookie

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestChromiumMetaVersion_NilAndInvalid(t *testing.T) {
	if chromiumMetaVersion(context.Background(), (*sql.DB)(nil)) != 0 {
		t.Fatal("expected 0 for nil db")
	}

	dbPath := filepath.Join(t.TempDir(), "Cookies")
	db := openTestSQLite(t, dbPath)
	if _, err := db.Exec(`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key,value) VALUES('version','nope')`); err != nil {
		t.Fatal(err)
	}
	if chromiumMetaVersion(context.Background(), db) != 0 {
		t.Fatal("expected 0 for invalid meta version")
	}
}

func TestChromiumDecryptAESCBC_ErrorBranches(t *testing.T) {
	key := chromiumDeriveAESCBCKey("pw", chromiumAESCBCIterationsLinux)
	if _, err := chromiumDecryptAESCBC([]byte{1, 2}, key, 0, false); err == nil {
		t.Fatal("expected too-short error")
	}
	if _, err := chromiumDecryptAESCBC([]byte("xxx"), key, 0, false); err == nil {
		t.Fatal("expected missing prefix error")
	}
	if _, err := chromiumDecryptAESCBC(append([]byte("v10"), []byte("abc")...), key, 0, false); err == nil {
		t.Fatal("expected non-block-size error")
	}
}

func TestChromiumDecodeCookieValue_InvalidUTF8(t *testing.T) {
	if _, ok := chromiumDecodeCookieValue([]byte{0xff}); ok {
		t.Fatal("expected invalid utf8")
	}
}

func TestOriginsToHosts_Dedupes(t *testing.T) {
	hosts := originsToHosts([]requestOrigin{{host: "example.com"}, {host: "example.com"}, {host: ""}})
	if len(hosts) != 1 || hosts[0] != "example.com" {
		t.Fatalf("unexpected: %v", hosts)
	}
}

func TestReadChromiumCookies_InvalidSQLiteFile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

	// Stub `security` so decryption setup doesn't touch keychain.
	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\necho pw\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	dbPath := filepath.Join(t.TempDir(), "Cookies")
	if err := os.WriteFile(dbPath, []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Get(context.Background(), Options{
		URL:      "https://example.com/",
		Browsers: []Browser{BrowserChrome},
		Profiles: map[Browser]string{BrowserChrome: dbPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 0 || len(res.Warnings) == 0 {
		t.Fatalf("expected warnings for invalid DB")
	}
}

func TestReadFirefoxCookies_InvalidSQLiteFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cookies.sqlite")
	if err := os.WriteFile(dbPath, []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Get(context.Background(), Options{
		URL:      "https://example.com/",
		Browsers: []Browser{BrowserFirefox},
		Profiles: map[Browser]string{BrowserFirefox: dbPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 0 || len(res.Warnings) == 0 {
		t.Fatalf("expected warnings for invalid firefox DB")
	}
}
